import queue
import time

import pytest

from alvsafe.config import Settings
from alvsafe.events import CRITICAL
from alvsafe.gui.controller import Controller


@pytest.fixture
def ctrl(bus):
    c = Controller(Settings(), bus=bus, notifications=False)
    yield c
    c.shutdown()


def esperar(condicao, timeout=5):
    limite = time.monotonic() + timeout
    while time.monotonic() < limite:
        if condicao():
            return True
        time.sleep(0.05)
    return False


# ---------- fila de eventos ----------

def test_eventos_viram_fila_e_contadores(ctrl, tmp_path):
    (tmp_path / "a.ps1").write_text("powershell -enc AAA")
    ctrl.scanner.auto_quarantine = False
    ctrl.scanner.scan_file(tmp_path / "a.ps1")

    eventos = ctrl.drain()
    kinds = [e.kind for e in eventos]
    assert "scan.file" in kinds and "threat" in kinds
    assert ctrl.scanned == 1 and ctrl.threats == 1
    assert ctrl.drain() == []  # fila esvaziada


def test_drain_respeita_o_limite(ctrl):
    for i in range(50):
        ctrl.bus.emit("teste", str(i))
    assert len(ctrl.drain(limit=10)) == 10
    assert len(ctrl.drain()) == 40


def test_fila_cheia_nao_trava_o_nucleo(ctrl):
    ctrl.queue = queue.Queue(maxsize=3)
    for i in range(10):
        ctrl.bus.emit("teste", str(i))
    assert ctrl.dropped == 7
    assert len(ctrl.drain()) == 3


def test_notificacao_so_para_ameaca(monkeypatch, bus):
    chamadas = []
    monkeypatch.setattr("alvsafe.system.notify", lambda t, m: chamadas.append(m))
    c = Controller(Settings(), bus=bus, notifications=True)
    try:
        c.bus.emit("scan.file", "um arquivo qualquer")
        c.bus.emit("threat", "MALWARE: x")
        c.bus.emit("alert", "RANSOMWARE: y", level=CRITICAL)
        assert esperar(lambda: len(chamadas) == 2)
        assert chamadas == ["MALWARE: x", "RANSOMWARE: y"]
    finally:
        c.shutdown()


# ---------- scan em thread ----------

def test_scan_roda_em_thread_e_publica_o_resultado(ctrl, tmp_path):
    (tmp_path / "a.ps1").write_text("powershell -enc AAA; Invoke-Expression x")

    assert ctrl.start_scan(tmp_path)
    assert esperar(lambda: not ctrl.scanning, timeout=10)

    tipo, resumo = ctrl.drain_results()[0]
    assert tipo == "scan" and resumo.threats and ctrl.threats == 1


def test_nao_inicia_dois_scans(ctrl, tmp_path):
    for i in range(200):
        (tmp_path / f"f{i}.sh").write_text("echo oi")
    ctrl.start_scan(tmp_path)
    if ctrl.scanning:
        assert ctrl.start_scan(tmp_path) is False
    ctrl.cancel_scan()


def test_pasta_inexistente_vira_evento(ctrl, tmp_path):
    ctrl.start_scan(tmp_path / "nao-existe")
    assert esperar(lambda: ctrl.drain_results())
    assert any(e.kind == "scan.error" for e in ctrl.drain())


# ---------- proteção ----------

def test_liga_e_desliga_protecao(ctrl):
    assert ctrl.start_protection() is True
    assert ctrl.protection_active
    assert ctrl.start_protection() is False  # já ligada
    assert ctrl.stop_protection() is True
    assert not ctrl.protection_active
    assert ctrl.stop_protection() is False


def test_shutdown_para_tudo(tmp_path, bus):
    c = Controller(Settings(watch_folders=[str(tmp_path)]), bus=bus, notifications=False)
    c.start_protection()
    c.shutdown()
    assert not c.protection_active


# ---------- diagnóstico e quarentena ----------

def test_doctor_em_thread(ctrl):
    ctrl.run_doctor()
    assert esperar(lambda: not ctrl.results.empty(), timeout=20)
    tipo, checagens = ctrl.drain_results()[0]
    assert tipo == "doctor" and any(c.name == "Backend de arquivos" for c in checagens)


def test_quarentena_pela_interface(ctrl, tmp_path):
    alvo = tmp_path / "mal.ps1"
    alvo.write_text("powershell -enc AAA; Invoke-Expression x")
    ctrl.scanner.scan_file(alvo)

    entradas = ctrl.quarantine_entries()
    assert len(entradas) == 1 and not alvo.exists()
    ctrl.restore(entradas[0].id)
    assert alvo.exists() and ctrl.quarantine_entries() == []


# ---------- janela de verdade ----------

@pytest.fixture
def janela():
    ctk = pytest.importorskip("customtkinter")
    import tkinter

    try:
        raiz = ctk.CTk()
    except tkinter.TclError as e:
        pytest.skip(f"sem display disponível: {e}")
    raiz.destroy()
    return ctk


def test_janela_abre_escaneia_e_fecha(janela, tmp_path, bus):
    from alvsafe.gui.app import AlvSafeApp

    (tmp_path / "mal.ps1").write_text("powershell -enc AAA; Invoke-Expression x")
    controller = Controller(Settings(), bus=bus, notifications=False)
    app = AlvSafeApp(controller)
    try:
        assert app.start_scan(tmp_path) is True

        # update() desenha a janela e dispara o _pump agendado com after()
        for _ in range(100):
            app.update()
            if "ameaças: 1" in app.stats_label.cget("text"):
                break
            time.sleep(0.05)

        assert "ameaças: 1" in app.stats_label.cget("text")
        assert "quarantine" in app.activity.get("1.0", "end")
        assert len(controller.quarantine_entries()) == 1

        app.refresh_quarantine()
        assert app.quarantine_list.winfo_children()
    finally:
        app.on_close()
