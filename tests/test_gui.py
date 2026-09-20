import os
import queue
import sys
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
    """Habilita os testes que abrem a janela de verdade.

    Cada um cria a sua raiz Tk. No macOS, abrir e fechar várias raízes
    no mesmo processo derruba o interpretador (falha de segmentação no
    Aqua, fora do controle do Python), então lá eles só rodam sob
    ALVSAFE_GUI_TESTS=1. No Linux, com display, rodam sempre: é o que
    o job de interface gráfica do CI faz.
    """
    ctk = pytest.importorskip("customtkinter")

    if sys.platform == "darwin" and not os.environ.get("ALVSAFE_GUI_TESTS"):
        pytest.skip("janela Tk instável no macOS em série; use ALVSAFE_GUI_TESTS=1 para forçar")
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        pytest.skip("sem display; use xvfb-run")
    return ctk


def test_janela_abre_escaneia_e_fecha(janela, tmp_path, bus):
    from alvsafe.gui.app import AlvSafeApp

    (tmp_path / "mal.ps1").write_text("powershell -enc AAA; Invoke-Expression x")
    controller = Controller(Settings(), bus=bus, notifications=False)
    app = AlvSafeApp(controller)
    try:
        painel = app.views["Painel"]
        assert app.current == "Painel"
        assert app.start_scan(tmp_path) is True

        # update() desenha a janela e dispara o _pump agendado com after()
        for _ in range(100):
            app.update()
            if painel.tiles["threats"].cget("text") == "1":
                break
            time.sleep(0.05)

        assert painel.tiles["threats"].cget("text") == "1"
        assert "MALWARE" in painel.activity.get("1.0", "end")
        assert len(controller.quarantine_entries()) == 1
        # scan com ameaça leva o usuário direto para a quarentena
        assert app.current == "Quarentena"
        assert app.views["Quarentena"].lista.winfo_children()
    finally:
        app.on_close()


def test_navegacao_entre_telas(janela, bus):
    from alvsafe.gui.app import AlvSafeApp
    from alvsafe.gui.views import VIEWS

    app = AlvSafeApp(Controller(Settings(), bus=bus, notifications=False))
    try:
        for view in VIEWS:
            app.show(view.title)
            app.update()
            assert app.current == view.title
            assert app.view_title.cget("text") == view.title
            assert app.views[view.title].winfo_ismapped()
    finally:
        app.on_close()


def test_estado_do_painel_segue_a_protecao(janela, tmp_path, bus):
    from alvsafe.gui.app import AlvSafeApp

    controller = Controller(Settings(watch_folders=[str(tmp_path)]), bus=bus, notifications=False)
    app = AlvSafeApp(controller)
    painel = app.views["Painel"]
    try:
        assert "Sem proteção" in painel.estado_titulo.cget("text")

        app.toggle_protection()
        app.update()
        assert painel.estado_titulo.cget("text") == "Protegido"
        assert bool(app.protection_switch.get()) is True

        app.toggle_protection()
        app.update()
        assert "Sem proteção" in painel.estado_titulo.cget("text")
        assert bool(app.protection_switch.get()) is False
    finally:
        app.on_close()


def test_quarentena_vazia_mostra_estado_proprio(janela, bus):
    from alvsafe.gui.app import AlvSafeApp

    app = AlvSafeApp(Controller(Settings(), bus=bus, notifications=False))
    try:
        app.show("Quarentena")
        app.update()
        textos = [w.cget("text") for card in app.views["Quarentena"].lista.winfo_children()
                  for w in card.winfo_children() if hasattr(w, "cget")]
        assert any("Nada em quarentena" in texto for texto in textos)
    finally:
        app.on_close()
