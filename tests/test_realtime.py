import time

import pytest

from alvsafe.config import Settings
from alvsafe.core.realtime import RansomwareDetector, Watcher, _Handler
from alvsafe.core.scanner import Scanner


class Ev:
    def __init__(self, src, dest=None, is_directory=False):
        self.src_path, self.dest_path, self.is_directory = src, dest, is_directory


@pytest.fixture
def watcher(tmp_path, bus):
    scanner = Scanner(Settings(), bus=bus, signatures=set(), auto_quarantine=False)
    return Watcher(Settings(), bus=bus, scanner=scanner, folders=[tmp_path], debounce=1.0)


def test_rajada_alerta_uma_vez(bus):
    d = RansomwareDetector(threshold=15, window=10, bus=bus)
    resultados = [d.process(f"/x/{i}.txt", now=i * 0.1) for i in range(20)]
    assert resultados.count(True) == 1


def test_janela_expira(bus):
    d = RansomwareDetector(threshold=15, window=10, bus=bus)
    for i in range(15):
        d.process(f"/x/{i}.txt", now=0)
    assert d.process("/x/novo.txt", now=100) is False
    assert len(d._events) == 1


def test_renomear_para_locked_alerta(watcher, bus):
    handler = _Handler(watcher)
    handler.on_moved(Ev("/x/foto.jpg", "/x/foto.jpg.locked"))
    assert any("foto.jpg.locked" in e.message for e in bus.events if e.kind == "alert")


def test_eventos_de_pasta_ignorados(watcher):
    handler = _Handler(watcher)
    handler.on_created(Ev("/x/pasta", is_directory=True))
    assert watcher.due(now=time.monotonic() + 10) == []


def test_debounce_agrupa_e_espera_silencio(watcher):
    watcher.notify("/x/a.sh", now=0)
    watcher.notify("/x/a.sh", now=0.5)   # mesmo arquivo sendo gravado aos poucos
    watcher.notify("/x/b.sh", now=0.2)
    assert watcher.due(now=1.25) == ["/x/b.sh"]  # a.sh ainda não ficou quieto 1s
    assert watcher.due(now=1.6) == ["/x/a.sh"]
    assert watcher.due(now=5) == []


def test_pasta_de_dados_ignorada(watcher, isolated_home):
    watcher.notify(str(isolated_home / "quarantine" / "x.bin"), now=0)
    assert watcher.due(now=10) == []


def test_pasta_inexistente_e_pulada(tmp_path, bus):
    w = Watcher(Settings(), bus=bus, scan=False, folders=[tmp_path / "nao-existe"])
    w.start()
    try:
        assert w.watching == []
        assert any(e.kind == "watch.skip" for e in bus.events)
    finally:
        w.stop()


def test_ponta_a_ponta_com_sistema_de_arquivos(tmp_path, bus):
    """Usa o watchdog de verdade: arquivo criado na pasta é escaneado."""
    scanner = Scanner(Settings(), bus=bus, signatures=set(), auto_quarantine=False)
    w = Watcher(Settings(), bus=bus, scanner=scanner, folders=[tmp_path], debounce=0.2).start()
    try:
        (tmp_path / "novo.sh").write_text("echo oi")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any(e.kind == "scan.file" and e.path.endswith("novo.sh") for e in bus.events):
                break
            time.sleep(0.1)
        else:
            pytest.fail("arquivo criado não foi escaneado em 5s")
    finally:
        w.stop()
