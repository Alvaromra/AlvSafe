import plistlib
from types import SimpleNamespace

import pytest

from alvsafe import service
from alvsafe.cli import main
from alvsafe.service import LaunchdManager, ServiceError, SystemdManager, get_manager


class FakeRunner:
    """Substitui o subprocess: guarda os comandos e devolve o que mandarmos."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.calls = []
        self.result = SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    def __call__(self, cmd):
        self.calls.append(cmd)
        return self.result

    def ran(self, *fragmentos):
        return any(all(f in " ".join(cmd) for f in fragmentos) for cmd in self.calls)


@pytest.fixture
def launchd(tmp_path):
    return LaunchdManager(runner=FakeRunner(), python="/venv/bin/python", home=tmp_path)


@pytest.fixture
def systemd(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return SystemdManager(runner=FakeRunner(), python="/venv/bin/python", home=tmp_path)


# ---------- macOS ----------

def test_plist_do_launchagent(launchd):
    caminho = launchd.install()

    assert caminho == launchd.home / "Library/LaunchAgents/com.alvaromra.alvsafe.plist"
    plist = plistlib.loads(caminho.read_bytes())
    assert plist["Label"] == "com.alvaromra.alvsafe"
    assert plist["ProgramArguments"][:4] == ["/venv/bin/python", "-m", "alvsafe", "watch"]
    assert "--notify" in plist["ProgramArguments"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}   # reinicia se cair, não se sair bem
    assert launchd.runner.ran("launchctl", "bootstrap")


def test_alvsafe_home_vai_para_o_servico(launchd, monkeypatch, tmp_path):
    monkeypatch.setenv("ALVSAFE_HOME", str(tmp_path / "dados"))
    plist = plistlib.loads(launchd.install().read_bytes())
    assert plist["EnvironmentVariables"]["ALVSAFE_HOME"] == str(tmp_path / "dados")


def test_desinstalar_remove_o_plist(launchd):
    launchd.install()
    assert launchd.installed
    launchd.uninstall()
    assert not launchd.installed
    assert launchd.runner.ran("launchctl", "bootout")


@pytest.mark.parametrize("saida,esperado", [
    ("\tstate = running\n", True),
    ("\tstate = waiting\n", False),
])
def test_status_do_launchd(tmp_path, saida, esperado):
    m = LaunchdManager(runner=FakeRunner(stdout=saida), home=tmp_path)
    m.write_unit()
    ativo, _ = m.status()
    assert ativo is esperado


def test_status_sem_instalacao(launchd):
    assert launchd.status() == (False, "não instalado")


# ---------- Linux ----------

def test_unidade_do_systemd(systemd):
    caminho = systemd.install()

    assert caminho == systemd.home / ".config/systemd/user/alvsafe.service"
    unit = caminho.read_text()
    assert "ExecStart=/venv/bin/python -m alvsafe watch --notify --log" in unit
    assert "Restart=on-failure" in unit
    assert "WantedBy=default.target" in unit
    assert systemd.runner.ran("systemctl", "daemon-reload")
    assert systemd.runner.ran("systemctl", "enable", "--now")


def test_xdg_config_home_e_respeitado(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    m = SystemdManager(runner=FakeRunner(), home=tmp_path)
    assert m.unit_path == tmp_path / "cfg" / "systemd" / "user" / "alvsafe.service"


def test_status_do_systemd(tmp_path):
    m = SystemdManager(runner=FakeRunner(stdout="active\n"), home=tmp_path)
    m.write_unit()
    assert m.status() == (True, "active")


def test_erro_do_sistema_vira_ServiceError(tmp_path):
    m = SystemdManager(runner=FakeRunner(returncode=1, stderr="Failed to connect to bus"), home=tmp_path)
    with pytest.raises(ServiceError, match="bus"):
        m.install()


def test_stop_silencioso_nao_levanta(tmp_path):
    m = SystemdManager(runner=FakeRunner(returncode=1), home=tmp_path)
    m.stop(quiet=True)
    with pytest.raises(ServiceError):
        m.stop()


# ---------- comum ----------

def test_sistema_sem_suporte(monkeypatch):
    monkeypatch.setattr("alvsafe.system.os_name", lambda: "windows")
    assert get_manager() is None


def test_logs_juntam_os_dois_arquivos(launchd):
    launchd.log_file.write_text("linha de evento\n")
    launchd.error_file.write_text("erro do processo\n")
    linhas = launchd.logs()
    assert any("service.log] linha de evento" in linha for linha in linhas)
    assert any("service.err] erro do processo" in linha for linha in linhas)


def test_cli_sem_suporte_retorna_2(monkeypatch):
    monkeypatch.setattr("alvsafe.system.os_name", lambda: "windows")
    assert main(["service", "status"]) == 2


def test_cli_status_usa_o_gerenciador(monkeypatch, tmp_path, capsys):
    m = SystemdManager(runner=FakeRunner(stdout="active\n"), home=tmp_path)
    m.write_unit()
    monkeypatch.setattr(service, "get_manager", lambda **kw: m)
    assert main(["service", "status"]) == 0
    assert "active" in capsys.readouterr().out


# ---------- log com rotação ----------

def test_log_do_watch_rotaciona(tmp_path):
    from alvsafe.cli import _FileLogger
    from alvsafe.events import Event

    destino = tmp_path / "logs" / "service.log"
    logger = _FileLogger(destino, max_bytes=200)
    for i in range(30):
        logger(Event(kind="threat", message=f"ameaça {i}"))

    assert destino.exists() and destino.with_suffix(".log.1").exists()
    assert destino.stat().st_size <= 300


def test_log_ignora_eventos_de_depuracao(tmp_path):
    from alvsafe.cli import _FileLogger
    from alvsafe.events import DEBUG, Event

    destino = tmp_path / "s.log"
    logger = _FileLogger(destino)
    logger(Event(kind="scan.file", message="x", level=DEBUG))
    assert not destino.exists()
