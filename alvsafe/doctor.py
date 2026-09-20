"""Diagnóstico do ambiente: o que funciona e o que precisa de ajuste."""

import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.version import VERSION_STRING as WATCHDOG_VERSION

from alvsafe import __version__, paths, system
from alvsafe.config import ConfigError, load_settings
from alvsafe.core import yara_rules
from alvsafe.core.realtime import check_folder
from alvsafe.core.signatures import load_signatures

OK, WARN, FAIL = "ok", "aviso", "falha"

EXPECTED_BACKEND = {"macos": "FSEventsObserver", "linux": "InotifyObserver", "windows": "WindowsApiObserver"}
TESTED_PYTHON = ((3, 10), (3, 13))


@dataclass
class Check:
    name: str
    status: str
    detail: str
    hint: str = ""


def _python():
    v = sys.version_info[:2]
    detail = f"{sys.version.split()[0]} ({sys.executable})"
    if v < TESTED_PYTHON[0]:
        return Check("Python", FAIL, detail, "o AlvSafe precisa de Python 3.10 ou mais novo")
    if v > TESTED_PYTHON[1]:
        return Check("Python", WARN, detail,
                     "versão mais nova que a testada; se algo falhar, use um venv com Python 3.13")
    return Check("Python", OK, detail)


def _data_dir():
    try:
        d = paths.data_dir()
        with tempfile.NamedTemporaryFile(dir=d):
            pass
        return Check("Pasta de dados", OK, str(d))
    except OSError as e:
        return Check("Pasta de dados", FAIL, str(e))


def _config():
    path = paths.config_file()
    try:
        load_settings(path)
    except ConfigError as e:
        return Check("Configuração", FAIL, str(e), "corrija o JSON ou apague o arquivo para voltar ao padrão")
    return Check("Configuração", OK, f"{path}" + ("" if path.exists() else " (usando padrões)"))


def _backend():
    name = type(Observer()).__name__
    expected = EXPECTED_BACKEND.get(system.os_name())
    detail = f"watchdog {WATCHDOG_VERSION}, backend {name}"
    if expected and name != expected:
        return Check("Backend de arquivos", WARN, detail,
                     f"o esperado neste sistema é {expected}; reinstale o watchdog "
                     "num venv com Python 3.13 (pip install --force-reinstall watchdog)")
    return Check("Backend de arquivos", OK, detail)


def _live_events(timeout=3.0):
    """Cria um arquivo numa pasta temporária e confere se o evento chega."""
    got = threading.Event()

    class H(FileSystemEventHandler):
        def on_any_event(self, event):
            if not event.is_directory:
                got.set()

    with tempfile.TemporaryDirectory(dir=paths.data_dir()) as tmp:
        observer = Observer()
        observer.schedule(H(), tmp, recursive=True)
        observer.start()
        try:
            (Path(tmp) / "doctor.txt").write_text("x")
            ok = got.wait(timeout)
        finally:
            observer.stop()
            observer.join(timeout=5)

    if ok:
        return Check("Eventos em tempo real", OK, "evento de teste recebido")
    return Check("Eventos em tempo real", FAIL, f"nenhum evento em {timeout:.0f}s",
                 "o monitor de arquivos não está funcionando neste ambiente")


def _watch_folders(settings):
    checks = []
    for folder in settings.resolved_watch_folders():
        problem = check_folder(folder)
        if problem is None:
            checks.append(Check(f"Monitorar {folder.name}", OK, str(folder)))
        elif problem == "sem permissão de leitura" and system.os_name() == "macos":
            checks.append(Check(f"Monitorar {folder.name}", FAIL, f"{folder}: bloqueada pelo macOS",
                                "Ajustes do Sistema > Privacidade e Segurança > Arquivos e Pastas: "
                                "libere o seu terminal para esta pasta"))
        else:
            status = WARN if problem == "não existe" else FAIL
            checks.append(Check(f"Monitorar {folder.name}", status, f"{folder}: {problem}"))
    return checks


def _yara():
    available, count, error = yara_rules.status()
    if available:
        return Check("YARA", OK, f"{count} arquivo(s) de regras")
    return Check("YARA", WARN, error or "indisponível", 'instale com: pip install -e ".[yara]"')


def _signatures():
    return Check("Assinaturas", OK, f"{len(load_signatures())} hashes carregados")


def _network():
    try:
        psutil.net_connections()
        return Check("Monitor de rede", OK, "conexões acessíveis")
    except psutil.AccessDenied:
        return Check("Monitor de rede", WARN, "sem permissão para listar conexões",
                     "no macOS isso exige rodar como administrador (sudo)")


def _notifications():
    backend = system.notification_backend()
    if backend:
        return Check("Notificações", OK, backend)
    hint = "instale libnotify (notify-send)" if system.os_name() == "linux" else ""
    return Check("Notificações", WARN, "nenhum backend encontrado", hint)


def run_checks(settings=None):
    checks = [
        Check("AlvSafe", OK, f"{__version__} em {system.os_name()}" + (" (WSL)" if system.is_wsl() else "")),
        _python(),
        _data_dir(),
        _config(),
    ]
    try:
        settings = settings or load_settings()
    except ConfigError:
        from alvsafe.config import Settings
        settings = Settings()
    checks += [_backend(), _live_events()]
    checks += _watch_folders(settings)
    checks += [_yara(), _signatures(), _network(), _notifications()]
    return checks
