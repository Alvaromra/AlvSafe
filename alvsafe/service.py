"""Instala o AlvSafe como serviço do usuário, para a proteção subir sozinha.

macOS usa launchd (LaunchAgent em ~/Library/LaunchAgents), Linux usa
systemd em modo usuário (~/.config/systemd/user). Nos dois casos é
serviço de usuário, e não de sistema: nada roda como root, e o serviço
enxerga a sessão gráfica, necessária para as notificações.

Os comandos externos passam por `runner`, o que torna tudo testável
sem instalar nada de verdade.
"""

import os
import plistlib
import subprocess
import sys
from pathlib import Path

from alvsafe import paths, system

LABEL = "com.alvaromra.alvsafe"
UNIT_NAME = "alvsafe.service"
DESCRIPTION = "AlvSafe: proteção em tempo real"


class ServiceError(Exception):
    pass


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


class ServiceManager:
    """Base comum. Cada sistema implementa os detalhes."""

    def __init__(self, runner=None, python=None, home=None):
        self.runner = runner or _run
        self.python = python or sys.executable
        self.home = Path(home) if home else Path.home()

    # ---------- comum ----------

    @property
    def log_file(self):
        return paths.data_dir() / "service.log"

    @property
    def error_file(self):
        return paths.data_dir() / "service.err"

    def command(self):
        return [self.python, "-m", "alvsafe", "watch", "--notify", "--log", str(self.log_file)]

    def environment(self):
        env = {}
        if os.environ.get("ALVSAFE_HOME"):
            env["ALVSAFE_HOME"] = os.environ["ALVSAFE_HOME"]
        return env

    def _exec(self, cmd):
        result = self.runner(cmd)
        if result.returncode != 0:
            raise ServiceError((result.stderr or result.stdout or "").strip() or f"falhou: {' '.join(cmd)}")
        return result

    def logs(self, limit=30):
        linhas = []
        for path in (self.log_file, self.error_file):
            if path.exists():
                conteudo = path.read_text(errors="ignore").splitlines()[-limit:]
                linhas += [f"[{path.name}] {linha}" for linha in conteudo]
        return linhas

    @property
    def installed(self):
        return self.unit_path.exists()


class LaunchdManager(ServiceManager):
    """macOS."""

    name = "launchd"

    @property
    def unit_path(self):
        return self.home / "Library" / "LaunchAgents" / f"{LABEL}.plist"

    @property
    def domain(self):
        return f"gui/{os.getuid()}"

    def write_unit(self):
        plist = {
            "Label": LABEL,
            "ProgramArguments": self.command(),
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Background",
            "StandardOutPath": str(self.error_file),
            "StandardErrorPath": str(self.error_file),
        }
        env = self.environment()
        if env:
            plist["EnvironmentVariables"] = env

        self.unit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.unit_path, "wb") as f:
            plistlib.dump(plist, f)
        return self.unit_path

    def install(self):
        self.write_unit()
        self.stop(quiet=True)
        self._exec(["launchctl", "bootstrap", self.domain, str(self.unit_path)])
        return self.unit_path

    def uninstall(self):
        self.stop(quiet=True)
        self.unit_path.unlink(missing_ok=True)

    def start(self):
        self._exec(["launchctl", "kickstart", f"{self.domain}/{LABEL}"])

    def stop(self, quiet=False):
        result = self.runner(["launchctl", "bootout", f"{self.domain}/{LABEL}"])
        if result.returncode != 0 and not quiet:
            raise ServiceError((result.stderr or "").strip() or "não estava rodando")

    def status(self):
        if not self.installed:
            return False, "não instalado"
        result = self.runner(["launchctl", "print", f"{self.domain}/{LABEL}"])
        if result.returncode != 0:
            return False, "instalado, mas não carregado"
        for linha in result.stdout.splitlines():
            if "state =" in linha:
                estado = linha.split("=", 1)[1].strip()
                return estado == "running", estado
        return True, "carregado"


class SystemdManager(ServiceManager):
    """Linux."""

    name = "systemd"

    @property
    def unit_path(self):
        base = os.environ.get("XDG_CONFIG_HOME")
        base = Path(base) if base else self.home / ".config"
        return base / "systemd" / "user" / UNIT_NAME

    def write_unit(self):
        env = "".join(f'Environment="{k}={v}"\n' for k, v in self.environment().items())
        unit = f"""[Unit]
Description={DESCRIPTION}
After=graphical-session.target

[Service]
Type=simple
ExecStart={' '.join(self.command())}
{env}Restart=on-failure
RestartSec=5
StandardOutput=append:{self.error_file}
StandardError=append:{self.error_file}

[Install]
WantedBy=default.target
"""
        self.unit_path.parent.mkdir(parents=True, exist_ok=True)
        self.unit_path.write_text(unit)
        return self.unit_path

    def install(self):
        self.write_unit()
        self._exec(["systemctl", "--user", "daemon-reload"])
        self._exec(["systemctl", "--user", "enable", "--now", UNIT_NAME])
        return self.unit_path

    def uninstall(self):
        self.runner(["systemctl", "--user", "disable", "--now", UNIT_NAME])
        self.unit_path.unlink(missing_ok=True)
        self.runner(["systemctl", "--user", "daemon-reload"])

    def start(self):
        self._exec(["systemctl", "--user", "start", UNIT_NAME])

    def stop(self, quiet=False):
        result = self.runner(["systemctl", "--user", "stop", UNIT_NAME])
        if result.returncode != 0 and not quiet:
            raise ServiceError((result.stderr or "").strip() or "não estava rodando")

    def status(self):
        if not self.installed:
            return False, "não instalado"
        result = self.runner(["systemctl", "--user", "is-active", UNIT_NAME])
        estado = result.stdout.strip() or "desconhecido"
        return estado == "active", estado


MANAGERS = {"macos": LaunchdManager, "linux": SystemdManager}


def get_manager(**kwargs):
    """Gerenciador do sistema atual, ou None se não houver suporte."""
    cls = MANAGERS.get(system.os_name())
    return cls(**kwargs) if cls else None
