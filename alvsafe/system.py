"""O que muda de um sistema operacional para outro."""

import platform
import shutil
import subprocess
import sys
from pathlib import Path


def os_name():
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("win"):
        return "windows"
    return sys.platform


def is_wsl():
    return os_name() == "linux" and "microsoft" in platform.release().lower()


def default_watch_folders():
    home = Path.home()
    return [home / "Downloads", home / "Desktop", home / "Documents"]


def notification_backend():
    """Nome do programa usado para notificar, ou None se não houver."""
    if os_name() == "macos" and shutil.which("osascript"):
        return "osascript"
    if os_name() == "linux" and shutil.which("notify-send"):
        return "notify-send"
    return None


def notify(title, message):
    """Mostra uma notificação do sistema. Retorna True se deu certo."""
    backend = notification_backend()

    if backend == "osascript":
        # Texto passado como argumento, nunca interpolado no script:
        # um nome de arquivo com aspas não consegue injetar AppleScript.
        cmd = [
            "osascript",
            "-e", "on run argv",
            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run",
            title, message,
        ]
    elif backend == "notify-send":
        cmd = ["notify-send", "--app-name=AlvSafe", title, message]
    else:
        return False

    try:
        return subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
