"""Onde o AlvSafe guarda dados e configuração, conforme o sistema.

- macOS:   ~/Library/Application Support/AlvSafe
- Linux:   $XDG_DATA_HOME/alvsafe (dados) e $XDG_CONFIG_HOME/alvsafe (config)
- Windows: %LOCALAPPDATA%\\AlvSafe e %APPDATA%\\AlvSafe

A variável ALVSAFE_HOME sobrepõe tudo (útil em testes e instalações portáteis).
São funções, e não constantes, para que a variável possa mudar em tempo de execução.
"""

import os
import sys
from pathlib import Path

BUNDLED_DATA = Path(__file__).resolve().parent / "data"


def _override():
    value = os.environ.get("ALVSAFE_HOME")
    return Path(value).expanduser() if value else None


def _ensure(path, mode=0o755):
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    return path


def data_dir():
    base = _override()
    if base is None:
        if sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support" / "AlvSafe"
        elif sys.platform.startswith("win"):
            base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "AlvSafe"
        else:
            xdg = os.environ.get("XDG_DATA_HOME")
            base = (Path(xdg) if xdg else Path.home() / ".local" / "share") / "alvsafe"
    return _ensure(base)


def config_dir():
    base = _override()
    if base is None:
        if sys.platform == "darwin":
            return data_dir()
        if sys.platform.startswith("win"):
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "AlvSafe"
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME")
            base = (Path(xdg) if xdg else Path.home() / ".config") / "alvsafe"
    return _ensure(base)


def config_file():
    return config_dir() / "settings.json"


def log_db():
    return data_dir() / "logs.db"


def quarantine_dir():
    return _ensure(data_dir() / "quarantine", mode=0o700)


def user_rules_dir():
    """Regras YARA extras do usuário, somadas às que vêm no pacote."""
    return _ensure(data_dir() / "rules")


def user_signatures_file():
    """Hashes extras do usuário, somados aos que vêm no pacote."""
    return data_dir() / "malware_hashes.txt"


def bundled_rules_dir():
    return BUNDLED_DATA / "rules"


def bundled_signatures_file():
    return BUNDLED_DATA / "malware_hashes.txt"
