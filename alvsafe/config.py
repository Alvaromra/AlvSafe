"""Configuração do AlvSafe, lida de settings.json com valores padrão."""

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from alvsafe import paths, system


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    max_file_size_mb: int = 50
    scan_extensions: list = field(default_factory=lambda: [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".command", ".py", ".js",
    ])
    # Comparados com o nome de cada pasta (não com substrings do caminho)
    excluded_dirs: list = field(default_factory=lambda: [
        ".git", "node_modules", "venv", ".venv", "__pycache__",
    ])
    # Vazio = pastas padrão do sistema (Downloads, Desktop, Documents)
    watch_folders: list = field(default_factory=list)
    realtime_protection: bool = True
    heuristic_detection: bool = True
    yara_detection: bool = True
    quarantine_enabled: bool = True
    virustotal: bool = False            # exige a variável de ambiente VT_API_KEY
    virustotal_min_detections: int = 3
    threat_threshold: int = 60
    scan_workers: int = 0  # 0 = automático

    @property
    def max_file_size_bytes(self):
        return self.max_file_size_mb * 1024 * 1024

    @property
    def extensions(self):
        return {e.lower() for e in self.scan_extensions}

    @property
    def excluded(self):
        return {d.lower() for d in self.excluded_dirs}

    def resolved_watch_folders(self):
        if self.watch_folders:
            return [Path(f).expanduser() for f in self.watch_folders]
        return system.default_watch_folders()

    def to_dict(self):
        return asdict(self)


def load_settings(path=None):
    path = Path(path) if path else paths.config_file()
    settings = Settings()

    if not path.exists():
        return settings

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: JSON inválido ({e})") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: esperado um objeto JSON")

    known = {f.name: f for f in fields(Settings)}
    for key, value in raw.items():
        if key not in known:
            continue  # chaves desconhecidas são ignoradas
        default = getattr(settings, key)
        # bool é subclasse de int: 1 não vale por True nem o contrário
        trocou_bool_por_int = (isinstance(default, int) and not isinstance(default, bool)
                               and isinstance(value, bool))
        if not isinstance(value, type(default)) or trocou_bool_por_int:
            raise ConfigError(f"{path}: '{key}' deveria ser {type(default).__name__}")
        setattr(settings, key, value)

    return settings


def save_settings(settings, path=None):
    path = Path(path) if path else paths.config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings.to_dict(), indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
