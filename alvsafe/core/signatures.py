"""Banco de hashes conhecidos: o do pacote somado ao do usuário."""

from alvsafe import paths


def _read(path):
    if not path.exists():
        return set()
    hashes = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            hashes.add(line)
    return hashes


def load_signatures():
    return _read(paths.bundled_signatures_file()) | _read(paths.user_signatures_file())
