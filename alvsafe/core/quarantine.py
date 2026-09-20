"""Quarentena neutralizada, com metadados e restauração.

Cada arquivo vira <id>.bin, com os bytes embaralhados por XOR. Assim
ele não roda nem é reconhecido pelo sistema (nem por outro antivírus),
e fica com permissão 0600. Ao lado fica <id>.json com os metadados.
O original só é apagado depois que a cópia foi gravada.
"""

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from alvsafe import paths

XOR_KEY = 0xA5
_TABLE = bytes(i ^ XOR_KEY for i in range(256))  # translate() faz o XOR em C
CHUNK = 1024 * 1024


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    sha256: str
    size: int
    mode: int
    reason: str
    quarantined_at: str


class Quarantine:

    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else paths.quarantine_dir()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _blob(self, entry_id):
        return self.directory / f"{entry_id}.bin"

    def _meta(self, entry_id):
        return self.directory / f"{entry_id}.json"

    def _new_id(self, sha256):
        base = f"{datetime.now():%Y%m%d-%H%M%S}-{sha256[:8]}"
        entry_id, n = base, 1
        while self._meta(entry_id).exists():
            n += 1
            entry_id = f"{base}-{n}"
        return entry_id

    def add(self, path, reason=""):
        path = Path(path).resolve()
        info = path.stat()

        digest = hashlib.sha256()
        tmp = self.directory / f".{path.name}.partial"
        try:
            with open(path, "rb") as src, open(tmp, "wb") as dst:
                os.chmod(tmp, 0o600)
                for chunk in iter(lambda: src.read(CHUNK), b""):
                    digest.update(chunk)
                    dst.write(chunk.translate(_TABLE))
            sha256 = digest.hexdigest()

            entry = QuarantineEntry(
                id=self._new_id(sha256),
                original_path=str(path),
                sha256=sha256,
                size=info.st_size,
                mode=stat.S_IMODE(info.st_mode),
                reason=reason,
                quarantined_at=datetime.now().isoformat(timespec="seconds"),
            )
            os.replace(tmp, self._blob(entry.id))
        finally:
            if tmp.exists():
                tmp.unlink()

        self._meta(entry.id).write_text(json.dumps(asdict(entry), indent=2, ensure_ascii=False))
        os.chmod(self._meta(entry.id), 0o600)
        path.unlink()
        return entry

    def list(self):
        entries = []
        for meta in sorted(self.directory.glob("*.json")):
            try:
                entries.append(QuarantineEntry(**json.loads(meta.read_text())))
            except (ValueError, TypeError):
                continue
        return entries

    def get(self, entry_id):
        meta = self._meta(entry_id)
        if not meta.exists():
            raise KeyError(entry_id)
        return QuarantineEntry(**json.loads(meta.read_text()))

    def restore(self, entry_id, destination=None, overwrite=False):
        entry = self.get(entry_id)
        dest = Path(destination) if destination else Path(entry.original_path)
        if dest.is_dir():
            dest = dest / Path(entry.original_path).name
        if dest.exists() and not overwrite:
            raise FileExistsError(dest)

        dest.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with open(self._blob(entry_id), "rb") as src, open(dest, "wb") as dst:
            for chunk in iter(lambda: src.read(CHUNK), b""):
                plain = chunk.translate(_TABLE)
                digest.update(plain)
                dst.write(plain)

        if digest.hexdigest() != entry.sha256:
            dest.unlink()
            raise ValueError(f"quarentena {entry_id} corrompida (hash não confere)")

        os.chmod(dest, entry.mode)
        self.delete(entry_id)
        return dest

    def delete(self, entry_id):
        self.get(entry_id)  # KeyError se não existir
        self._blob(entry_id).unlink(missing_ok=True)
        self._meta(entry_id).unlink(missing_ok=True)
