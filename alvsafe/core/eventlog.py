"""Histórico persistente de eventos em SQLite.

O esquema (tabela logs: event, file, timestamp) é o mesmo da versão
anterior, para a GUI e o dashboard continuarem lendo sem mudança.
"""

import sqlite3
import threading
from datetime import datetime

from alvsafe import paths

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT,
    file TEXT,
    timestamp TEXT
)
"""

_lock = threading.Lock()


def _connect(db_path=None):
    conn = sqlite3.connect(db_path or paths.log_db(), timeout=5)
    conn.execute(_SCHEMA)
    return conn


def log_event(event, detail, db_path=None):
    with _lock:
        conn = _connect(db_path)
        try:
            conn.execute(
                "INSERT INTO logs (event, file, timestamp) VALUES (?, ?, ?)",
                (event, str(detail), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        finally:
            conn.close()


def recent(limit=20, db_path=None):
    """Últimos eventos, do mais recente para o mais antigo: (id, event, detail, timestamp)."""
    with _lock:
        conn = _connect(db_path)
        try:
            return conn.execute(
                "SELECT id, event, file, timestamp FROM logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
