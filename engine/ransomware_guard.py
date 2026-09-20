"""Detecção de comportamento típico de ransomware.

Sinais: muitas escritas em pouco tempo, ou arquivos com extensões
usadas por ransomware. Só alerta; não encerra processos.
"""

import threading
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from engine.alerts import alert

SUSPICIOUS_EXTENSIONS = {".locked", ".encrypted", ".crypt", ".enc", ".crypto"}

THRESHOLD = 15      # eventos
TIME_WINDOW = 10    # segundos

WATCH_FOLDERS = [
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path.home() / "Downloads",
]

# Janela deslizante de timestamps: memória limitada, ao contrário
# de um dicionário que cresce com cada caminho já visto.
_events = deque()
_lock = threading.Lock()


def process_event(path, now=None):
    """Registra um evento de arquivo. Retorna True se gerou alerta."""
    now = time.monotonic() if now is None else now
    alerted = False

    with _lock:
        _events.append(now)
        while _events and now - _events[0] > TIME_WINDOW:
            _events.popleft()
        burst = len(_events)

    if burst > THRESHOLD:
        alerted |= alert(
            "RANSOMWARE",
            f"{burst} modificações em {TIME_WINDOW}s nas pastas monitoradas",
            key="burst",
        )

    if Path(path).suffix.lower() in SUSPICIOUS_EXTENSIONS:
        alerted |= alert("RANSOMWARE", f"extensão suspeita: {path}")

    return alerted


class RansomwareHandler(FileSystemEventHandler):

    def on_modified(self, event):
        if not event.is_directory:
            process_event(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            process_event(event.src_path)


def start_ransomware_protection():
    observer = Observer()
    handler = RansomwareHandler()

    for folder in WATCH_FOLDERS:
        if folder.exists():
            observer.schedule(handler, str(folder), recursive=True)
            print(f"[RANSOMWARE] Monitorando {folder}")

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
