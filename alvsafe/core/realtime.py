"""Proteção em tempo real: um só observador de arquivos para scan e ransomware.

- Arquivos criados, modificados ou renomeados entram numa fila com debounce:
  só são escaneados depois de ficarem quietos por `debounce` segundos.
  Isso evita escanear um download pela metade (e escanear 50 vezes
  um arquivo que está sendo gravado aos poucos).
- Renomeações contam: ransomware costuma trocar foto.jpg por foto.jpg.locked.
"""

import os
import threading
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from alvsafe import paths
from alvsafe.config import load_settings
from alvsafe.core.alerts import alert
from alvsafe.events import INFO, WARNING
from alvsafe.events import bus as default_bus

SUSPICIOUS_EXTENSIONS = {".locked", ".encrypted", ".crypt", ".enc", ".crypto"}


class RansomwareDetector:
    """Rajadas de escrita e extensões típicas de ransomware."""

    def __init__(self, threshold=15, window=10.0, bus=None):
        self.threshold = threshold
        self.window = window
        self.bus = bus
        self._events = deque()
        self._lock = threading.Lock()

    def process(self, path, now=None):
        """Registra um evento de arquivo. Retorna True se gerou alerta."""
        now = time.monotonic() if now is None else now
        alerted = False

        with self._lock:
            self._events.append(now)
            while self._events and now - self._events[0] > self.window:
                self._events.popleft()
            burst = len(self._events)

        if burst > self.threshold:
            alerted |= alert(
                "RANSOMWARE",
                f"{burst} modificações em {self.window:.0f}s nas pastas monitoradas",
                key="burst", bus=self.bus,
            )

        if Path(path).suffix.lower() in SUSPICIOUS_EXTENSIONS:
            alerted |= alert("RANSOMWARE", f"extensão suspeita: {path}", bus=self.bus)

        return alerted


class _Handler(FileSystemEventHandler):

    def __init__(self, watcher):
        self.watcher = watcher

    def on_created(self, event):
        if not event.is_directory:
            self.watcher.notify(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.watcher.notify(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.watcher.notify(event.dest_path)


def check_folder(folder):
    """None se a pasta pode ser monitorada; senão, o motivo."""
    folder = Path(folder)
    if not folder.exists():
        return "não existe"
    if not folder.is_dir():
        return "não é pasta"
    try:
        os.listdir(folder)
    except PermissionError:
        return "sem permissão de leitura"
    return None


class Watcher:

    def __init__(self, settings=None, bus=None, scanner=None, folders=None,
                 debounce=1.0, scan=True, ransomware=True):
        self.settings = settings or load_settings()
        self.bus = bus or default_bus
        self.folders = [Path(f).expanduser() for f in (folders or self.settings.resolved_watch_folders())]
        self.debounce = debounce
        self.scan = scan
        self.ransomware = RansomwareDetector(bus=self.bus) if ransomware else None

        if scanner is None and scan:
            from alvsafe.core.scanner import Scanner
            scanner = Scanner(self.settings, bus=self.bus)
        self.scanner = scanner

        self._ignore = [str(paths.data_dir().resolve())]
        self._pending = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._observer = None
        self._worker = None
        self.watching = []

    @property
    def backend(self):
        return type(self._observer or Observer()).__name__

    def _ignored(self, path):
        try:
            real = str(Path(path).resolve())
        except OSError:
            return True
        return any(real.startswith(prefix) for prefix in self._ignore)

    def notify(self, path, now=None):
        """Chamado pelo watchdog para cada evento de arquivo."""
        if self._ignored(path):
            return
        if self.ransomware:
            self.ransomware.process(path, now=now)
        if self.scan:
            with self._lock:
                self._pending[path] = time.monotonic() if now is None else now

    def due(self, now=None):
        """Retira da fila os caminhos que ficaram quietos pelo tempo de debounce."""
        now = time.monotonic() if now is None else now
        with self._lock:
            ready = [p for p, t in self._pending.items() if now - t >= self.debounce]
            for p in ready:
                del self._pending[p]
        return ready

    def _work(self):
        while not self._stop.wait(0.25):
            for path in self.due():
                if os.path.isfile(path):
                    self.scanner.scan_file(path)

    def start(self):
        self._observer = Observer()
        handler = _Handler(self)

        for folder in self.folders:
            problem = check_folder(folder)
            if problem:
                self.bus.emit("watch.skip", f"{folder}: {problem}", level=WARNING, path=folder)
                continue
            self._observer.schedule(handler, str(folder), recursive=True)
            self.watching.append(folder)
            self.bus.emit("watch.folder", f"monitorando {folder}", level=INFO, path=folder)

        self._observer.start()
        if self.scan:
            self._worker = threading.Thread(target=self._work, name="alvsafe-realtime", daemon=True)
            self._worker.start()

        self.bus.emit("watch.start", f"proteção em tempo real ativa ({self.backend})",
                      level=INFO, backend=self.backend, folders=[str(f) for f in self.watching])
        return self

    def stop(self):
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._worker:
            self._worker.join(timeout=5)

    def sleep(self, seconds):
        """Espera até `seconds`; retorna True se o watcher foi parado."""
        return self._stop.wait(seconds)

    def wait(self):
        """Bloqueia até stop() ou Ctrl+C."""
        try:
            while not self._stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def start_realtime_protection():
    """Compatibilidade com a GUI antiga: roda o watcher até ser interrompido."""
    Watcher().start().wait()
