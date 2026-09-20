"""Barramento de eventos: o núcleo emite, as interfaces (CLI, GUI) mostram.

O núcleo nunca imprime nada. Assim o mesmo código serve para terminal
e para janela, e a GUI pode repassar os eventos para a thread principal.
"""

import sys
import threading
import time
from dataclasses import dataclass, field

DEBUG = "debug"
INFO = "info"
WARNING = "warning"
CRITICAL = "critical"


@dataclass(frozen=True)
class Event:
    kind: str                 # ex.: "scan.file", "threat", "alert", "watch.folder"
    message: str
    level: str = INFO
    path: str | None = None
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class EventBus:

    def __init__(self):
        self._subscribers = []
        self._lock = threading.Lock()

    def subscribe(self, callback):
        """Registra um callback(event). Retorna uma função que cancela o registro."""
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe():
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def emit(self, kind, message, level=INFO, path=None, **data):
        event = Event(kind=kind, message=message, level=level,
                      path=str(path) if path is not None else None, data=data)
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:  # um assinante com defeito não derruba o núcleo
                print(f"[alvsafe] erro num assinante de eventos: {e}", file=sys.stderr)
        return event


# Barramento padrão do processo
bus = EventBus()
