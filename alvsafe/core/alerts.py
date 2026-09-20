"""Alertas centralizados: emitem evento, gravam no log e evitam repetição."""

import threading
import time

from alvsafe.core.eventlog import log_event
from alvsafe.events import WARNING
from alvsafe.events import bus as default_bus

# Mesmo alerta só é repetido depois desse intervalo
COOLDOWN_SECONDS = 300

_last_seen = {}
_lock = threading.Lock()


def alert(kind, detail, key=None, bus=None, level=WARNING):
    """Emite um alerta. Retorna False se ele foi suprimido pelo cooldown.

    key: identifica alertas "iguais" quando o detalhe varia (ex.: contagens).
    """
    dedupe_key = (kind, key if key is not None else detail)
    now = time.monotonic()

    with _lock:
        last = _last_seen.get(dedupe_key)
        if last is not None and now - last < COOLDOWN_SECONDS:
            return False
        _last_seen[dedupe_key] = now

    (bus or default_bus).emit("alert", detail, level=level, category=kind)

    try:
        log_event(kind, detail)
    except Exception as e:
        (bus or default_bus).emit("error", f"falha ao gravar alerta no log: {e}", level=WARNING)

    return True


def reset():
    with _lock:
        _last_seen.clear()
