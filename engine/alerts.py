"""Alertas centralizados: imprime, registra no log e evita repetição."""

import threading
import time

from engine.logger import log_event

# Mesmo alerta (tipo + detalhe) só é repetido depois desse intervalo
COOLDOWN_SECONDS = 300

_last_seen = {}
_lock = threading.Lock()


def alert(kind, detail, key=None):
    """Emite um alerta. Retorna False se ele foi suprimido pelo cooldown.

    key: identifica alertas "iguais" quando o detalhe varia (ex.: contagens).
    """
    key = (kind, key if key is not None else detail)
    now = time.monotonic()

    with _lock:
        last = _last_seen.get(key)
        if last is not None and now - last < COOLDOWN_SECONDS:
            return False
        _last_seen[key] = now

    print(f"[{kind}] {detail}")

    try:
        log_event(kind, detail)
    except Exception as e:
        print(f"[ALERTA] Falha ao registrar no log: {e}")

    return True
