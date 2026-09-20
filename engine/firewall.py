"""Monitor de conexões: alerta portas locais associadas a backdoors."""

import psutil

from engine.alerts import alert

SUSPICIOUS_PORTS = {4444, 1337, 5555, 6666}


def monitor_connections():
    """Retorna as portas locais suspeitas em uso."""
    try:
        connections = psutil.net_connections()
    except psutil.AccessDenied:
        # No macOS, listar conexões de outros processos exige root
        alert("FIREWALL", "Sem permissão para listar conexões (rode como admin)")
        return []

    found = []

    for conn in connections:
        if conn.laddr and conn.laddr.port in SUSPICIOUS_PORTS:
            found.append(conn.laddr.port)
            alert("PORTA SUSPEITA", f"porta local {conn.laddr.port} (pid {conn.pid})")

    return found
