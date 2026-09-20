"""Monitor de conexões de saída para portas e redes suspeitas."""

import ipaddress

import psutil

from engine.alerts import alert

SUSPICIOUS_PORTS = {4444, 5555, 1337, 6666}

# Redes em notação CIDR. Evite faixas enormes: um prefixo como
# "185." cobre milhões de endereços legítimos.
SUSPICIOUS_NETWORKS = [
    ipaddress.ip_network("192.168.56.0/24"),
]


def _is_suspicious_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in SUSPICIOUS_NETWORKS)


def monitor_web():
    """Retorna as conexões remotas suspeitas (ip, porta)."""
    try:
        connections = psutil.net_connections()
    except psutil.AccessDenied:
        alert("WEB", "Sem permissão para listar conexões (rode como admin)")
        return []

    found = []

    for conn in connections:
        if not conn.raddr:
            continue

        ip, port = conn.raddr.ip, conn.raddr.port

        if port in SUSPICIOUS_PORTS:
            found.append((ip, port))
            alert("WEB", f"porta remota suspeita {ip}:{port} (pid {conn.pid})")
        elif _is_suspicious_ip(ip):
            found.append((ip, port))
            alert("WEB", f"IP suspeito {ip}:{port} (pid {conn.pid})")

    return found
