"""Monitor de rede: portas locais de backdoor e conexões de saída suspeitas."""

import ipaddress

import psutil

from alvsafe.core.alerts import alert

SUSPICIOUS_PORTS = {4444, 1337, 5555, 6666}

# Redes em CIDR. Evite faixas enormes: "185." cobriria milhões de IPs legítimos.
SUSPICIOUS_NETWORKS = [ipaddress.ip_network("192.168.56.0/24")]


def _connections(bus, kind):
    try:
        return psutil.net_connections()
    except psutil.AccessDenied:
        # No macOS, listar conexões de outros processos exige root
        alert(kind, "sem permissão para listar conexões (rode como admin)", bus=bus)
        return None


def _is_suspicious_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in SUSPICIOUS_NETWORKS)


def monitor_connections(bus=None):
    """Portas locais suspeitas em uso."""
    conns = _connections(bus, "FIREWALL")
    if conns is None:
        return []
    found = []
    for conn in conns:
        if conn.laddr and conn.laddr.port in SUSPICIOUS_PORTS:
            found.append(conn.laddr.port)
            alert("PORTA SUSPEITA", f"porta local {conn.laddr.port} (pid {conn.pid})", bus=bus)
    return found


def monitor_web(bus=None):
    """Conexões remotas suspeitas [(ip, porta)]."""
    conns = _connections(bus, "WEB")
    if conns is None:
        return []
    found = []
    for conn in conns:
        if not conn.raddr:
            continue
        ip, port = conn.raddr.ip, conn.raddr.port
        if port in SUSPICIOUS_PORTS:
            found.append((ip, port))
            alert("WEB", f"porta remota suspeita {ip}:{port} (pid {conn.pid})", bus=bus)
        elif _is_suspicious_ip(ip):
            found.append((ip, port))
            alert("WEB", f"IP suspeito {ip}:{port} (pid {conn.pid})", bus=bus)
    return found
