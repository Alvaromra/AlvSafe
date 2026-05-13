# ============================================
# engine/firewall.py
# ============================================

import psutil

SUSPICIOUS_PORTS = [
    4444,
    1337,
    5555,
    6666
]


def monitor_connections():

    connections = psutil.net_connections()

    for conn in connections:

        try:

            if conn.laddr:

                port = conn.laddr.port

                if port in SUSPICIOUS_PORTS:

                    print(
                        f"[PORTA SUSPEITA] "
                        f"{port}"
                    )

        except:
            pass