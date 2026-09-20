import psutil

SUSPICIOUS_PORTS = [
    4444,
    5555,
    1337,
    6666
]

SUSPICIOUS_IPS = [
    '45.9.',
    '185.',
    '192.168.56.'
]


def monitor_web():

    connections = psutil.net_connections()

    for conn in connections:

        try:

            if conn.raddr:

                ip = conn.raddr.ip

                port = conn.raddr.port

                # ====================================
                # PORT
                # ====================================

                if port in SUSPICIOUS_PORTS:

                    print(
                        '[WEB] '
                        f'Porta suspeita: {port}'
                    )

                # ====================================
                # IP
                # ====================================

                for suspicious in SUSPICIOUS_IPS:

                    if suspicious in ip:

                        print(
                            '[WEB] '
                            f'IP suspeito: {ip}'
                        )

        except:
            pass