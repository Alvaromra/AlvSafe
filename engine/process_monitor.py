# ============================================
# engine/process_monitor.py
# ============================================

import psutil

SUSPICIOUS_NAMES = [
    'mimikatz',
    'meterpreter',
    'nc.exe',
    'malware',
    'trojan'
]


def monitor_processes():

    for proc in psutil.process_iter(
        ['pid', 'name']
    ):

        try:

            process_name = proc.info['name']

            if not process_name:
                continue

            for suspicious in SUSPICIOUS_NAMES:

                if suspicious.lower() in process_name.lower():

                    print(
                        f"[KILL] "
                        f"{process_name}"
                    )

                    proc.kill()

        except:
            pass