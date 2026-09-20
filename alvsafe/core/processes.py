"""Monitor de processos: apenas alerta, nunca encerra processos."""

from pathlib import Path

import psutil

from alvsafe.core.alerts import alert

# Comparação exata com o nome do executável (sem extensão)
SUSPICIOUS_NAMES = {"mimikatz", "meterpreter", "nc", "ncat"}


def monitor_processes(bus=None):
    """Retorna [(pid, nome)] dos processos suspeitos em execução."""
    found = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"]
            if name and Path(name).stem.lower() in SUSPICIOUS_NAMES:
                found.append((proc.info["pid"], name))
                alert("PROCESSO SUSPEITO", f"{name} (pid {proc.info['pid']})", bus=bus)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return found
