"""Monitor de processos: apenas alerta, nunca encerra processos.

Encerrar processos pelo nome é perigoso: qualquer software legítimo
com um nome parecido seria morto. A decisão fica com o usuário.
"""

from pathlib import Path

import psutil

from engine.alerts import alert

# Comparação exata com o nome do executável (sem extensão),
# para não pegar por engano coisas como "Malwarebytes" ou "VeraCrypt".
SUSPICIOUS_NAMES = {
    "mimikatz",
    "meterpreter",
    "nc",
    "ncat",
}


def monitor_processes():
    """Verifica os processos em execução e retorna os suspeitos."""
    found = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"]
            if not name:
                continue

            if Path(name).stem.lower() in SUSPICIOUS_NAMES:
                found.append((proc.info["pid"], name))
                alert(
                    "PROCESSO SUSPEITO",
                    f"{name} (pid {proc.info['pid']})",
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return found
