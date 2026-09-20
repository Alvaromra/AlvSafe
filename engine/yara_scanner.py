from pathlib import Path

import yara

BASE_DIR = Path.home() / "ALVSafe"

RULES_DIR = BASE_DIR / "yara_rules"

RULES_DIR.mkdir(
    exist_ok=True
)

RULE_FILE = RULES_DIR / "malware_rules.yar"

# =========================
# CRIAR REGRA PADRÃO
# =========================

if not RULE_FILE.exists():

    RULE_FILE.write_text(
        '''
rule Suspicious_Powershell
{
    strings:
        $a = "powershell -enc"
        $b = "Invoke-Expression"

    condition:
        any of them
}
'''
    )

# =========================
# COMPILAR
# =========================

rules = yara.compile(
    filepath=str(RULE_FILE)
)


def yara_scan(file_path):

    try:

        matches = rules.match(
            file_path
        )

        return matches

    except:

        return []