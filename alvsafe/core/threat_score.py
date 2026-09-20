"""Pontuação de ameaça a partir dos indicadores encontrados."""

WEIGHTS = {
    "powershell_encoded": 40,
    "process_injection": 60,
    "ransomware_extension": 70,
    "yara_match": 80,
    "high_entropy": 30,
    "suspicious_network": 25,
    "temp_execution": 20,
}


def calculate_threat_score(indicators):
    return sum(weight for name, weight in WEIGHTS.items() if indicators.get(name))


def classify_score(score):
    if score >= 100:
        return "MALWARE"
    if score >= 60:
        return "DANGEROUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"
