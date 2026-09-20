"""Pontuação de ameaça a partir dos indicadores encontrados.

Pesos calibrados por confiança: um hash conhecido é certeza, entropia
alta sozinha não é nada (todo instalador é comprimido). O limite de
quarentena é 60, então nenhum indicador fraco leva um arquivo embora
sozinho; é preciso ao menos um indicador forte, ou vários médios.
"""

WEIGHTS = {
    "signature_match": 100,      # hash conhecido: certeza
    "eicar_test": 100,           # arquivo de teste padrão, feito para ser detectado
    "vt_malicious": 100,         # VirusTotal acima do limite configurado
    "ransomware_extension": 70,
    "yara_match": 60,
    "process_injection": 60,
    "heuristic_strong": 40,      # ex.: powershell -enc, Invoke-Expression
    "suspicious_network": 25,
    "high_entropy": 20,          # normal em instaladores e binários comprimidos
    "temp_execution": 10,
}

WEAK_WEIGHT = 10          # por palavra-chave fraca encontrada
WEAK_CAP = 20             # teto, para não somar até virar ameaça sozinha

STRONG_EXTRA_WEIGHT = 20  # por palavra-chave forte além da primeira
STRONG_EXTRA_CAP = 40     # duas fortes no mesmo script já bastam para agir


def calculate_threat_score(indicators):
    score = sum(weight for name, weight in WEIGHTS.items() if indicators.get(name))
    score += min(int(indicators.get("heuristic_weak", 0)) * WEAK_WEIGHT, WEAK_CAP)
    score += min(int(indicators.get("heuristic_strong_extra", 0)) * STRONG_EXTRA_WEIGHT, STRONG_EXTRA_CAP)
    return score


def classify_score(score):
    if score >= 100:
        return "MALWARE"
    if score >= 60:
        return "DANGEROUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"
