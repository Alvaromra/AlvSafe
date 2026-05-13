# ============================================
# engine/threat_score.py
# ============================================

def calculate_threat_score(
    indicators
):

    score = 0

    # ========================================
    # HEURISTIC
    # ========================================

    if indicators.get(
        'powershell_encoded'
    ):

        score += 40

    if indicators.get(
        'process_injection'
    ):

        score += 60

    if indicators.get(
        'ransomware_extension'
    ):

        score += 70

    if indicators.get(
        'yara_match'
    ):

        score += 80

    if indicators.get(
        'high_entropy'
    ):

        score += 30

    if indicators.get(
        'suspicious_network'
    ):

        score += 25

    if indicators.get(
        'temp_execution'
    ):

        score += 20

    return score

# ============================================
# CLASSIFICATION
# ============================================

def classify_score(
    score
):

    if score >= 100:

        return 'MALWARE'

    elif score >= 60:

        return 'DANGEROUS'

    elif score >= 30:

        return 'SUSPICIOUS'

    return 'SAFE'