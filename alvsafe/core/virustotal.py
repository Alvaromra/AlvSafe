"""Consulta de hash no VirusTotal (API v3).

A chave vem da variável de ambiente VT_API_KEY e nunca do código.
Só o hash do arquivo é enviado, não o conteúdo.
"""

import hashlib
import os

import requests

API_URL = "https://www.virustotal.com/api/v3/files/{}"
TIMEOUT_SECONDS = 15


def sha256_of(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_virustotal(file_path):
    """Retorna um resumo da análise, ou None se não houver resultado.

    Resumo: last_analysis_stats do VT (malicious, suspicious, ...) + "sha256"
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None

    file_hash = sha256_of(file_path)

    try:
        response = requests.get(
            API_URL.format(file_hash),
            headers={"x-apikey": api_key},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as e:
        print(f"[VIRUSTOTAL] Erro de rede: {e}")
        return None

    if response.status_code == 404:
        return None  # hash desconhecido pelo VirusTotal
    if response.status_code != 200:
        print(f"[VIRUSTOTAL] HTTP {response.status_code}")
        return None

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    return {"sha256": file_hash, **stats}
