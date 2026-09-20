"""Heurística por palavras-chave no conteúdo do arquivo."""

SUSPICIOUS_KEYWORDS = [
    "powershell -enc",
    "cmd.exe /c",
    "wget",
    "curl",
    "base64",
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "Invoke-Expression",
    "DownloadString",
    "mimikatz",
    "nc.exe",
    "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
]

_LOWERED = [(k, k.lower()) for k in SUSPICIOUS_KEYWORDS]


def find_keywords(content):
    """Palavras-chave suspeitas encontradas no conteúdo (bytes).

    Decodifica como UTF-8 e UTF-16, porque scripts do Windows
    costumam ser salvos em UTF-16.
    """
    text = (
        content.decode("utf-8", errors="ignore")
        + content.decode("utf-16", errors="ignore")
    ).lower()
    return [original for original, lowered in _LOWERED if lowered in text]
