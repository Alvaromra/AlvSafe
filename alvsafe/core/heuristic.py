"""Heurística por palavras-chave, restrita a arquivos de texto.

Procurar palavras dentro de binários é a origem dos falsos positivos:
o instalador do Python contém a string "curl", e qualquer executável
contém "VirtualAlloc". Em binário, essas sequências não significam
nada. Por isso a heurística só roda em conteúdo textual.

As palavras são separadas por peso. As fortes praticamente não
aparecem em script legítimo. As fracas são comuns e só pesam somadas.
"""

from dataclasses import dataclass, field

# Execução ofuscada, injeção em processo e ferramentas de ataque
STRONG_KEYWORDS = [
    "powershell -enc",
    "powershell -e ",
    "-encodedcommand",
    "invoke-expression",
    "iex(",
    "downloadstring",
    "createremotethread",
    "virtualallocex",
    "writeprocessmemory",
    "mimikatz",
    "meterpreter",
    "frombase64string",
]

# Comuns em software legítimo: só contam somadas
WEAK_KEYWORDS = [
    "cmd.exe /c",
    "wget ",
    "curl ",
    "base64",
    "nc.exe",
    "chmod +x",
    "/dev/tcp/",
]

EICAR_MARKER = "eicar-standard-antivirus-test-file"

# Um arquivo de texto pode ter algum byte estranho, mas não muitos
_BINARY_SAMPLE = 8192
_BINARY_RATIO = 0.10
_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b\x1b"


@dataclass
class HeuristicResult:
    strong: list = field(default_factory=list)
    weak: list = field(default_factory=list)
    eicar: bool = False
    binary: bool = False

    def __bool__(self):
        return bool(self.strong or self.weak or self.eicar)


def looks_binary(content):
    sample = content[:_BINARY_SAMPLE]
    if not sample:
        return False
    if b"\x00" in sample:
        # UTF-16 (comum em scripts do Windows) tem zeros, mas alternados
        if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return False
        return True
    return sum(1 for b in sample if b not in _TEXT_BYTES) / len(sample) > _BINARY_RATIO


def decode(content):
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return content.decode("utf-16", errors="ignore")
    return content.decode("utf-8", errors="ignore")


def analyze(content):
    """Analisa o conteúdo (bytes). Em binário, devolve resultado vazio."""
    if looks_binary(content):
        return HeuristicResult(binary=True)

    text = decode(content).lower()
    return HeuristicResult(
        strong=[k.strip() for k in STRONG_KEYWORDS if k in text],
        weak=[k.strip() for k in WEAK_KEYWORDS if k in text],
        eicar=EICAR_MARKER in text,
    )
