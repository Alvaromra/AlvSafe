"""Identidade visual do AlvSafe.

A paleta é de sala de monitoramento: fundo grafite frio, superfícies em
degraus discretos e cor reservada para significado, nunca para enfeite.
Verde só aparece quando há proteção ativa, âmbar em aviso e vermelho em
ameaça, então a tela pode ser lida de longe, pela cor, sem se ler texto.

Cada cor é uma tupla (claro, escuro), que é o formato que o
customtkinter usa para trocar de tema sem recriar os widgets.
"""

import sys

# ---------------------------------------------------------------- cores

BG = ("#F2F4F7", "#12151A")           # fundo da janela
SIDEBAR = ("#E8EBF0", "#171B22")      # navegação
SURFACE = ("#FFFFFF", "#1B2029")      # cartões
SURFACE_2 = ("#F7F8FA", "#212733")    # linhas dentro de cartões
BORDER = ("#D8DCE4", "#2C333F")

TEXT = ("#1A1D23", "#E7EAF0")
TEXT_MUTED = ("#6B7280", "#8B93A1")
TEXT_FAINT = ("#9AA1AC", "#646C7A")

ACCENT = ("#15803D", "#35C48F")       # protegido, ação principal
ACCENT_HOVER = ("#166534", "#2BA97A")
WARNING = ("#B45309", "#E2A33A")
DANGER = ("#B91C1C", "#E5484D")
NEUTRAL = ("#64748B", "#6B7480")

GHOST = ("#E2E6EC", "#252B36")        # botão secundário
GHOST_HOVER = ("#D5DAE2", "#2E3542")

SEVERITY = {
    "critical": DANGER,
    "warning": WARNING,
    "info": NEUTRAL,
    "debug": TEXT_FAINT,
    "ok": ACCENT,
}

# ----------------------------------------------------------- tipografia

if sys.platform == "darwin":
    FAMILY = "SF Pro Text"
    MONO = "SF Mono"
elif sys.platform.startswith("win"):
    FAMILY = "Segoe UI"
    MONO = "Consolas"
else:
    FAMILY = "DejaVu Sans"
    MONO = "DejaVu Sans Mono"

# Escala curta e com saltos claros: título, seção, corpo, apoio
SIZE_DISPLAY = 26
SIZE_TITLE = 17
SIZE_BODY = 13
SIZE_SMALL = 11

# ------------------------------------------------------------- espaço

GAP = 8
PAD = 16
PAD_LG = 24
RADIUS = 10

SIDEBAR_WIDTH = 216


def font(ctk, size=SIZE_BODY, weight="normal", mono=False):
    return ctk.CTkFont(family=MONO if mono else FAMILY, size=size, weight=weight)
