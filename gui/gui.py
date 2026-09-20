import sys
import time

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))

import customtkinter as ctk

from tkinter import filedialog

from threading import Thread

from datetime import datetime

from alvsafe import system
from alvsafe.core.network import monitor_connections, monitor_web
from alvsafe.core.processes import monitor_processes
from alvsafe.core.quarantine import Quarantine
from alvsafe.core.realtime import start_realtime_protection
from alvsafe.core.scanner import Scanner
from alvsafe.events import bus
from alvsafe.paths import log_db

from gui.tray import run_tray
from gui.dashboard import open_dashboard

# Notificações do sistema para ameaças e alertas
bus.subscribe(
    lambda e: system.notify("AlvSafe", e.message)
    if e.kind in ("threat", "alert") else None
)

scanner = Scanner()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()

run_tray(app)

app.title("ALVSafe Antivirus")

app.geometry("1200x700")

# ============================================
# GRID
# ============================================

app.grid_columnconfigure(
    1,
    weight=1
)

app.grid_rowconfigure(
    0,
    weight=1
)

# ============================================
# SIDEBAR
# ============================================

sidebar = ctk.CTkFrame(
    app,
    width=250,
    corner_radius=0
)

sidebar.grid(
    row=0,
    column=0,
    sticky="ns"
)

title = ctk.CTkLabel(
    sidebar,
    text="ALVSafe",
    font=("Arial", 30, "bold")
)

title.pack(
    pady=(40, 10)
)

subtitle = ctk.CTkLabel(
    sidebar,
    text="Advanced Protection",
    font=("Arial", 14)
)

subtitle.pack(
    pady=(0, 30)
)

# ============================================
# MAIN FRAME
# ============================================

main_frame = ctk.CTkFrame(app)

main_frame.grid(
    row=0,
    column=1,
    sticky="nsew",
    padx=20,
    pady=20
)

# ============================================
# STATUS
# ============================================

status_label = ctk.CTkLabel(
    main_frame,
    text="🟢 Protegido",
    font=("Arial", 28, "bold")
)

status_label.pack(
    pady=20
)

# ============================================
# INFO FRAME
# ============================================

info_frame = ctk.CTkFrame(
    main_frame
)

info_frame.pack(
    fill="x",
    padx=20,
    pady=10
)

files_label = ctk.CTkLabel(
    info_frame,
    text="Arquivos Escaneados: 0",
    font=("Arial", 16)
)

files_label.pack(
    anchor="w",
    padx=20,
    pady=10
)

threats_label = ctk.CTkLabel(
    info_frame,
    text="Ameaças Detectadas: 0",
    font=("Arial", 16)
)

threats_label.pack(
    anchor="w",
    padx=20,
    pady=10
)

last_scan_label = ctk.CTkLabel(
    info_frame,
    text="Último Scan: Nunca",
    font=("Arial", 16)
)

last_scan_label.pack(
    anchor="w",
    padx=20,
    pady=10
)

# ============================================
# PROGRESS BAR
# ============================================

progress = ctk.CTkProgressBar(
    main_frame,
    width=700
)

progress.pack(
    pady=20
)

progress.set(0)

# ============================================
# LOG BOX
# ============================================

log_box = ctk.CTkTextbox(
    main_frame,
    width=850,
    height=350,
    font=("Consolas", 13)
)

log_box.pack(
    padx=20,
    pady=20,
    fill="both",
    expand=True
)

# ============================================
# LOG FUNCTION
# ============================================

def log(message):

    current_time = datetime.now().strftime(
        "%H:%M:%S"
    )

    log_box.insert(
        "end",
        f"[{current_time}] {message}\n"
    )

    log_box.see("end")

# ============================================
# UPDATE STATS
# ============================================

def update_stats():

    files_label.configure(
        text=(
            "Arquivos Escaneados: "
            f"{scanner.scanned}"
        )
    )

    threats_label.configure(
        text=(
            "Ameaças Detectadas: "
            f"{len(scanner.infected)}"
        )
    )

# ============================================
# SCAN FUNCTION
# ============================================

def run_scan(folder):

    status_label.configure(
        text="🟡 Escaneando..."
    )

    progress.set(0)

    log(
        f"Escaneando: {folder}"
    )

    scanner.scan_path(
        folder
    )

    progress.set(1)

    update_stats()

    last_scan_label.configure(
        text=(
            "Último Scan: "
            f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        )
    )

    log("Scan finalizado")

    status_label.configure(
        text="🟢 Protegido"
    )

# ============================================
# SELECT FOLDER
# ============================================

def choose_folder():

    folder = filedialog.askdirectory()

    if folder:

        Thread(
            target=run_scan,
            args=(folder,),
            daemon=True
        ).start()

# ============================================
# POPUP WINDOW
# ============================================

def create_popup(
    title,
    content
):

    popup = ctk.CTkToplevel(app)

    popup.title(title)

    popup.geometry("500x400")

    popup.grab_set()

    label = ctk.CTkLabel(
        popup,
        text=title,
        font=("Arial", 24, "bold")
    )

    label.pack(
        pady=20
    )

    textbox = ctk.CTkTextbox(
        popup,
        width=420,
        height=250
    )

    textbox.pack(
        padx=20,
        pady=20,
        fill="both",
        expand=True
    )

    textbox.insert(
        "0.0",
        content
    )

    textbox.configure(
        state="disabled"
    )

# ============================================
# PROTECTION STATUS
# ============================================

def protection_status():

    realtime_status = (
        "🟢 Proteção em tempo real ativa\n\n"
        "🟢 Monitoramento de processos ativo\n\n"
        "🟢 Proteção web ativa\n\n"
        "🟢 Proteção ransomware ativa\n\n"
        "🟢 Firewall monitorando\n\n"
        "🟢 Engine heurística ativa\n\n"
        "🟢 YARA ativo\n"
        
    )

    create_popup(
        "Proteção Ativa",
        realtime_status
    )

# ============================================
# QUARANTINE
# ============================================

def open_quarantine():

    entries = Quarantine().list()

    if not entries:

        content = (
            "Nenhum arquivo "
            "em quarentena"
        )

    else:

        content = "\n".join(
            f"{e.id}  {e.original_path}" for e in entries
        )

    create_popup(
        "Quarentena",
        content
    )

# ============================================
# SETTINGS
# ============================================

def open_settings():

    settings_text = (
        "ALVSafe Settings\n\n"
        "✅ Proteção em tempo real\n"
        "✅ Detecção heurística\n"
        "✅ YARA\n"
        "✅ Firewall monitor\n"
        "✅ Quarentena automática\n"
        "✅ Monitoramento de processos\n"
    )

    create_popup(
        "Configurações",
        settings_text
    )

# ============================================
# LOGS
# ============================================

def open_logs():

    import sqlite3

    try:

        conn = sqlite3.connect(
            log_db()
        )

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT event,
            file,
            timestamp
            FROM logs
            ORDER BY id DESC
            LIMIT 50
            '''
        )

        rows = cursor.fetchall()

        conn.close()

        if not rows:

            content = (
                'Nenhum log encontrado'
            )

        else:

            content = ''

            for row in rows:

                content += (
                    f'[{row[2]}]\n'
                    f'{row[0]}\n'
                    f'{row[1]}\n\n'
                )

        create_popup(
            'Logs',
            content
        )

    except Exception as e:

        create_popup(
            'Erro',
            str(e)
        )

# ============================================
# REALTIME THREAD
# ============================================

def realtime_worker():

    log(
        "Proteção em tempo real iniciada"
    )

    start_realtime_protection()

# ============================================
# PROCESS MONITOR THREAD
# ============================================

def process_worker():

    while True:

        monitor_processes()

        time.sleep(5)

# ============================================
# FIREWALL THREAD
# ============================================

def firewall_worker():

    while True:

        monitor_connections()

        time.sleep(5)

# ============================================
# BUTTONS
# ============================================

scan_button = ctk.CTkButton(
    sidebar,
    text="🔍 Escanear Pasta",
    command=choose_folder,
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

scan_button.pack(
    pady=20
)

protection_button = ctk.CTkButton(
    sidebar,
    text="🛡 Proteção Ativa",
    command=protection_status,
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

protection_button.pack(
    pady=20
)

quarantine_button = ctk.CTkButton(
    sidebar,
    text="☣ Quarentena",
    command=open_quarantine,
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

quarantine_button.pack(
    pady=20
)

settings_button = ctk.CTkButton(
    sidebar,
    text="⚙ Configurações",
    command=open_settings,
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

settings_button.pack(
    pady=20
)

dashboard_button = ctk.CTkButton(
    sidebar,
    text="📊 Dashboard",
    command=lambda:
        open_dashboard(app),
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

dashboard_button.pack(
    pady=20
)

logs_button = ctk.CTkButton(
    sidebar,
    text="📄 Logs",
    command=open_logs,
    width=200,
    height=50,
    font=("Arial", 16, "bold")
)

logs_button.pack(
    pady=20
)

# ============================================
# START THREADS
# ============================================

Thread(
    target=realtime_worker,
    daemon=True
).start()

Thread(
    target=process_worker,
    daemon=True
).start()

Thread(
    target=firewall_worker,
    daemon=True
).start()

# ============================================
# INITIAL LOGS
# ============================================

log("ALVSafe iniciado")

log(
    "Engine heurística carregada"
)

log(
    "Monitoramento ativo"
)

# ============================================
# MINIMIZE TO TRAY
# ============================================


def minimize_to_tray():

    app.withdraw()


app.protocol(
    'WM_DELETE_WINDOW',
    minimize_to_tray
)

def web_worker():

    while True:

        monitor_web()

        time.sleep(10)


Thread(
    target=web_worker,
    daemon=True
).start()

# ============================================
# MAIN LOOP
# ============================================

app.mainloop()