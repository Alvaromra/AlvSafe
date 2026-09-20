import sqlite3


import matplotlib.pyplot as plt

from matplotlib.backends.backend_tkagg import (
    FigureCanvasTkAgg
)

import customtkinter as ctk

# ============================================
# DATABASE
# ============================================

from alvsafe.paths import log_db

# ============================================
# LOAD DATA
# ============================================

def load_stats():

    conn = sqlite3.connect(log_db())

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT event,
        COUNT(*)
        FROM logs
        GROUP BY event
        '''
    )

    data = cursor.fetchall()

    conn.close()

    return data

# ============================================
# DASHBOARD
# ============================================

def open_dashboard(app):

    dashboard = ctk.CTkToplevel(app)

    dashboard.title(
        "ALVSafe Dashboard"
    )

    dashboard.geometry(
        "900x600"
    )

    title = ctk.CTkLabel(
        dashboard,
        text="Dashboard",
        font=("Arial", 28, "bold")
    )

    title.pack(
        pady=20
    )

    stats = load_stats()

    if not stats:

        empty = ctk.CTkLabel(
            dashboard,
            text="Sem dados ainda",
            font=("Arial", 18)
        )

        empty.pack(
            pady=50
        )

        return

    labels = [
        row[0]
        for row in stats
    ]

    values = [
        row[1]
        for row in stats
    ]

    fig, ax = plt.subplots(
        figsize=(7, 5)
    )

    ax.bar(
        labels,
        values
    )

    ax.set_title(
        "Detecções"
    )

    canvas = FigureCanvasTkAgg(
        fig,
        master=dashboard
    )

    canvas.draw()

    canvas.get_tk_widget().pack(
        fill="both",
        expand=True,
        padx=20,
        pady=20
    )