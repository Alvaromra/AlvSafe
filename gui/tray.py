from pystray import (
    Icon,
    Menu,
    MenuItem
)

from PIL import Image

import threading

import os

import sys


def resource_path(relative_path):

    try:

        base_path = sys._MEIPASS

    except Exception:

        base_path = os.path.abspath(".")

    return os.path.join(
        base_path,
        relative_path
    )


ICON_PATH = resource_path(
    "assets/icon.ico"
)


def run_tray(app):

    image = Image.open(
        ICON_PATH
    )

    def show_window(icon, item):

        app.after(
            0,
            app.deiconify
        )

    def hide_window(icon, item):

        app.after(
            0,
            app.withdraw
        )

    def quit_app(icon, item):

        icon.stop()

        app.after(
            0,
            app.destroy
        )

        os._exit(0)

    menu = Menu(

        MenuItem(
            'Abrir ALVSafe',
            show_window
        ),

        MenuItem(
            'Ocultar',
            hide_window
        ),

        MenuItem(
            'Sair',
            quit_app
        )
    )

    tray_icon = Icon(
        'ALVSafe',
        image,
        'ALVSafe Antivirus',
        menu
    )

    threading.Thread(
        target=tray_icon.run,
        daemon=True
    ).start()