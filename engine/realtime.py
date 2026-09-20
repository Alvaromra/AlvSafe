# ============================================
# engine/realtime.py
# ============================================

from watchdog.observers import Observer

from watchdog.events import (
    FileSystemEventHandler
)

from engine.scanner import (
    AntivirusScanner
)

from pathlib import Path

import platform
import time

scanner = AntivirusScanner()

SYSTEM = platform.system()

# ============================================
# CROSS PLATFORM PATHS
# ============================================

if SYSTEM == "Windows":

    WATCH_FOLDERS = [
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop")
    ]

elif SYSTEM == "Linux":

    if "microsoft" in platform.release().lower():

        WATCH_FOLDERS = [
            "/mnt/c/Users/Alvaro/Downloads",
            "/mnt/c/Users/Alvaro/Desktop"
        ]

    else:

        WATCH_FOLDERS = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop")
        ]

elif SYSTEM == "Darwin":

    WATCH_FOLDERS = [
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop")
    ]

else:

    WATCH_FOLDERS = []

# ============================================
# HANDLER
# ============================================

class ProtectionHandler(
    FileSystemEventHandler
):

    # ========================================
    # CREATED
    # ========================================

    def on_created(self, event):

        if event.is_directory:
            return

        time.sleep(1)

        print(
            f"[REALTIME] "
            f"{event.src_path}"
        )

        scanner.scan_file(
            event.src_path
        )

    # ========================================
    # MODIFIED
    # ========================================

    def on_modified(self, event):

        if event.is_directory:
            return

        time.sleep(1)

        print(
            f"[MODIFIED] "
            f"{event.src_path}"
        )

        scanner.scan_file(
            event.src_path
        )

# ============================================
# START
# ============================================

def start_realtime_protection():

    observer = Observer()

    handler = ProtectionHandler()

    for folder in WATCH_FOLDERS:

        path = Path(folder)

        if path.exists():

            print(
                f"[MONITORANDO] "
                f"{folder}"
            )

            observer.schedule(
                handler,
                folder,
                recursive=False
            )

        else:

            print(
                f"[IGNORADO] "
                f"{folder}"
            )

    observer.start()

    print()

    print(
        "Proteção em tempo real iniciada"
    )

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

        print()

        print(
            "Proteção encerrada"
        )

    observer.join()