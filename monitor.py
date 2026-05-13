from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from scanner import AntivirusScanner

import time

scanner = AntivirusScanner()


class RealtimeMonitor(
    FileSystemEventHandler
):

    def on_created(self, event):

        if not event.is_directory:

            print()
            print("[MONITOR] Novo arquivo:")
            print(event.src_path)

            scanner.scan_file(
                event.src_path
            )


def start_monitor(path):

    observer = Observer()

    handler = RealtimeMonitor()

    observer.schedule(
        handler,
        path,
        recursive=True
    )

    observer.start()

    print()
    print(f"Monitorando: {path}")
    print()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

        print()
        print("Monitor encerrado")

    observer.join()