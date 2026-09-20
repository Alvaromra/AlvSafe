from watchdog.observers import Observer

from watchdog.events import (
    FileSystemEventHandler
)

from pathlib import Path

import time

import psutil

SUSPICIOUS_EXTENSIONS = [
    '.locked',
    '.encrypted',
    '.crypt',
    '.enc',
    '.crypto'
]

EVENT_COUNTER = {}

THRESHOLD = 15

TIME_WINDOW = 10


class RansomwareHandler(
    FileSystemEventHandler
):

    def on_modified(
        self,
        event
    ):

        if event.is_directory:
            return

        process_event(
            event.src_path
        )

    def on_created(
        self,
        event
    ):

        if event.is_directory:
            return

        process_event(
            event.src_path
        )


def process_event(path):

    now = time.time()

    EVENT_COUNTER[path] = now

    recent_events = [

        t for t in EVENT_COUNTER.values()

        if now - t < TIME_WINDOW
    ]

    if len(recent_events) > THRESHOLD:

        print(
            '[RANSOMWARE] '
            'Atividade suspeita detectada'
        )

        kill_suspicious_processes()

    ext = Path(path).suffix.lower()

    if ext in SUSPICIOUS_EXTENSIONS:

        print(
            '[RANSOMWARE] '
            f'Extensão suspeita: {path}'
        )

        kill_suspicious_processes()


def kill_suspicious_processes():

    SUSPICIOUS_NAMES = [

        'encrypt',
        'locker',
        'crypt',
        'wannacry',
        'ransom'
    ]

    for proc in psutil.process_iter(
        ['pid', 'name']
    ):

        try:

            name = proc.info['name']

            if not name:
                continue

            for suspicious in SUSPICIOUS_NAMES:

                if suspicious.lower() in name.lower():

                    print(
                        '[KILL] '
                        f'{name}'
                    )

                    proc.kill()

        except:
            pass


def start_ransomware_protection():

    observer = Observer()

    handler = RansomwareHandler()

    WATCH_FOLDERS = [

        str(Path.home() / 'Documents'),

        str(Path.home() / 'Desktop'),

        str(Path.home() / 'Downloads')
    ]

    for folder in WATCH_FOLDERS:

        path = Path(folder)

        if path.exists():

            observer.schedule(
                handler,
                folder,
                recursive=True
            )

            print(
                '[RANSOMWARE] '
                f'Monitorando {folder}'
            )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()