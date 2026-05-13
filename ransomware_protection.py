from pathlib import Path
import time

last_changes = {}

SUSPICIOUS_EXTENSIONS = [
    '.locked',
    '.encrypted',
    '.crypt'
]


def detect_ransomware(file_path):

    path = Path(file_path)

    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        return True

    current_time = time.time()

    if file_path not in last_changes:

        last_changes[file_path] = current_time
        return False

    diff = current_time - last_changes[file_path]

    last_changes[file_path] = current_time

    if diff < 1:
        return True

    return False