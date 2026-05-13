import shutil
from pathlib import Path
from datetime import datetime

QUARANTINE_DIR = Path("quarantine")

QUARANTINE_DIR.mkdir(exist_ok=True)


def quarantine_file(file_path):
    try:
        file_name = Path(file_path).name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        destination = QUARANTINE_DIR / f"{timestamp}_{file_name}"

        shutil.move(file_path, destination)

        return destination

    except Exception as e:
        print(f"Erro na quarentena: {e}")
        return None