from pathlib import Path

DATABASE = "database/malware_hashes.txt"


def load_signatures():

    path = Path(DATABASE)

    if not path.exists():
        return set()

    with open(path, 'r') as f:

        return set(
            line.strip()
            for line in f.readlines()
        )