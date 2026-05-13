from collections import defaultdict

import time

changes = defaultdict(list)

THRESHOLD = 20
TIME_WINDOW = 10


def detect_mass_modification(
    file_path
):

    current_time = time.time()

    changes['activity'].append(
        current_time
    )

    recent = [
        t for t in changes['activity']
        if current_time - t < TIME_WINDOW
    ]

    changes['activity'] = recent

    if len(recent) > THRESHOLD:

        print(
            '[RANSOMWARE] '
            'Atividade suspeita'
        )

        return True

    return False