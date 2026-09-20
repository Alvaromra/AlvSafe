from pathlib import Path

from concurrent.futures import (
    ThreadPoolExecutor
)

from rich import print

from engine.signatures import (
    load_signatures
)

from engine.heuristic import (
    heuristic_scan
)

from engine.quarantine import (
    quarantine_file
)

from engine.logger import (
    log_event
)

from engine.yara_scanner import (
    yara_scan
)

from engine.threat_score import (
    calculate_threat_score,
    classify_score
)

from gui.notifications import (
    show_notification
)

import hashlib

import threading

import math

signatures = load_signatures()

EXTENSIONS = [
    '.exe',
    '.dll',
    '.bat',
    '.cmd',
    '.ps1',
    '.sh',
    '.py',
    '.js'
]

MAX_FILE_SIZE = 50 * 1024 * 1024

EXCLUDED_DIRS = [
    'venv',
    '.git',
    'node_modules',
    '__pycache__',
    'AppData',
    'Steam',
    'Cache'
]


class AntivirusScanner:

    def __init__(self):

        self.infected = []

        self.scanned = 0

        self.lock = threading.Lock()

    # ========================================
    # ENTROPY
    # ========================================

    def calculate_entropy(
        self,
        data
    ):

        if not data:
            return 0

        entropy = 0

        for x in range(256):

            p_x = (
                data.count(
                    bytes([x])
                ) / len(data)
            )

            if p_x > 0:

                entropy += (
                    - p_x *
                    math.log2(p_x)
                )

        return entropy

    # ========================================
    # SCAN FILE
    # ========================================

    def scan_file(
        self,
        file_path
    ):

        try:

            path = Path(file_path)

            if not path.is_file():
                return

            if path.stat().st_size > MAX_FILE_SIZE:
                return

            if path.suffix.lower() not in EXTENSIONS:
                return

            with self.lock:

                self.scanned += 1

            print(
                f"[cyan]Escaneando:[/cyan] "
                f"{file_path}"
            )

            indicators = {

                'powershell_encoded': False,

                'process_injection': False,

                'ransomware_extension': False,

                'yara_match': False,

                'high_entropy': False,

                'suspicious_network': False,

                'temp_execution': False
            }

            # ====================================
            # READ FILE
            # ====================================

            with open(
                file_path,
                'rb'
            ) as f:

                content = f.read()

            # ====================================
            # ENTROPY
            # ====================================

            entropy = self.calculate_entropy(
                content
            )

            if entropy > 7.2:

                indicators[
                    'high_entropy'
                ] = True

                print(
                    '[ENTROPY] '
                    f'{entropy:.2f}'
                )

            # ====================================
            # TEMP EXECUTION
            # ====================================

            if 'temp' in str(
                file_path
            ).lower():

                indicators[
                    'temp_execution'
                ] = True

            # ====================================
            # HEURISTIC
            # ====================================

            heuristic_result = (
                heuristic_scan(
                    file_path
                )
            )

            if heuristic_result:

                indicators[
                    'powershell_encoded'
                ] = True

            # ====================================
            # YARA
            # ====================================

            yara_matches = yara_scan(
                file_path
            )

            if yara_matches:

                indicators[
                    'yara_match'
                ] = True

            # ====================================
            # HASH
            # ====================================

            file_hash = hashlib.sha256(
                content
            ).hexdigest()

            if file_hash in signatures:

                indicators[
                    'yara_match'
                ] = True

            # ====================================
            # SCORE
            # ====================================

            score = calculate_threat_score(
                indicators
            )

            classification = classify_score(
                score
            )

            print(
                f'[THREAT SCORE] '
                f'{score} '
                f'({classification})'
            )

            # ====================================
            # DETECTION
            # ====================================

            if score >= 60:

                self.detect_threat(
                    file_path,
                    classification,
                    (
                        f'Ameaça detectada '
                        f'({classification})'
                    )
                )

        except Exception as e:

            print(
                f"[red]Erro:[/red] {e}"
            )

    # ========================================
    # THREAT
    # ========================================

    def detect_threat(
        self,
        file_path,
        event_type,
        message
    ):

        print(
            f"[red][THREAT][/red] "
            f"{file_path}"
        )

        quarantine_file(
            file_path
        )

        log_event(
            event_type,
            file_path
        )

        try:

            show_notification(
                'ALVSafe',
                message
            )

        except:
            pass

        with self.lock:

            self.infected.append(
                file_path
            )

    # ========================================
    # DIRECTORY
    # ========================================

    def scan_directory(
        self,
        directory
    ):

        directory = Path(directory)

        if not directory.exists():

            print(
                '[red]Diretório inválido[/red]'
            )

            return

        files = []

        for file in directory.rglob('*'):

            if any(

                excluded.lower() in
                str(file).lower()

                for excluded in EXCLUDED_DIRS
            ):
                continue

            files.append(file)

        print()

        print(
            f'[green]Arquivos:[/green] '
            f'{len(files)}'
        )

        print(
            '[green]Multithread ativo[/green]'
        )

        with ThreadPoolExecutor(
            max_workers=12
        ) as executor:

            executor.map(
                self.scan_file,
                files
            )

        print()

        print(
            f'[green]Escaneados:[/green] '
            f'{self.scanned}'
        )

        print(
            f'[red]Ameaças:[/red] '
            f'{len(self.infected)}'
        )