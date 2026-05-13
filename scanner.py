from pathlib import Path
from rich import print

from utils import calculate_sha256
from signatures import load_signatures
from quarantine import quarantine_file


signatures = load_signatures()


EXTENSIONS = [
    '.exe',
    '.dll',
    '.bat',
    '.cmd',
    '.ps1',
    '.sh',
    '.app',
    '.pkg',
    '.dmg'
]


class AntivirusScanner:

    def __init__(self):
        self.infected = []
        self.scanned = 0

    def scan_file(self, file_path):

        try:
            path = Path(file_path)

            if not path.is_file():
                return

            self.scanned += 1

            print(f"[cyan]Escaneando:[/cyan] {file_path}")

            if path.suffix.lower() not in EXTENSIONS:
                return

            file_hash = calculate_sha256(file_path)

            if not file_hash:
                return

            if file_hash in signatures:

                print(f"[red][ALERTA][/red] Malware detectado:")
                print(f"[yellow]{file_path}[/yellow]")

                quarantine_file(file_path)

                self.infected.append(file_path)

        except Exception as e:
            print(f"[red]Erro:[/red] {e}")

    def scan_directory(self, directory):

        directory = Path(directory)

        if not directory.exists():
            print("[red]Diretório não encontrado[/red]")
            return

        for file in directory.rglob('*'):
            self.scan_file(file)

        print()
        print(f"[green]Arquivos escaneados:[/green] {self.scanned}")
        print(f"[red]Ameaças encontradas:[/red] {len(self.infected)}")