"""Ponte entre o núcleo e a interface gráfica.

O Tkinter não é thread-safe: só a thread principal pode tocar nos widgets.
O scanner e o monitor, por outro lado, rodam em threads. A solução é esta
classe: ela assina o barramento de eventos e despeja tudo numa fila. A
janela lê a fila com `after()`, já na thread principal.

Nada aqui importa Tkinter, o que também torna a lógica testável sem tela.
"""

import queue
import threading
import time

from alvsafe import system
from alvsafe.config import load_settings
from alvsafe.core.eventlog import recent
from alvsafe.core.quarantine import Quarantine
from alvsafe.core.scanner import Scanner
from alvsafe.events import CRITICAL, WARNING, EventBus

QUEUE_LIMIT = 2000


class Controller:

    def __init__(self, settings=None, bus=None, notifications=True):
        self.settings = settings or load_settings()
        self.bus = bus or EventBus()
        self.notifications = notifications
        self.queue = queue.Queue(maxsize=QUEUE_LIMIT)
        # Resultados de trabalho em thread (scan, diagnóstico). Chamar
        # widget.after() de fora da thread principal não é seguro no
        # Tkinter, então a janela busca isto no mesmo laço dos eventos.
        self.results = queue.Queue()
        self.dropped = 0

        self.scanner = Scanner(self.settings, bus=self.bus)
        self.quarantine = Quarantine()
        self.watcher = None

        self._scan_thread = None
        self._lock = threading.Lock()
        self.scanned = 0
        self.threats = 0
        self.total = 0            # arquivos a analisar no scan atual (0 = contando)
        self.current = ""         # último arquivo analisado
        self.scan_started = None

        self.bus.subscribe(self._on_event)

    # ---------- eventos ----------

    def _on_event(self, event):
        if event.kind == "scan.file":
            with self._lock:
                self.scanned += 1
                self.current = event.path or ""
        elif event.kind == "threat":
            with self._lock:
                self.threats += 1

        try:
            self.queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1  # interface lenta: perde evento, não trava o scan

        if self.notifications and (event.kind == "threat" or
                                   (event.kind == "alert" and event.level in (WARNING, CRITICAL))):
            threading.Thread(target=system.notify, args=("AlvSafe", event.message), daemon=True).start()

    def drain(self, limit=200):
        """Eventos acumulados desde a última chamada. Só a thread da interface chama."""
        events = []
        for _ in range(limit):
            try:
                events.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return events

    # ---------- scan ----------

    @property
    def scanning(self):
        return self._scan_thread is not None and self._scan_thread.is_alive()

    def drain_results(self):
        """[(tipo, valor)] concluídos desde a última chamada: ("scan", resumo) e ("doctor", checagens)."""
        results = []
        while True:
            try:
                results.append(self.results.get_nowait())
            except queue.Empty:
                return results

    def start_scan(self, path):
        """Roda o scan numa thread. Retorna False se já houver um em andamento."""
        if self.scanning:
            return False

        def run():
            try:
                # Contagem prévia: uma passada sem stat, só para a barra
                # de progresso saber o tamanho do trabalho.
                extensions = self.settings.extensions
                total = sum(1 for p in self.scanner.iter_files(path)
                            if p.suffix.lower() in extensions)
                with self._lock:
                    self.total = total
                summary = self.scanner.scan_path(path)
            except (OSError, ValueError) as e:
                self.bus.emit("scan.error", str(e), level=WARNING, path=path)
                summary = None
            self.results.put(("scan", summary))

        with self._lock:
            self.scanned = 0
            self.threats = 0
            self.total = 0
            self.current = ""
            self.scan_started = time.monotonic()
        self._scan_thread = threading.Thread(target=run, name="alvsafe-gui-scan", daemon=True)
        self._scan_thread.start()
        return True

    def cancel_scan(self):
        self.scanner.cancel()

    # ---------- proteção em tempo real ----------

    @property
    def protection_active(self):
        return self.watcher is not None

    def start_protection(self):
        if self.watcher:
            return False
        from alvsafe.core.realtime import Watcher

        self.watcher = Watcher(self.settings, bus=self.bus, scanner=self.scanner)
        self.watcher.start()
        return True

    def stop_protection(self):
        if not self.watcher:
            return False
        self.watcher.stop()
        self.watcher = None
        return True

    # ---------- consultas ----------

    def quarantine_entries(self):
        return self.quarantine.list()

    def restore(self, entry_id, overwrite=False):
        return self.quarantine.restore(entry_id, overwrite=overwrite)

    def delete(self, entry_id):
        self.quarantine.delete(entry_id)

    @property
    def progress(self):
        """(fração concluída, texto) para a barra. Fração None enquanto conta."""
        with self._lock:
            scanned, total = self.scanned, self.total
        if not self.scanning and not scanned:
            return 0.0, ""
        if not total:
            return None, f"{scanned} analisados"
        return min(scanned / total, 1.0), f"{scanned} de {total}"

    @property
    def elapsed(self):
        return 0.0 if self.scan_started is None else time.monotonic() - self.scan_started

    def service_status(self):
        """(nome do gerenciador, ativo, detalhe) ou None onde não há suporte."""
        from alvsafe.service import ServiceError, get_manager

        manager = get_manager()
        if manager is None:
            return None
        try:
            ativo, detalhe = manager.status()
        except (ServiceError, OSError) as e:
            return manager.name, False, str(e)
        return manager.name, ativo, detalhe

    def watched_folders(self):
        if self.watcher:
            return list(self.watcher.watching)
        return []

    def recent_logs(self, limit=50):
        return recent(limit)

    def run_doctor(self):
        """Roda o diagnóstico numa thread; o resultado sai em drain_results()."""
        def run():
            from alvsafe.doctor import run_checks
            self.results.put(("doctor", run_checks(self.settings)))

        threading.Thread(target=run, name="alvsafe-gui-doctor", daemon=True).start()

    # ---------- encerramento ----------

    def shutdown(self):
        self.cancel_scan()
        self.stop_protection()
        if self._scan_thread:
            self._scan_thread.join(timeout=3)
