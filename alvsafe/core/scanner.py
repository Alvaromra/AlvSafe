"""Scanner de arquivos.

Cada arquivo é lido uma única vez; hash, entropia, heurística e YARA
trabalham sobre os mesmos bytes. Pastas excluídas são podadas durante
a varredura (não se entra nelas), em vez de filtradas depois.
"""

import hashlib
import math
import os
import tempfile
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from alvsafe.config import load_settings
from alvsafe.core import heuristic, yara_rules
from alvsafe.core.eventlog import log_event
from alvsafe.core.quarantine import Quarantine
from alvsafe.core.signatures import load_signature_set
from alvsafe.core.threat_score import calculate_threat_score, classify_score
from alvsafe.events import CRITICAL, DEBUG, INFO, WARNING
from alvsafe.events import bus as default_bus

HIGH_ENTROPY = 7.2
VT_MIN_SCORE = 30  # abaixo disso não vale gastar a cota da API
_TEMP_NAMES = {"tmp", "temp"}


ENTROPY_SAMPLE = 1024 * 1024   # 1 MB por amostra
ENTROPY_FULL_LIMIT = 4 * ENTROPY_SAMPLE


def shannon_entropy(data):
    """Entropia de Shannon em bits por byte (0 a 8).

    Em arquivos grandes, calcula sobre três amostras (início, meio e fim)
    em vez do arquivo inteiro: o resultado é praticamente o mesmo e evita
    varrer dezenas de MB por arquivo.
    """
    if not data:
        return 0.0
    if len(data) > ENTROPY_FULL_LIMIT:
        meio = len(data) // 2
        data = (data[:ENTROPY_SAMPLE]
                + data[meio:meio + ENTROPY_SAMPLE]
                + data[-ENTROPY_SAMPLE:])
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


@dataclass
class ScanResult:
    path: str
    sha256: str | None = None
    score: int = 0
    classification: str = "SAFE"
    reasons: list = field(default_factory=list)
    skipped: str | None = None      # motivo, se o arquivo não foi analisado
    error: str | None = None
    quarantine_id: str | None = None
    threshold: int = 60

    @property
    def is_threat(self):
        return self.skipped is None and self.error is None and self.score >= self.threshold


@dataclass
class ScanSummary:
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    threats: list = field(default_factory=list)
    duration: float = 0.0
    cancelled: bool = False


class Scanner:

    def __init__(self, settings=None, bus=None, signatures=None, quarantine=None, auto_quarantine=True):
        self.settings = settings or load_settings()
        self.bus = bus or default_bus
        self.signatures = load_signature_set() if signatures is None else set(signatures)
        self._vt_cache = {}
        self._quarantine = quarantine
        self.auto_quarantine = auto_quarantine
        self._cancel = threading.Event()
        self._temp_root = os.path.realpath(tempfile.gettempdir())

        # Totais acumulados (a GUI usa)
        self.scanned = 0
        self.infected = []
        self._lock = threading.Lock()

    @property
    def quarantine(self):
        if self._quarantine is None:
            self._quarantine = Quarantine()
        return self._quarantine

    def cancel(self):
        self._cancel.set()

    # ---------- arquivos ----------

    def skip_reason(self, path):
        if path.suffix.lower() not in self.settings.extensions:
            return "extensão"
        try:
            info = path.stat()
        except OSError:
            return "inacessível"
        if not path.is_file():
            return "não é arquivo"
        if info.st_size > self.settings.max_file_size_bytes:
            return "tamanho"
        return None

    def _in_temp(self, path):
        real = os.path.realpath(path)
        if real.startswith(self._temp_root + os.sep):
            return True
        return any(part.lower() in _TEMP_NAMES for part in Path(real).parent.parts)

    def scan_file(self, path):
        path = Path(path)
        result = ScanResult(path=str(path), threshold=self.settings.threat_threshold)

        result.skipped = self.skip_reason(path)
        if result.skipped:
            return result

        try:
            content = path.read_bytes()
        except OSError as e:
            result.error = str(e)
            self.bus.emit("scan.error", f"{path}: {e}", level=WARNING, path=path)
            return result

        indicators = {}
        result.sha256 = hashlib.sha256(content).hexdigest()

        if result.sha256 in self.signatures:
            indicators["signature_match"] = True
            result.reasons.append("hash conhecido")

        entropy = shannon_entropy(content)
        if entropy > HIGH_ENTROPY:
            indicators["high_entropy"] = True
            result.reasons.append(f"entropia {entropy:.2f}")

        if self._in_temp(path):
            indicators["temp_execution"] = True
            result.reasons.append("pasta temporária")

        if self.settings.heuristic_detection:
            found = heuristic.analyze(content)
            if found.eicar:
                indicators["eicar_test"] = True
                result.reasons.append("arquivo de teste EICAR")
            if found.strong:
                indicators["heuristic_strong"] = True
                indicators["heuristic_strong_extra"] = len(found.strong) - 1
                result.reasons.append("heurística: " + ", ".join(found.strong))
            if found.weak:
                indicators["heuristic_weak"] = len(found.weak)
                result.reasons.append("indícios fracos: " + ", ".join(found.weak))

        if self.settings.yara_detection:
            rules = yara_rules.match(content)
            if rules:
                indicators["yara_match"] = True
                result.reasons.append("YARA: " + ", ".join(rules))

        if self._virustotal_needed(indicators, result):
            detections = self._virustotal(path, result.sha256)
            if detections is not None and detections >= self.settings.virustotal_min_detections:
                indicators["vt_malicious"] = True
                result.reasons.append(f"VirusTotal: {detections} detecções")

        result.score = calculate_threat_score(indicators)
        result.classification = classify_score(result.score)

        with self._lock:
            self.scanned += 1

        self.bus.emit("scan.file", str(path), level=DEBUG, path=path,
                      score=result.score, classification=result.classification)

        if result.is_threat:
            self._handle_threat(path, result)

        return result

    def _virustotal_needed(self, indicators, result):
        """Consulta só o que já é suspeito: a API gratuita é limitada."""
        if not self.settings.virustotal:
            return False
        partial = calculate_threat_score(indicators)
        return VT_MIN_SCORE <= partial < 100

    def _virustotal(self, path, sha256):
        if sha256 in self._vt_cache:
            return self._vt_cache[sha256]
        from alvsafe.core.virustotal import check_virustotal

        try:
            report = check_virustotal(path)
        except OSError as e:
            self.bus.emit("scan.error", f"VirusTotal falhou para {path}: {e}", level=WARNING, path=path)
            return None
        detections = report["malicious"] if report else None
        self._vt_cache[sha256] = detections
        return detections

    def _handle_threat(self, path, result):
        with self._lock:
            self.infected.append(str(path))

        self.bus.emit(
            "threat", f"{result.classification} ({result.score}): {path}",
            level=CRITICAL, path=path, score=result.score,
            classification=result.classification, reasons=result.reasons,
        )
        log_event(result.classification, str(path))

        if self.auto_quarantine and self.settings.quarantine_enabled:
            try:
                entry = self.quarantine.add(path, reason="; ".join(result.reasons))
                result.quarantine_id = entry.id
                self.bus.emit("quarantine", f"{path} -> quarentena {entry.id}",
                              level=WARNING, path=path, id=entry.id)
                log_event("QUARENTENA", f"{path} ({entry.id})")
            except OSError as e:
                self.bus.emit("scan.error", f"falha ao pôr em quarentena {path}: {e}",
                              level=WARNING, path=path)

    # ---------- pastas ----------

    def iter_files(self, root):
        root = Path(root)
        if root.is_file():
            yield root
            return
        excluded = self.settings.excluded
        for dirpath, dirnames, filenames in os.walk(root, onerror=None):
            if self._cancel.is_set():
                return
            dirnames[:] = [d for d in dirnames if d.lower() not in excluded]
            for name in filenames:
                yield Path(dirpath) / name

    def scan_path(self, root, workers=None):
        self._cancel.clear()
        root = Path(root).expanduser()
        summary = ScanSummary()
        start = time.monotonic()

        if not root.exists():
            raise FileNotFoundError(root)

        workers = workers or self.settings.scan_workers or min(8, (os.cpu_count() or 2) + 2)
        self.bus.emit("scan.start", f"escaneando {root}", level=INFO, path=root, workers=workers)

        extensions = self.settings.extensions
        pending = deque()
        limit = workers * 4  # poucos arquivos "em voo": memória constante em árvores grandes

        def collect(result):
            if result.skipped:
                summary.skipped += 1
            elif result.error:
                summary.errors += 1
            else:
                summary.scanned += 1
                if result.is_threat:
                    summary.threats.append(result)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for path in self.iter_files(root):
                if self._cancel.is_set():
                    break
                # Filtro barato antes de ocupar uma thread
                if path.suffix.lower() not in extensions:
                    summary.skipped += 1
                    continue
                pending.append(pool.submit(self.scan_file, path))
                if len(pending) >= limit:
                    collect(pending.popleft().result())

            if self._cancel.is_set():
                summary.cancelled = True
                for future in pending:
                    future.cancel()
            for future in pending:
                if not future.cancelled():
                    collect(future.result())

        summary.duration = time.monotonic() - start
        self.bus.emit(
            "scan.done",
            f"{summary.scanned} analisados, {len(summary.threats)} ameaças, "
            f"{summary.skipped} ignorados em {summary.duration:.1f}s",
            level=INFO, path=root, scanned=summary.scanned,
            threats=len(summary.threats), skipped=summary.skipped, errors=summary.errors,
        )
        return summary
