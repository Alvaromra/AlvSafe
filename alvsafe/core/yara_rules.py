"""Regras YARA: as do pacote somadas às do usuário, compiladas uma vez.

O yara-python é opcional. Sem ele, o scanner segue sem essa camada
e o `alvsafe doctor` avisa.
"""

import threading

from alvsafe import paths

try:
    import yara
except ImportError:  # pragma: no cover - depende do ambiente
    yara = None

_rules = None
_error = None
_count = 0
_lock = threading.Lock()


def _rule_files():
    files = {}
    for directory, prefix in ((paths.bundled_rules_dir(), "pkg"), (paths.user_rules_dir(), "user")):
        if directory.exists():
            for f in sorted(directory.glob("*.yar")) + sorted(directory.glob("*.yara")):
                files[f"{prefix}_{f.stem}"] = str(f)
    return files


def load(force=False):
    """Compila as regras (uma vez). Retorna o objeto de regras ou None."""
    global _rules, _error, _count
    with _lock:
        if _rules is not None and not force:
            return _rules
        if yara is None:
            _error = "yara-python não instalado"
            return None
        files = _rule_files()
        if not files:
            _error = "nenhuma regra encontrada"
            return None
        try:
            _rules = yara.compile(filepaths=files)
            _count = len(files)
            _error = None
        except yara.Error as e:
            _rules = None
            _error = f"erro ao compilar regras: {e}"
        return _rules


def match(content):
    """Nomes das regras que casam com o conteúdo (bytes)."""
    rules = load()
    if rules is None:
        return []
    try:
        return [m.rule for m in rules.match(data=content, timeout=30)]
    except yara.Error:
        return []


def status():
    """(disponível, arquivos de regra, erro) para o doctor."""
    load()
    return _rules is not None, _count, _error
