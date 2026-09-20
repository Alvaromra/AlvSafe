"""Banco de hashes conhecidos: o do pacote somado ao do usuário.

Só SHA-256. A versão anterior guardava MD5 enquanto o scanner comparava
SHA-256, então nenhuma assinatura casava. Linhas que não são SHA-256
são ignoradas e contabilizadas, e o `alvsafe doctor` mostra quantas.
"""

import re
from dataclasses import dataclass, field

from alvsafe import paths

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MD5_OR_SHA1 = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$")


@dataclass
class SignatureSet:
    hashes: set = field(default_factory=set)
    legacy: int = 0    # MD5/SHA-1: formato antigo, não usado
    invalid: int = 0

    def __contains__(self, value):
        return value in self.hashes

    def __len__(self):
        return len(self.hashes)


def parse(text, into=None):
    result = SignatureSet() if into is None else into  # cuidado: um conjunto vazio é falsy
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        token = line.split()[0]
        if SHA256.match(token):
            result.hashes.add(token)
        elif MD5_OR_SHA1.match(token):
            result.legacy += 1
        else:
            result.invalid += 1
    return result


def load_signature_set():
    result = SignatureSet()
    for path in (paths.bundled_signatures_file(), paths.user_signatures_file()):
        if path.exists():
            parse(path.read_text(encoding="utf-8", errors="ignore"), into=result)
    return result


def load_signatures():
    return load_signature_set().hashes
