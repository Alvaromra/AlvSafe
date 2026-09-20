import hashlib
import os

import pytest

from alvsafe.config import Settings
from alvsafe.core.quarantine import Quarantine
from alvsafe.core.scanner import Scanner, shannon_entropy


def make(tmp_path, rel, content=b"echo ok\n"):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def test_entropia():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaa") == 0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)


def test_hash_conhecido_vai_para_quarentena(tmp_path, bus):
    alvo = make(tmp_path, "scan/mal.sh", b"#!/bin/sh\necho mal\n")
    sha = hashlib.sha256(alvo.read_bytes()).hexdigest()
    scanner = Scanner(Settings(), bus=bus, signatures={sha})

    summary = scanner.scan_path(tmp_path / "scan")

    assert summary.scanned == 1 and len(summary.threats) == 1
    threat = summary.threats[0]
    assert "hash conhecido" in threat.reasons
    assert threat.quarantine_id and not alvo.exists()
    kinds = [e.kind for e in bus.events]
    assert kinds[0] == "scan.start" and kinds[-1] == "scan.done"
    assert "threat" in kinds and "quarantine" in kinds


def test_no_quarantine_so_relata(tmp_path, bus):
    alvo = make(tmp_path, "mal.sh")
    sha = hashlib.sha256(alvo.read_bytes()).hexdigest()
    summary = Scanner(Settings(), bus=bus, signatures={sha}, auto_quarantine=False).scan_path(tmp_path)
    assert len(summary.threats) == 1 and alvo.exists()
    assert "quarantine" not in [e.kind for e in bus.events]


def test_filtros_extensao_tamanho_e_pastas_excluidas(tmp_path, bus):
    make(tmp_path, "a.sh")
    make(tmp_path, "foto.jpg")
    make(tmp_path, "grande.sh", b"x" * (2 * 1024 * 1024))
    make(tmp_path, "node_modules/pacote/b.sh")
    make(tmp_path, ".git/hooks/c.sh")
    # a pasta abaixo era excluída antes só por conter "cache" no nome
    make(tmp_path, "cache_de_projeto/d.sh")

    settings = Settings(max_file_size_mb=1)
    summary = Scanner(settings, bus=bus, signatures=set()).scan_path(tmp_path)

    analisados = sorted(os.path.basename(e.path) for e in bus.events if e.kind == "scan.file")
    assert analisados == ["a.sh", "d.sh"]
    assert summary.scanned == 2 and summary.skipped == 2  # foto.jpg (extensão) e grande.sh (tamanho)


def test_heuristica_e_yara_aparecem_nos_motivos(tmp_path, bus):
    alvo = make(tmp_path, "x.ps1", b"powershell -enc AAAA; Invoke-Expression $x")
    result = Scanner(Settings(), bus=bus, signatures=set(), auto_quarantine=False).scan_file(alvo)
    assert any(r.startswith("heurística") for r in result.reasons)
    pytest.importorskip("yara")
    assert any("Suspicious_Powershell" in r for r in result.reasons)


def test_eicar_detectado_pela_heuristica(tmp_path, bus, eicar):
    alvo = make(tmp_path, "eicar.sh", eicar)
    result = Scanner(Settings(), bus=bus, signatures=set(), auto_quarantine=False).scan_file(alvo)
    assert any("EICAR" in r for r in result.reasons)


def test_arquivo_inexistente(tmp_path, bus):
    with pytest.raises(FileNotFoundError):
        Scanner(Settings(), bus=bus, signatures=set()).scan_path(tmp_path / "nada")


def test_muitos_arquivos_memoria_limitada(tmp_path, bus):
    for i in range(300):
        make(tmp_path, f"d{i % 7}/f{i}.sh")
    summary = Scanner(Settings(), bus=bus, signatures=set()).scan_path(tmp_path, workers=2)
    assert summary.scanned == 300


# ---------- quarentena ----------

def test_quarentena_neutraliza_e_restaura(tmp_path):
    original = make(tmp_path, "bin/prog.sh", b"#!/bin/sh\necho perigo\n")
    os.chmod(original, 0o755)
    q = Quarantine()

    entry = q.add(original, reason="teste")
    blob = q.directory / f"{entry.id}.bin"

    assert not original.exists()
    assert blob.read_bytes() != b"#!/bin/sh\necho perigo\n"   # conteúdo embaralhado
    assert oct(blob.stat().st_mode & 0o777) == "0o600"          # sem permissão de execução
    assert [e.id for e in q.list()] == [entry.id]

    restored = q.restore(entry.id)
    assert restored == original.resolve()
    assert original.read_bytes() == b"#!/bin/sh\necho perigo\n"
    assert oct(original.stat().st_mode & 0o777) == "0o755"     # permissão original de volta
    assert q.list() == []


def test_restaurar_nao_sobrescreve_sem_force(tmp_path):
    original = make(tmp_path, "a.sh", b"1")
    q = Quarantine()
    entry = q.add(original)
    original.write_bytes(b"outro")
    with pytest.raises(FileExistsError):
        q.restore(entry.id)
    alt = q.restore(entry.id, destination=tmp_path / "restaurado.sh")
    assert alt.read_bytes() == b"1"


def test_quarentena_corrompida_nao_restaura(tmp_path):
    q = Quarantine()
    entry = q.add(make(tmp_path, "a.sh", b"abc"))
    (q.directory / f"{entry.id}.bin").write_bytes(b"lixo")
    with pytest.raises(ValueError):
        q.restore(entry.id)
    assert not (tmp_path / "a.sh").exists()


def test_apagar_e_id_inexistente(tmp_path):
    q = Quarantine()
    entry = q.add(make(tmp_path, "a.sh"))
    q.delete(entry.id)
    assert q.list() == []
    with pytest.raises(KeyError):
        q.delete(entry.id)
