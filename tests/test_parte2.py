from types import SimpleNamespace

import psutil
import pytest

from engine import alerts, firewall, process_monitor, ransomware_guard, virustotal, web_protection


# ---------- alerts ----------

def test_alerta_repetido_e_suprimido():
    assert alerts.alert("TESTE", "x") is True
    assert alerts.alert("TESTE", "x") is False
    assert alerts.alert("TESTE", "y") is True


def test_alerta_com_key_ignora_detalhe():
    assert alerts.alert("TESTE", "10 eventos", key="burst") is True
    assert alerts.alert("TESTE", "11 eventos", key="burst") is False


# ---------- processos ----------

def _proc(pid, name):
    return SimpleNamespace(info={"pid": pid, "name": name})


def test_processo_suspeito_detectado_sem_kill(monkeypatch):
    procs = [
        _proc(1, "mimikatz.exe"),
        _proc(2, "Malwarebytes.exe"),
        _proc(3, "VeraCrypt.exe"),
        _proc(4, "nc"),
        _proc(5, None),
    ]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: procs)

    found = process_monitor.monitor_processes()

    assert found == [(1, "mimikatz.exe"), (4, "nc")]


# ---------- conexões ----------

def _conn(lport=None, raddr=None, pid=99):
    laddr = SimpleNamespace(ip="127.0.0.1", port=lport) if lport else ()
    return SimpleNamespace(laddr=laddr, raddr=raddr or (), pid=pid)


def test_firewall_porta_suspeita(monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda: [_conn(4444), _conn(8080)])
    assert firewall.monitor_connections() == [4444]


def test_firewall_sem_permissao_nao_quebra(monkeypatch):
    def negar():
        raise psutil.AccessDenied()
    monkeypatch.setattr(psutil, "net_connections", negar)
    assert firewall.monitor_connections() == []


@pytest.mark.parametrize("ip,esperado", [
    ("192.168.56.10", True),
    ("185.1.2.3", False),   # antes era falso positivo
    ("10.185.0.1", False),  # antes era falso positivo
    ("::1", False),
    ("lixo", False),
])
def test_ip_suspeito(ip, esperado):
    assert web_protection._is_suspicious_ip(ip) is esperado


def test_web_porta_e_ip(monkeypatch):
    conns = [
        _conn(raddr=SimpleNamespace(ip="8.8.8.8", port=4444)),
        _conn(raddr=SimpleNamespace(ip="192.168.56.2", port=443)),
        _conn(raddr=SimpleNamespace(ip="1.1.1.1", port=443)),
        _conn(),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda: conns)
    assert web_protection.monitor_web() == [("8.8.8.8", 4444), ("192.168.56.2", 443)]


# ---------- ransomware ----------

@pytest.fixture
def janela_limpa():
    ransomware_guard._events.clear()
    yield
    ransomware_guard._events.clear()


def test_rajada_alerta_uma_vez(janela_limpa):
    n = ransomware_guard.THRESHOLD + 5
    resultados = [ransomware_guard.process_event(f"/x/{i}.txt", now=i * 0.1) for i in range(n)]
    assert resultados.count(True) == 1


def test_janela_expira(janela_limpa):
    for i in range(ransomware_guard.THRESHOLD):
        ransomware_guard.process_event(f"/x/{i}.txt", now=0)
    # depois da janela, os eventos antigos saem
    assert ransomware_guard.process_event("/x/novo.txt", now=100) is False
    assert len(ransomware_guard._events) == 1


def test_extensao_suspeita(janela_limpa):
    assert ransomware_guard.process_event("/x/foto.JPG.locked", now=0) is True


# ---------- virustotal ----------

def test_vt_sem_chave(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    f = tmp_path / "a.txt"
    f.write_text("oi")
    assert virustotal.check_virustotal(f) is None


def test_vt_respostas(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "fake")
    f = tmp_path / "a.txt"
    f.write_text("oi")

    stats = {"malicious": 3, "suspicious": 0, "harmless": 0, "undetected": 60}
    respostas = {
        404: SimpleNamespace(status_code=404),
        200: SimpleNamespace(
            status_code=200,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": stats}}},
        ),
    }
    chamadas = []

    def fake_get(url, headers, timeout):
        chamadas.append((url, headers, timeout))
        return respostas[status]

    monkeypatch.setattr(virustotal.requests, "get", fake_get)

    status = 404
    assert virustotal.check_virustotal(f) is None

    status = 200
    resultado = virustotal.check_virustotal(f)
    assert resultado["malicious"] == 3
    assert resultado["sha256"] == virustotal.sha256_of(f)

    # só o hash sai da máquina, e sempre com timeout
    assert all(url.endswith(resultado["sha256"]) and t for url, _, t in chamadas)
    assert chamadas[0][1] == {"x-apikey": "fake"}
