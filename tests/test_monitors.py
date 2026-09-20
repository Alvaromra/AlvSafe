from types import SimpleNamespace

import psutil
import pytest

from alvsafe.core import alerts, network, processes, virustotal
from alvsafe.core.eventlog import recent


def test_alerta_repetido_e_suprimido():
    assert alerts.alert("TESTE", "x") is True
    assert alerts.alert("TESTE", "x") is False
    assert alerts.alert("TESTE", "y") is True


def test_alerta_com_key_ignora_detalhe():
    assert alerts.alert("TESTE", "10 eventos", key="burst") is True
    assert alerts.alert("TESTE", "11 eventos", key="burst") is False


def test_alerta_emite_evento_e_grava_log(bus):
    alerts.alert("TESTE", "detalhe", bus=bus)
    assert [(e.kind, e.message, e.data["category"]) for e in bus.events] == [("alert", "detalhe", "TESTE")]
    assert recent(1)[0][1:3] == ("TESTE", "detalhe")


def _proc(pid, name):
    return SimpleNamespace(info={"pid": pid, "name": name})


def test_processo_suspeito_detectado_sem_kill(monkeypatch):
    procs = [_proc(1, "mimikatz.exe"), _proc(2, "Malwarebytes.exe"),
             _proc(3, "VeraCrypt.exe"), _proc(4, "nc"), _proc(5, None)]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: procs)
    assert processes.monitor_processes() == [(1, "mimikatz.exe"), (4, "nc")]


def _conn(lport=None, raddr=None, pid=99):
    laddr = SimpleNamespace(ip="127.0.0.1", port=lport) if lport else ()
    return SimpleNamespace(laddr=laddr, raddr=raddr or (), pid=pid)


def test_porta_local_suspeita(monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda: [_conn(4444), _conn(8080)])
    assert network.monitor_connections() == [4444]


def test_sem_permissao_nao_quebra(monkeypatch):
    def negar():
        raise psutil.AccessDenied()
    monkeypatch.setattr(psutil, "net_connections", negar)
    assert network.monitor_connections() == []
    assert network.monitor_web() == []


@pytest.mark.parametrize("ip,esperado", [
    ("192.168.56.10", True), ("185.1.2.3", False), ("10.185.0.1", False), ("::1", False), ("lixo", False),
])
def test_ip_suspeito(ip, esperado):
    assert network._is_suspicious_ip(ip) is esperado


def test_web_porta_e_ip(monkeypatch):
    conns = [
        _conn(raddr=SimpleNamespace(ip="8.8.8.8", port=4444)),
        _conn(raddr=SimpleNamespace(ip="192.168.56.2", port=443)),
        _conn(raddr=SimpleNamespace(ip="1.1.1.1", port=443)),
        _conn(),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda: conns)
    assert network.monitor_web() == [("8.8.8.8", 4444), ("192.168.56.2", 443)]


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
        200: SimpleNamespace(status_code=200,
                             json=lambda: {"data": {"attributes": {"last_analysis_stats": stats}}}),
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
    assert all(url.endswith(resultado["sha256"]) and t for url, _, t in chamadas)
