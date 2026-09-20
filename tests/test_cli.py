import hashlib
import json

from alvsafe import paths
from alvsafe.cli import main


def test_scan_limpo_retorna_0(tmp_path, capsys):
    (tmp_path / "a.sh").write_text("echo oi")
    assert main(["scan", str(tmp_path)]) == 0
    assert "Nenhuma ameaça" in capsys.readouterr().out


def test_scan_com_ameaca_retorna_1_e_json(tmp_path, capsys):
    alvo = tmp_path / "mal.sh"
    alvo.write_text("echo mal")
    paths.user_signatures_file().write_text(hashlib.sha256(alvo.read_bytes()).hexdigest() + "\n")

    assert main(["scan", "--json", "--no-quarantine", str(tmp_path)]) == 1
    saida = json.loads(capsys.readouterr().out)
    assert saida["threats"][0]["path"].endswith("mal.sh")
    assert alvo.exists()


def test_scan_caminho_inexistente_retorna_2(tmp_path):
    assert main(["scan", str(tmp_path / "nada")]) == 2


def test_fluxo_quarentena(tmp_path, capsys):
    alvo = tmp_path / "mal.sh"
    alvo.write_text("echo mal")
    paths.user_signatures_file().write_text(hashlib.sha256(alvo.read_bytes()).hexdigest() + "\n")

    assert main(["scan", str(tmp_path)]) == 1
    assert not alvo.exists()

    from alvsafe.core.quarantine import Quarantine
    entry_id = Quarantine().list()[0].id

    capsys.readouterr()
    assert main(["quarantine", "list"]) == 0
    assert entry_id in capsys.readouterr().out

    assert main(["quarantine", "restore", entry_id]) == 0
    assert alvo.read_text() == "echo mal"
    assert main(["quarantine", "delete", "inexistente"]) == 2


def test_logs(capsys):
    from alvsafe.core.eventlog import log_event
    log_event("TESTE", "algo")
    assert main(["logs", "-n", "5"]) == 0
    assert "algo" in capsys.readouterr().out


def test_config_init_show_path(capsys):
    assert main(["config", "init"]) == 0
    assert main(["config", "init"]) == 2  # já existe
    capsys.readouterr()
    assert main(["config", "show"]) == 0
    assert json.loads(capsys.readouterr().out)["max_file_size_mb"] == 50


def test_config_invalida_retorna_2(tmp_path):
    ruim = tmp_path / "ruim.json"
    ruim.write_text("{quebrado")
    assert main(["--config", str(ruim), "scan", str(tmp_path)]) == 2


def test_doctor_roda(capsys):
    code = main(["doctor"])
    out = capsys.readouterr().out
    assert "Backend de arquivos" in out and "Eventos em tempo real" in out
    assert code in (0, 1)
