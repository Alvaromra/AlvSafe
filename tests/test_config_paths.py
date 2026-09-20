import json

import pytest

from alvsafe import paths
from alvsafe.config import ConfigError, Settings, load_settings, save_settings


def test_alvsafe_home_redireciona_tudo(isolated_home):
    assert paths.data_dir() == isolated_home
    assert paths.config_file().parent == isolated_home
    assert paths.quarantine_dir().is_dir()
    assert oct(paths.quarantine_dir().stat().st_mode & 0o777) == "0o700"


def test_dados_do_pacote_existem():
    assert paths.bundled_signatures_file().exists()
    assert any(paths.bundled_rules_dir().glob("*.yar"))


def test_padroes_sem_arquivo():
    s = load_settings()
    assert s == Settings()
    assert [f.name for f in s.resolved_watch_folders()] == ["Downloads", "Desktop", "Documents"]


def test_roundtrip_e_mescla_parcial(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"max_file_size_mb": 10, "chave_desconhecida": 1}))
    s = load_settings(path)
    assert s.max_file_size_mb == 10
    assert s.quarantine_enabled is True  # padrão mantido
    s.watch_folders = ["~/x"]
    save_settings(s, path)
    assert load_settings(path).watch_folders == ["~/x"]


@pytest.mark.parametrize("conteudo", ['{"max_file_size_mb": "50"}', '{"quarantine_enabled": 1}',
                                      '{"max_file_size_mb": true}', "[1, 2]", "{quebrado"])
def test_config_invalida(tmp_path, conteudo):
    path = tmp_path / "s.json"
    path.write_text(conteudo)
    with pytest.raises(ConfigError):
        load_settings(path)
