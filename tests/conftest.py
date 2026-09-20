import pytest

from alvsafe.core import alerts


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Cada teste usa uma pasta de dados própria e descartável."""
    home = tmp_path / "alvsafe-home"
    monkeypatch.setenv("ALVSAFE_HOME", str(home))
    alerts.reset()
    yield home
    alerts.reset()


@pytest.fixture
def bus():
    from alvsafe.events import EventBus

    b = EventBus()
    b.events = []
    b.subscribe(b.events.append)
    return b


@pytest.fixture
def eicar():
    # Montado em tempo de execução: nenhum arquivo de teste de vírus no repositório
    return ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
