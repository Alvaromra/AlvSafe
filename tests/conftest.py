import os
import sys
import tempfile
from pathlib import Path

# O logger cria ~/ALVSafe/database ao ser importado.
# Aponta o HOME para uma pasta temporária antes de qualquer import do engine.
os.environ["HOME"] = tempfile.mkdtemp(prefix="alvsafe-test-")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from engine import alerts


@pytest.fixture(autouse=True)
def reset_alerts():
    alerts._last_seen.clear()
    yield
    alerts._last_seen.clear()
