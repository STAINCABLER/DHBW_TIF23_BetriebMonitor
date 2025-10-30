from pathlib import Path
import sys

import pytest


MODULE_ROOT = Path(__file__).resolve().parents[1]
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

sys.modules.pop("server", None)
import server


@pytest.fixture(autouse=True)
def clean_store(monkeypatch):
    """Ensure each test works with a fresh in-memory store."""
    server._cancel_session_cleanup()
    memory_store = server.MemoryStore()
    monkeypatch.setattr(server, "store", memory_store, raising=False)
    monkeypatch.setattr(server, "_session_cleanup_timer", None, raising=False)
    yield
    server._cancel_session_cleanup()


@pytest.fixture()
def client():
    """Flask test client with testing configuration enabled."""
    server._cancel_session_cleanup()
    server.app.config.update({"TESTING": True})
    with server.app.test_client() as test_client:
        yield test_client
