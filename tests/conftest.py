# tests/conftest.py
from pathlib import Path
import pytest, requests

ROOT = Path(__file__).resolve().parents[1]        # project root

# ---------- sample-file helpers ----------
@pytest.fixture(scope="session")
def sample_pdf():
    return ROOT / "examples" / "test.pdf"

@pytest.fixture(scope="session")
def sample_docm():
    return ROOT / "examples" / "macro_test.docm"

# ---------- stop every test from hitting the internet ----------
@pytest.fixture(autouse=True)
def stub_requests(monkeypatch):
    class _Fake:
        status_code = 200
        def json(self): return {"data": {}}
    monkeypatch.setattr(requests, "get",  lambda *a, **k: _Fake())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Fake())
