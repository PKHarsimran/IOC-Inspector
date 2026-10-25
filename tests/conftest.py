# tests/conftest.py
from pathlib import Path
import pytest
import requests

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
    from ioc_inspector_core import abuseipdb_check, url_reputation

    # Keep tests independent of credentials, cached responses and real delays.
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    for module in (abuseipdb_check, url_reputation):
        monkeypatch.setattr(module, "_RATE_PAUSE", 0)
    url_reputation._fetch_vt_report.cache_clear()
    abuseipdb_check._fetch_abuse_data.cache_clear()
    class _Fake:
        status_code = 200
        def json(self): return {"data": {}}
    monkeypatch.setattr(requests, "get",  lambda *a, **k: _Fake())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Fake())
