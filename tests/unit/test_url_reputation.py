from ioc_inspector_core.url_reputation import lookup_urls, _vt_url_id

def test_vt_url_id_is_deterministic():
    id1 = _vt_url_id("https://example.com")
    id2 = _vt_url_id("https://example.com")
    assert id1 == id2
    assert isinstance(id1, str)
    assert "=" not in id1  # no padding :contentReference[oaicite:1]{index=1}

def test_lookup_urls_no_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert lookup_urls(["http://bad.com"]) == {}
