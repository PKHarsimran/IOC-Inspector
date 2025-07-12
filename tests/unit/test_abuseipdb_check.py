from ioc_inspector_core.abuseipdb_check import lookup_ips

def test_lookup_ips_no_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert lookup_ips(["1.2.3.4"]) == {}

def test_lookup_ips_empty_list(monkeypatch):
    # Even if key is set, empty input returns empty dict
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "DUMMY")
    assert lookup_ips([]) == {}
