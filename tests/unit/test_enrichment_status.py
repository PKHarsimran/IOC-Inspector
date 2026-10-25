from unittest.mock import MagicMock

import pytest
import requests

import ioc_inspector_core as core
from ioc_inspector_core import abuseipdb_check as abuse
from ioc_inspector_core import url_reputation as vt
from ioc_inspector_core.reputation_status import summarize


def test_offline_bypasses_lookup_functions_even_with_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "configured")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "configured")
    monkeypatch.setattr(core, "parse_pdf", lambda path: {"type": "pdf", "urls": ["https://example.com"], "ips": ["198.51.100.4"]})
    url_lookup = MagicMock(side_effect=AssertionError("offline must not call lookup"))
    ip_lookup = MagicMock(side_effect=AssertionError("offline must not call lookup"))
    monkeypatch.setattr(core, "lookup_urls", url_lookup)
    monkeypatch.setattr(core, "lookup_ips", ip_lookup)
    result = core.analyze(tmp_path / "sample.pdf", offline=True)
    assert result["url_rep"] == result["ip_rep"] == {}
    for info in result["enrichment"].values():
        assert info["status"] == "skipped"
        assert info["reason"] == "offline"
        assert info["skipped"] == 1
    url_lookup.assert_not_called()
    ip_lookup.assert_not_called()


def test_no_keys_and_no_indicators_have_distinct_reasons(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "parse_pdf", lambda path: {"type": "pdf", "urls": ["https://example.com"], "ips": []})
    result = core.analyze(tmp_path / "sample.pdf")
    assert result["enrichment"]["virustotal"]["reason"] == "no_api_key"
    assert result["enrichment"]["abuseipdb"]["reason"] == "no_indicators"


@pytest.mark.parametrize("status_code,state", [(404, "not_found"), (429, "failed"), (403, "failed")])
def test_vt_http_status_is_reported(monkeypatch, status_code, state):
    monkeypatch.setenv("VT_API_KEY", "key")
    response = MagicMock(status_code=status_code)
    monkeypatch.setattr(vt.requests, "get", lambda *args, **kwargs: response)
    statuses = {}
    assert vt.lookup_urls(["https://example.com"], statuses=statuses) == {}
    assert statuses["https://example.com"] == {"status": state, "reason": f"http_{status_code}"}


@pytest.mark.parametrize("module,lookup,indicator,key", [
    (vt, vt.lookup_urls, "https://example.com", "VT_API_KEY"),
    (abuse, abuse.lookup_ips, "198.51.100.4", "ABUSEIPDB_API_KEY"),
])
@pytest.mark.parametrize("failure,reason", [(requests.Timeout("timeout"), "request_error"), (ValueError("bad JSON"), "invalid_response")])
def test_network_and_malformed_responses_are_visible(monkeypatch, module, lookup, indicator, key, failure, reason):
    monkeypatch.setenv(key, "key")
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(module.requests, "get", fail)
    statuses = {}
    assert lookup([indicator], statuses=statuses) == {}
    assert statuses[indicator] == {"status": "failed", "reason": reason}


def test_abuse_http_failures_preserve_status(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    monkeypatch.setattr(abuse.requests, "get", lambda *args, **kwargs: MagicMock(status_code=429))
    statuses = {}
    assert abuse.lookup_ips(["198.51.100.4"], statuses=statuses) == {}
    assert statuses["198.51.100.4"] == {"status": "failed", "reason": "http_429"}


@pytest.mark.parametrize("payload", [{}, {"abuseConfidenceScore": 101}])
def test_abuse_invalid_data_does_not_become_clean_result(monkeypatch, payload):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    response = MagicMock(status_code=200)
    response.json.return_value = {"data": payload}
    monkeypatch.setattr(abuse.requests, "get", lambda *args, **kwargs: response)
    statuses = {}
    assert abuse.lookup_ips(["198.51.100.4"], statuses=statuses) == {}
    assert statuses["198.51.100.4"]["reason"] == "invalid_response"


def test_mixed_lookup_outcomes_are_partial():
    info = summarize({"one": {"status": "success", "reason": ""}, "two": {"status": "failed", "reason": "http_429"}})
    assert info["status"] == "partial"
    assert info["succeeded"] == info["failed"] == 1


def test_successful_lookups_flow_into_scored_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("VT_API_KEY", "key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    monkeypatch.setattr(core, "parse_pdf", lambda path: {"type": "pdf", "urls": ["https://example.com"], "ips": ["198.51.100.4"]})
    def respond(url, **kwargs):
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": (
            {"attributes": {"last_analysis_stats": {"malicious": 7}}}
            if "virustotal" in url else {"abuseConfidenceScore": 80, "totalReports": 4}
        )}
        return response
    monkeypatch.setattr(requests, "get", respond)
    result = core.analyze(tmp_path / "sample.pdf")
    assert result["score"] == 55
    for info in result["enrichment"].values():
        assert info["status"] == "success"
        assert info["succeeded"] == info["total"] == 1
