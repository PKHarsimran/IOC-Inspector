import os
from unittest.mock import patch, MagicMock
import ioc_inspector_core.abuseipdb_check as abuseipdb_check

@patch("ioc_inspector_core.abuseipdb_check.requests.get")
def test_lookup_ips_success(mock_get, monkeypatch):
    # Force override the API key directly
    monkeypatch.setattr(abuseipdb_check, "os", os)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 80,
            "totalReports": 50,
            "usageType": "Spam"
        }
    }
    mock_get.return_value = mock_resp

    result = abuseipdb_check.lookup_ips(["8.8.8.8"])
    assert "8.8.8.8" in result
    assert result["8.8.8.8"]["abuse_confidence"] == 80
    assert result["8.8.8.8"]["malicious"] is True
