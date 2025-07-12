from unittest.mock import patch, MagicMock
from ioc_inspector_core.url_reputation import lookup_urls

@patch('ioc_inspector_core.url_reputation.requests.get')
def test_lookup_urls_success(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 7}
            }
        }
    }
    mock_get.return_value = mock_resp

    result = lookup_urls(["http://evil.com"])
    assert result["http://evil.com"]["malicious"] is True
    assert result["http://evil.com"]["vendors"] == 7
