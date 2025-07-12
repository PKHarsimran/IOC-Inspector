from unittest.mock import patch, MagicMock
from ioc_inspector_core.url_reputation import lookup_urls, _vt_url_id

@patch('ioc_inspector_core.url_reputation.requests.get')
def test_lookup_urls_success(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake_key")

    url = "http://evil.com"
    url_id = _vt_url_id(url)

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

    result = lookup_urls([url])
    assert url in result
    assert result[url]["malicious"] is True
    assert result[url]["vendors"] == 7

    mock_get.assert_called_with(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={'x-apikey': 'fake_key'},
        timeout=15
    )
