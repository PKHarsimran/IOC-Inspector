from ioc_inspector_core.indicators import extract_ips, extract_urls


def test_urls_preserve_balanced_parentheses_and_strip_prose():
    text = '(https://example.com/a_(b)). "https://example.com/a?x=1&y=2"'
    assert extract_urls(text) == {"https://example.com/a_(b)", "https://example.com/a?x=1&y=2"}


def test_ips_reject_invalid_addresses_and_partial_matches():
    assert extract_ips("999.1.2.3 1.2.3.4.5 x1.2.3.4 198.51.100.1.") == {"198.51.100.1"}
