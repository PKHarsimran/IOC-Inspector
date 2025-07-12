"""
Happy-path smoke-test for PDF parser.

Ensures that a benign one-page PDF does not blow up and
returns sensible, empty IOC fields.
"""
from ioc_inspector_core.pdf_parser import parse_pdf

def test_pdf_parser_returns_expected_structure(sample_pdf):
    findings = parse_pdf(sample_pdf)

    # must have these keys
    assert findings["type"] == "pdf"
    for key in ("urls", "ips", "embedded_files", "js_count"):
        assert key in findings

    # and they must be the right types
    assert isinstance(findings["urls"], list)
    assert isinstance(findings["ips"], list)
    assert isinstance(findings["embedded_files"], int)
    assert isinstance(findings["js_count"], int)


