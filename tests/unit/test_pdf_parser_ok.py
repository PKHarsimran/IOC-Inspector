"""
Happy-path smoke-test for PDF parser.

Ensures that a benign one-page PDF does not blow up and
returns sensible, empty IOC fields.
"""

from ioc_inspector_core.pdf_parser import parse_pdf

def test_blank_pdf_has_no_iocs(sample_pdf):
    out = parse_pdf(sample_pdf)

    assert out["type"] == "pdf"
    assert out["urls"] == []
    assert out["ips"] == []
    assert out["embedded_files"] == 0
    assert out["js_count"] == 0

