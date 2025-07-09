"""
Happy-path smoke-test for PDF parser.

Ensures that a benign one-page PDF does not blow up and
returns sensible, empty IOC fields.
"""

from pathlib import Path
from ioc_inspector_core.pdf_parser import parse_pdf


def test_blank_pdf_has_no_iocs():
    sample = Path("examples/test.pdf")          # your benign sample
    findings = parse_pdf(sample)

    assert findings["type"] == "pdf"
    assert findings["urls"] == []
    assert findings["ips"] == []
    # embedded files & javascript should be zero on the blank sample
    assert findings["embedded_files"] == 0
    assert findings["js_count"] == 0
