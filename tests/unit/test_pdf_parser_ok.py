"""
Happy-path smoke-test for PDF parser.

Ensures that a benign one-page PDF does not blow up and
returns sensible, empty IOC fields.
"""
from ioc_inspector_core.pdf_parser import parse_pdf
import fitz

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


def test_pdf_extracts_plain_ips_and_full_urls(tmp_path):
    path = tmp_path / "indicators.pdf"
    with fitz.open() as doc:
        page = doc.new_page()
        page.insert_text((72, 72), "Contact 198.51.100.42 or https://example.com/a?x=1&y=2.")
        page.insert_text((72, 100), "Invalid address: 999.999.999.999")
        doc.save(path)
    findings = parse_pdf(path)
    assert findings["ips"] == ["198.51.100.42"]
    assert findings["urls"] == ["https://example.com/a?x=1&y=2"]


def test_pdf_detects_javascript_in_action_dictionary(tmp_path):
    path = tmp_path / "script.pdf"
    with fitz.open() as doc:
        doc.new_page()
        action = doc.get_new_xref()
        doc.update_object(action, "<< /S /JavaScript /JS (app.alert\\(1\\)) >>")
        doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{action} 0 R")
        doc.save(path)
    assert parse_pdf(path)["js_count"] == 1


