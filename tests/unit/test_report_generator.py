import json
import pytest
import jsonschema

import ioc_inspector_core.report_generator as rg

def make_dummy(tmp_path):
    # Dummy path in tmp, no need for real file
    return tmp_path / "foo.pdf"

@pytest.fixture(autouse=True)
def stub_reports_dir(tmp_path, monkeypatch):
    # Redirect reports into the temp folder
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))  # if your code reads env
    # Or directly override the module constant:
    monkeypatch.setattr(rg, "REPORTS_DIR", tmp_path, raising=False)
    return tmp_path

def test_generate_markdown(tmp_path):
    src = make_dummy(tmp_path)
    result = {
        "verdict": "benign",
        "score": 0,
        "summary": "none",
        "urls": ["http://a"],
        "ips": ["1.1.1.1"],
    }
    rg.generate_report(src, result, fmt="markdown")
    out = tmp_path / "foo_report.md"
    text = out.read_text()
    assert "# IOC Inspector Report - foo.pdf" in text
    assert "**Verdict:** **BENIGN**" in text

def test_generate_json(tmp_path):
    src = make_dummy(tmp_path)
    result = {"verdict": "malicious", "score": 100}
    rg.generate_report(src, result, fmt="json")
    out = tmp_path / "foo_report.json"
    data = json.loads(out.read_text())
    assert data["verdict"] == "malicious"
    assert data["score"] == 100
    
def test_generate_markdown_with_urls_ips(tmp_path):
    src = tmp_path / "test.pdf"
    result = {
        "verdict": "suspicious",
        "score": 45,
        "summary": "URLs and IPs detected",
        "urls": ["http://example.com"],
        "ips": ["192.168.1.1"],
        "url_rep": {"http://example.com": {"vendors": 2, "malicious": False}},
        "ip_rep": {"192.168.1.1": {"abuse_confidence": 50, "total_reports": 3, "malicious": False}},
    }
    rg.generate_report(src, result, fmt="markdown")
    out = tmp_path / "test_report.md"
    text = out.read_text()
    assert "http://example.com" in text
    assert "192.168.1.1" in text


def test_generate_csv(tmp_path):
    src = make_dummy(tmp_path)
    result = {"verdict": "benign", "score": 1}
    rg.generate_report(src, result, fmt="csv")
    out = tmp_path / "foo_report.csv"
    text = out.read_text()
    assert "verdict" in text


def test_generate_jsonl(tmp_path):
    src = make_dummy(tmp_path)
    result = {"verdict": "benign", "score": 2}
    rg.generate_report(src, result, fmt="jsonl")
    out = tmp_path / "foo_report.jsonl"
    data = json.loads(out.read_text())
    assert data["score"] == 2


def test_generate_html(tmp_path):
    src = make_dummy(tmp_path)
    result = {"verdict": "benign", "score": 3}
    rg.generate_report(src, result, fmt="html")
    out = tmp_path / "foo_report.html"
    text = out.read_text()
    assert "<html>" in text
    
def test_schema_validation(tmp_path):
    src = make_dummy(tmp_path)
    # Missing required 'score'
    result = {"verdict": "benign"}
    with pytest.raises(jsonschema.ValidationError):
        rg.generate_report(src, result, fmt="json")


def test_unknown_format_does_not_write_mislabelled_markdown(tmp_path):
    with pytest.raises(ValueError, match="Unsupported report format"):
        rg.generate_report(make_dummy(tmp_path), {"verdict": "benign", "score": 0}, fmt="yaml")
    assert not list(tmp_path.glob("*_report.*"))


def test_html_escapes_document_content(tmp_path):
    rg.generate_report(
        make_dummy(tmp_path),
        {"verdict": "benign", "score": 0, "summary": "<script>alert(1)</script>"},
        fmt="html",
    )
    text = (tmp_path / "foo_report.html").read_text()
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


@pytest.mark.parametrize("fmt", ["markdown", "html", "json", "csv", "jsonl"])
def test_enrichment_skips_are_explicit_in_every_format(tmp_path, fmt):
    from ioc_inspector_core.reputation_status import summarize
    result = {
        "verdict": "benign", "score": 0, "urls": ["https://example.com"], "ips": ["198.51.100.7"],
        "enrichment": {
            "virustotal": summarize({"https://example.com": {"status": "skipped", "reason": "offline"}}, "offline"),
            "abuseipdb": summarize({"198.51.100.7": {"status": "skipped", "reason": "offline"}}, "offline"),
        },
    }
    output = tmp_path / "custom"
    rg.generate_report(make_dummy(tmp_path), result, fmt=fmt, output_dir=output)
    text = next(output.iterdir()).read_text(encoding="utf-8")
    assert "offline" in text
    assert "skipped" in text
    if fmt in ("markdown", "html"):
        assert "not checked" in text
        assert "Lookup status" in text


def test_invalid_enrichment_status_is_rejected(tmp_path):
    with pytest.raises(jsonschema.ValidationError):
        rg.generate_report(make_dummy(tmp_path), {
            "verdict": "benign", "score": 0,
            "enrichment": {"virustotal": {"status": "pretend_clean", "reason": ""}},
        }, fmt="json")
