import json
from pathlib import Path
import pytest

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
    assert "# IOC Inspector Report – foo.pdf" in text
    assert "**Verdict:** **BENIGN**" in text

def test_generate_json(tmp_path):
    src = make_dummy(tmp_path)
    result = {"verdict": "malicious", "score": 100}
    rg.generate_report(src, result, fmt="json")
    out = tmp_path / "foo_report.json"
    data = json.loads(out.read_text())
    assert data["verdict"] == "malicious"
    assert data["score"] == 100
