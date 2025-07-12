from ioc_inspector_core.heuristics import score

def test_score_empty_findings():
    findings = {}
    out = score(findings)
    assert out["score"] == 0
    assert out["verdict"] == "benign"
    assert "No significant issues detected" in out["summary"]

def test_score_macro_and_pdf_features():
    # macro + embedded + js → 25 + 10 + 10 = 45 → "suspicious"
    findings = {
        "macro": True,
        "suspicious_keywords": [],
        "url_rep": {},
        "ip_rep": {},
        "embedded_files": 1,
        "js_count": 1,
    }
    out = score(findings)
    assert out["score"] == 45
    assert out["verdict"] == "suspicious"
