from pathlib import Path
from ioc_inspector_core import analyze

def test_smoke_pdf():
    """Basic sanity: analyzer runs without raising and returns dict."""
    res = analyze(Path("examples/test.pdf"))
    assert isinstance(res, dict)
