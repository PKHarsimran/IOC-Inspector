from ioc_inspector_core import analyze

def test_dispatch_pdf(sample_pdf):
    assert analyze(sample_pdf)["type"] == "pdf"

def test_dispatch_docm(sample_docm):
    assert analyze(sample_docm)["type"] == "office"
