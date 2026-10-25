import pytest
from zipfile import ZipFile
from unittest.mock import MagicMock
import ioc_inspector_core.doc_parser as parser
from ioc_inspector_core.doc_parser import parse_office
from ioc_inspector_core.exceptions import ParserError

def test_docm_detects_macro(sample_docm):
    out = parse_office(sample_docm)
    assert out["type"] == "office"
    assert out["macro"] is True
    assert isinstance(out["urls"], list)
    assert isinstance(out["ips"], list)

def test_garbage_doc_raises(tmp_path):
    garbage = tmp_path / "garbage.docm"
    garbage.write_bytes(b"\x00")
    with pytest.raises(ParserError):
        parse_office(garbage)


@pytest.mark.parametrize("extension,part", [("docx", "word/document.xml"), ("xlsx", "xl/sharedStrings.xml")])
def test_ooxml_indicators_without_macros(tmp_path, extension, part):
    path = tmp_path / f"links.{extension}"
    with ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        archive.writestr(part, '<document><text>198.51.100.7 https://example.com/visible</text></document>')
        archive.writestr("_rels/.rels", '<Relationships><Relationship Target="https://example.com/hidden?x=1&amp;y=2"/></Relationships>')
    findings = parse_office(path)
    assert not findings["macro"]
    assert findings["ips"] == ["198.51.100.7"]
    assert findings["urls"] == ["https://example.com/hidden?x=1&y=2", "https://example.com/visible"]


def test_rtf_plaintext_indicators(tmp_path):
    path = tmp_path / "links.rtf"
    path.write_bytes(b"{\\rtf1 Visit https://example.com/test or 198.51.100.8}")
    findings = parse_office(path)
    assert findings["urls"] == ["https://example.com/test"]
    assert findings["ips"] == ["198.51.100.8"]


def test_macro_keywords_contain_actual_suspicious_keywords(monkeypatch, tmp_path):
    source = tmp_path / "macro.doc"
    source.touch()
    vb = MagicMock()
    vb.detect_vba_macros.return_value = True
    vb.extract_macros.return_value = [(None, None, "Module1", 'Sub AutoOpen()\nShell "cmd.exe"\nEnd Sub')]
    monkeypatch.setattr(parser, "VBA_Parser", lambda path: vb)
    monkeypatch.setattr(parser, "analyze_macros", lambda path: {})
    findings = parse_office(source)
    assert "Shell" in findings["suspicious_keywords"]
    assert "Suspicious" not in findings["suspicious_keywords"]
    assert "AutoExec" not in findings["suspicious_keywords"]
    vb.close.assert_called_once()
