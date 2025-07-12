import pytest
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
