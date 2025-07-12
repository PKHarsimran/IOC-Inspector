"""
Failure-path test: corrupt PDF should raise ParserError and log an ERROR.
"""

import pytest, logging
from ioc_inspector_core.pdf_parser import parse_pdf
from ioc_inspector_core.exceptions import ParserError

def test_corrupt_pdf_raises_parser_error(tmp_path, caplog):
    bad = tmp_path / "corrupt.pdf"
    bad.write_bytes(b"\x00")

    with caplog.at_level(logging.ERROR), pytest.raises(ParserError):
        parse_pdf(bad)

    assert any(r.levelname == "ERROR" for r in caplog.records)

