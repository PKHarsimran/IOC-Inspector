"""
Failure-path test: corrupt PDF should raise ParserError and log an ERROR.
"""

import pytest
from pathlib import Path
from ioc_inspector_core.pdf_parser import parse_pdf
from ioc_inspector_core.exceptions import ParserError


def test_corrupt_pdf_raises_parser_error(tmp_path, caplog):
    # create a 1-byte garbage file → not a real PDF
    bad = tmp_path / "corrupt.pdf"
    bad.write_bytes(b"\x00")

    with caplog.at_level("ERROR"):
        with pytest.raises(ParserError):
            parse_pdf(bad)

    # ensure an ERROR-level log record was emitted
    assert any(rec.levelname == "ERROR" for rec in caplog.records)
