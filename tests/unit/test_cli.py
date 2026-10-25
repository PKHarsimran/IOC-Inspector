from click.testing import CliRunner
import pytest

import main
import ioc_inspector_core.report_generator as reports
from ioc_inspector_core.exceptions import ParserError


@pytest.fixture(autouse=True)
def reports_in_temp_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)


def test_cli_multiple_files(monkeypatch, tmp_path):
    calls = []

    def fake_analyze(path):
        calls.append(path)
        return {"score": 0, "verdict": "benign"}

    monkeypatch.setattr(main, "analyze", fake_analyze)

    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("a")
    f2.write_text("b")

    runner = CliRunner()
    result = runner.invoke(main.cli, ["--file", str(f1), "--file", str(f2), "--quiet"])
    assert result.exit_code == 0
    assert calls == [f1, f2]

def test_cli_threads(monkeypatch, tmp_path):
    calls = []

    def fake_analyze(path):
        calls.append(path)
        return {"score": 0, "verdict": "benign"}

    monkeypatch.setattr(main, "analyze", fake_analyze)

    d = tmp_path / "data"
    d.mkdir()
    f1 = d / "a.pdf"
    f2 = d / "b.pdf"
    f1.write_text("a")
    f2.write_text("b")

    runner = CliRunner()
    result = runner.invoke(
        main.cli,
        ["--dir", str(d), "--quiet", "--threads", "2"],
    )
    assert result.exit_code == 0
    assert set(calls) == {f1, f2}


def test_cli_honors_all_configured_report_formats(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORT_FORMATS", ["csv", "jsonl", "html"])
    monkeypatch.setattr(main, "analyze", lambda path: {"score": 0, "verdict": "benign"})
    source = tmp_path / "input.pdf"
    source.touch()
    result = CliRunner().invoke(main.cli, ["--file", str(source), "--quiet"])
    assert result.exit_code == 0, result.output
    assert {p.suffix for p in tmp_path.glob("input_report.*")} == {".csv", ".jsonl", ".html"}


def test_cli_combines_file_and_directory_without_duplicates(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(main, "REPORT_FORMATS", [])
    def fake_analyze(path):
        calls.append(path)
        return {"score": 0, "verdict": "benign"}
    monkeypatch.setattr(main, "analyze", fake_analyze)
    for name in ("a.pdf", "b.pdf"):
        (tmp_path / name).touch()
    result = CliRunner().invoke(main.cli, ["--file", str(tmp_path / "a.pdf"), "--dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert set(calls) == {tmp_path / "a.pdf", tmp_path / "b.pdf"}
    assert len(calls) == 2


@pytest.mark.parametrize("threads", ["1", "2"])
def test_report_failure_does_not_abort_batch(monkeypatch, tmp_path, threads):
    calls = []
    monkeypatch.setattr(main, "REPORT_FORMATS", ["json"])
    monkeypatch.setattr(main, "analyze", lambda path: {"score": 0, "verdict": "benign"})
    def write_report(path, result, **kwargs):
        calls.append(path.name)
        if path.name == "a.pdf":
            raise OSError("disk full")
    monkeypatch.setattr(main, "generate_report", write_report)
    (tmp_path / "a.pdf").touch()
    (tmp_path / "b.pdf").touch()
    result = CliRunner().invoke(main.cli, ["--dir", str(tmp_path), "--quiet", "--threads", threads])
    assert result.exit_code == 1
    assert set(calls) == {"a.pdf", "b.pdf"}
    assert "[REPORT ERROR]" in result.output
    assert "disk full" in result.output


def test_quiet_still_prints_parser_errors(monkeypatch, tmp_path):
    def broken(path):
        raise ParserError("damaged document")
    monkeypatch.setattr(main, "analyze", broken)
    path = tmp_path / "bad.pdf"
    path.touch()
    result = CliRunner().invoke(main.cli, ["--file", str(path), "--quiet"])
    assert result.exit_code == 1
    assert "[PARSER ERROR]" in result.output


def test_batch_reports_do_not_overwrite_same_stem(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORT_FORMATS", ["json"])
    monkeypatch.setattr(main, "analyze", lambda path: {"score": 0, "verdict": "benign"})
    sources = tmp_path / "sources"
    sources.mkdir()
    for name in ("invoice.pdf", "invoice.docx"):
        (sources / name).touch()
    result = CliRunner().invoke(main.cli, ["--dir", str(sources), "--threads", "2"])
    assert result.exit_code == 0, result.output
    assert len(list(tmp_path.glob("invoice_*_report.json"))) == 2


def test_invalid_report_configuration_fails_before_analysis(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORT_FORMATS", ["yaml"])
    path = tmp_path / "test.pdf"
    path.touch()
    result = CliRunner().invoke(main.cli, ["--file", str(path)])
    assert result.exit_code == 1
    assert "Unsupported REPORT_FORMATS: yaml" in result.output

