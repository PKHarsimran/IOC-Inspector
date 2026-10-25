import io
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

import main
from ioc_inspector_core import report_generator as reports
from ioc_inspector_core.exceptions import ParserError


@pytest.fixture
def scanner(monkeypatch, tmp_path):
    calls = []
    def fake(path, **kwargs):
        calls.append((path, kwargs))
        if path.stem == "broken":
            raise ParserError("damaged PDF")
        return {"type": "pdf", "score": 80 if path.stem == "bad" else 0,
                "verdict": "malicious" if path.stem == "bad" else "benign"}
    monkeypatch.setattr(main, "analyze", fake)
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path / "reports")
    return calls


def test_explicit_formats_replace_defaults_and_use_output_directory(scanner, tmp_path):
    source = tmp_path / "input.pdf"
    source.touch()
    output = tmp_path / "custom"
    result = CliRunner().invoke(main.cli, ["-f", str(source), "--format", "CSV", "--format", "html", "--output-dir", str(output)])
    assert result.exit_code == 0, result.output
    assert {p.suffix for p in output.iterdir()} == {".csv", ".html"}
    assert not (tmp_path / "reports").exists()
    assert "1 scanned, 0 errors, 0 skipped" in result.output


def test_format_override_can_repair_bad_environment_formats(scanner, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORT_FORMATS", ["invalid"])
    source = tmp_path / "input.pdf"
    source.touch()
    result = CliRunner().invoke(main.cli, ["-f", str(source), "--format", "json", "--report"])
    assert result.exit_code == 0, result.output
    assert {p.suffix for p in (tmp_path / "reports").iterdir()} == {".json", ".md"}


def test_directory_filters_sizes_outputs_and_keeps_business_reports(scanner, tmp_path):
    for name in ("keep.PDF", "annual_report.pdf", "skip.docx", "notes.txt", "old_report.json"):
        (tmp_path / name).touch()
    with (tmp_path / "large.pdf").open("wb") as handle:
        handle.truncate(1024 * 1024 + 1)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports/ignored.pdf").touch()
    result = CliRunner().invoke(main.cli, ["-d", str(tmp_path), "--extensions", ".PDF", "--max-size-mb", "1", "--batch-report"])
    assert result.exit_code == 0, result.output
    assert {path.name for path, _ in scanner} == {"keep.PDF", "annual_report.pdf"}
    batch = json.loads((tmp_path / "reports/batch_summary.json").read_text())
    assert {item["reason"] for item in batch["files"] if item["status"] == "skipped"} == {
        "extension_filter", "size_limit", "generated_report", "excluded_directory",
    }


def test_default_directory_scan_skips_unsupported_files(scanner, tmp_path):
    (tmp_path / "keep.pdf").touch()
    (tmp_path / "notes.txt").touch()
    result = CliRunner().invoke(main.cli, ["-d", str(tmp_path), "--batch-report"])
    assert result.exit_code == 0
    assert [path.name for path, _ in scanner] == ["keep.pdf"]
    assert "1 unsupported_extension" in result.output


@pytest.mark.parametrize("threads", ["1", "3"])
def test_batch_includes_findings_errors_skips_and_stable_result_order(scanner, tmp_path, threads):
    for name in ("ok.pdf", "broken.pdf", "bad.pdf", "notes.txt"):
        (tmp_path / name).touch()
    result = CliRunner().invoke(main.cli, ["-d", str(tmp_path), "--threads", threads, "--batch-report", "--offline", "--quiet"])
    assert result.exit_code == 1
    batch = json.loads((tmp_path / "reports/batch_summary.json").read_text())
    assert batch["offline"] is True
    assert batch["summary"] == {"scanned": 2, "errors": 1, "skipped": 1,
                               "benign": 1, "suspicious": 0, "malicious": 1, "unknown": 0}
    assert [item["source"].split("\\")[-1].split("/")[-1] for item in batch["files"] if item["status"] != "skipped"] == ["bad.pdf", "broken.pdf", "ok.pdf"]
    assert all(kwargs == {"offline": True} for _, kwargs in scanner)
    assert "PARSER ERROR" in result.output
    assert "Scan summary" not in result.output


def test_skipped_only_batch_is_written_and_returns_no_target_code(scanner, tmp_path):
    (tmp_path / "notes.txt").touch()
    result = CliRunner().invoke(main.cli, ["-d", str(tmp_path), "--batch-report"])
    assert result.exit_code == 2
    assert not scanner
    batch = json.loads((tmp_path / "reports/batch_summary.json").read_text())
    assert batch["summary"]["skipped"] == 1
    assert batch["summary"]["scanned"] == 0


def test_batch_writer_failure_returns_error_after_scan(scanner, monkeypatch, tmp_path):
    source = tmp_path / "input.pdf"
    source.touch()
    def fail(*args, **kwargs):
        raise OSError("read-only destination")
    monkeypatch.setattr(main, "generate_batch_report", fail)
    result = CliRunner().invoke(main.cli, ["-f", str(source), "--batch-report"])
    assert result.exit_code == 1
    assert "[BATCH REPORT ERROR] read-only destination" in result.output
    assert "1 scanned, 0 errors" in result.output
    assert len(scanner) == 1


def test_interactive_file_menu_retries_invalid_formats(scanner, tmp_path):
    source = tmp_path / "input.pdf"
    source.touch()
    output = tmp_path / "menu-output"
    answers = f"file\n{source}\nwrong\njson,csv\n{output}\n2\npdf\n1\ny\ny\n"
    result = CliRunner().invoke(main.cli, ["--interactive"], input=answers)
    assert result.exit_code == 0, result.output
    assert scanner == [(source, {"offline": True})]
    assert {path.name for path in output.iterdir()} == {"input_report.json", "input_report.csv", "batch_summary.json"}
    assert "Choose from:" in result.output


def test_interactive_folder_menu_can_disable_per_file_reports(scanner, tmp_path):
    (tmp_path / "input.pdf").touch()
    output = tmp_path / "output"
    answers = f"folder\n{tmp_path}\nnone\n{output}\n1\npdf\n0\ny\ny\n"
    result = CliRunner().invoke(main.cli, ["--interactive"], input=answers)
    assert result.exit_code == 0, result.output
    assert {p.name for p in output.iterdir()} == {"batch_summary.json"}


@pytest.mark.parametrize("args", [["--extensions", "exe"], ["--extensions", ""], ["--max-size-mb", "-1"], ["--format", "yaml"]])
def test_invalid_options_fail_before_scanning(scanner, tmp_path, args):
    source = tmp_path / "input.pdf"
    source.touch()
    result = CliRunner().invoke(main.cli, ["-f", str(source), *args])
    assert result.exit_code == 2
    assert not scanner


def test_quiet_menu_is_rejected(scanner):
    result = CliRunner().invoke(main.cli, ["--interactive", "--quiet"])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output


def test_no_color_environment_suppresses_ansi(scanner, monkeypatch, tmp_path):
    source = tmp_path / "input.pdf"
    source.touch()
    monkeypatch.setenv("NO_COLOR", "1")
    result = CliRunner().invoke(main.cli, ["-f", str(source)], color=True)
    assert result.exit_code == 0
    assert "\x1b[" not in result.output


def test_progress_renders_in_terminal_but_no_progress_disables_it(scanner, monkeypatch, tmp_path):
    terminal = io.StringIO()
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(main, "Console", lambda **kwargs: Console(file=terminal, force_terminal=True, legacy_windows=False, width=90))
    source = tmp_path / "input.pdf"
    source.touch()
    result = CliRunner().invoke(main.cli, ["-f", str(source)])
    assert result.exit_code == 0
    assert "Scanning" in terminal.getvalue()
    terminal.seek(0)
    terminal.truncate()
    result = CliRunner().invoke(main.cli, ["-f", str(source), "--no-progress"])
    assert result.exit_code == 0
    assert terminal.getvalue() == ""


def test_file_selection_error_is_recorded_and_other_documents_continue(scanner, monkeypatch, tmp_path):
    for name in ("locked.pdf", "ok.pdf"):
        (tmp_path / name).touch()
    original_stat = Path.stat
    def checked_stat(path, *args, **kwargs):
        if path.name == "locked.pdf":
            raise PermissionError("file became unreadable")
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", checked_stat)
    result = CliRunner().invoke(main.cli, ["-d", str(tmp_path), "--batch-report"])
    assert result.exit_code == 1
    assert [path.name for path, _ in scanner] == ["ok.pdf"]
    batch = json.loads((tmp_path / "reports/batch_summary.json").read_text())
    assert batch["summary"]["errors"] == 1
    assert batch["files"][0]["error_stage"] == "selection"


def test_size_limit_can_be_disabled_for_an_explicit_file(scanner, tmp_path):
    source = tmp_path / "large.pdf"
    with source.open("wb") as handle:
        handle.truncate(1024 * 1024 + 1)
    runner = CliRunner()
    result = runner.invoke(main.cli, ["-f", str(source), "--max-size-mb", "1"])
    assert result.exit_code == 2
    assert not scanner
    result = runner.invoke(main.cli, ["-f", str(source), "--max-size-mb", "0"])
    assert result.exit_code == 0
    assert scanner[0][0] == source
