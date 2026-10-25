#!/usr/bin/env python3
"""IOC Inspector: document scanning, interactive setup, and batch reports."""

from __future__ import annotations

import hashlib
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ioc_inspector_core import analyze
from ioc_inspector_core import report_generator as reports
from ioc_inspector_core.cli_support import (
    ScanOptions, interactive_options, parse_extensions, select_targets, summarize_scan,
)
from ioc_inspector_core.exceptions import ParserError
from ioc_inspector_core.report_generator import REPORT_EXTENSIONS, generate_batch_report, generate_report
from logger import LOG_DIR, configure_logging, get_logger
from settings import REPORT_FORMATS

log = get_logger(__name__)

try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_ver
    PKG_VER = _pkg_ver("ioc_inspector")
except (PackageNotFoundError, ModuleNotFoundError):
    PKG_VER = "dev"


def process_document(doc: Path, options: ScanOptions, output_stem: str) -> dict:
    """Keep analysis and report failures local to their document."""
    record: dict = {"source": str(doc), "status": "scanned", "reports": []}
    try:
        if options.max_size_mb and doc.stat().st_size > options.max_size_mb * 1024 * 1024:
            return {"source": str(doc), "status": "skipped", "reason": "size_limit"}
        outcome = analyze(doc, offline=True) if options.offline else analyze(doc)
        record["result"] = outcome
    except Exception as exc:
        stage = "parser" if isinstance(exc, ParserError) else "analysis"
        log.exception("Error analyzing %s", doc)
        record.update(status="error", error_stage=stage, error=str(exc))
        return record
    try:
        for fmt in options.formats:
            generate_report(doc, outcome, fmt=fmt, output_stem=output_stem, output_dir=options.output_dir)
            record["reports"].append(str(options.output_dir / f"{output_stem}_report.{REPORT_EXTENSIONS[fmt]}"))
    except Exception as exc:
        log.exception("Error writing report for %s", doc)
        record.update(status="error", error_stage="report", error=str(exc))
    return record


def display_result(record: dict, *, quiet: bool) -> None:
    if record["status"] == "error":
        label = record["error_stage"].upper()
        click.echo(f"[{label} ERROR] {record['source']}: {record['error']}", err=True)
    if quiet or "result" not in record:
        return
    outcome = record["result"]
    color = {"benign": "green", "suspicious": "yellow", "malicious": "red"}.get(outcome["verdict"], "cyan")
    click.secho(
        f"{record['source']}: score={outcome['score']}  verdict={outcome['verdict']}",
        fg=color, color=False if "NO_COLOR" in os.environ else None,
    )
    if outcome.get("enrichment"):
        labels = []
        for name, info in outcome["enrichment"].items():
            reason = f" ({info['reason']})" if info.get("reason") else ""
            labels.append(f"{name}={info['status']}{reason}")
        click.echo("  Reputation: " + "; ".join(labels))


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog="Examples:\n  ioc-inspector --interactive\n"
           "  ioc-inspector --file invoice.pdf --offline\n"
           "  ioc-inspector --dir samples --format json --batch-report",
)
@click.version_option(PKG_VER, prog_name="IOC Inspector")
@click.option("-f", "--file", "files", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              multiple=True, help="Scan a document; repeat for multiple files.")
@click.option("-d", "--dir", "dir_", type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Recursively scan supported documents in a directory.")
@click.option("--interactive", is_flag=True, help="Choose scan settings through prompts.")
@click.option("--report", is_flag=True, help="Add Markdown to the selected report formats.")
@click.option("--json", "json_", is_flag=True, help="Add JSON to the selected report formats.")
@click.option("--format", "formats", multiple=True, type=click.Choice(list(REPORT_EXTENSIONS), case_sensitive=False),
              help="Replace default report formats; repeat for multiple formats.")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path), help="Directory for reports.")
@click.option("--batch-report", is_flag=True, help="Also write batch_summary.json with all findings, skips and errors.")
@click.option("--extensions", help="Filter document types, e.g. pdf,docx,xlsx (case insensitive).")
@click.option("--max-size-mb", type=click.IntRange(min=0), default=50, show_default=True,
              help="Maximum input size in MiB; 0 disables the limit.")
@click.option("--offline", is_flag=True, help="Skip reputation services, even with API keys configured.")
@click.option("--quiet", is_flag=True, help="Suppress progress and summaries; errors still print.")
@click.option("--no-progress", is_flag=True, help="Disable the terminal spinner and progress bar.")
@click.option("-t", "--threads", type=click.IntRange(1, 32), default=1, show_default=True,
              help="Number of concurrent workers.")
@click.option("--debug", is_flag=True, help="Enable debug logs across analysis modules.")
def cli(
    files: tuple[Path, ...], dir_: Path | None, interactive: bool, report: bool,
    json_: bool, formats: tuple[str, ...], output_dir: Path | None,
    batch_report: bool, extensions: str | None, max_size_mb: int, offline: bool,
    quiet: bool, no_progress: bool, threads: int, debug: bool,
) -> None:
    """Extract static indicators and score PDFs, Office documents, and RTF files."""
    if interactive and quiet:
        raise click.UsageError("--interactive and --quiet cannot be combined.")
    if not (files or dir_ or interactive):
        raise click.UsageError("Specify --file, --dir, or --interactive.")

    selected_formats = list(dict.fromkeys(formats if formats else REPORT_FORMATS))
    options = ScanOptions(
        files=files, directory=dir_, formats=selected_formats,
        output_dir=output_dir if output_dir is not None else reports.REPORTS_DIR,
        extensions=parse_extensions(extensions) if extensions is not None else None,
        max_size_mb=max_size_mb, threads=threads, offline=offline, batch_report=batch_report,
    )
    if interactive:
        options = interactive_options(options)
    if report and "markdown" not in options.formats:
        options.formats.append("markdown")
    if json_ and "json" not in options.formats:
        options.formats.append("json")
    invalid = set(options.formats) - REPORT_EXTENSIONS.keys()
    if invalid:
        raise click.ClickException(f"Unsupported REPORT_FORMATS: {', '.join(sorted(invalid))}")

    configure_logging(quiet=quiet, debug=debug, console_level="DEBUG" if debug else "WARNING")
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    targets, records = select_targets(options, LOG_DIR)
    for record in records:
        if record["status"] == "error":
            display_result(record, quiet=quiet)
    stems = Counter(path.stem.casefold() for path in targets)
    names = {}
    for path in targets:
        suffix = ""
        if stems[path.stem.casefold()] > 1:
            suffix = "_" + hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:12]
        names[path] = path.stem + suffix

    console = Console(stderr=True)
    progress = Progress(
        SpinnerColumn("line"), TextColumn("Scanning"), BarColumn(),
        MofNCompleteColumn(), TimeElapsedColumn(), console=console,
        transient=True, disable=quiet or no_progress or not console.is_terminal,
    )
    completed: dict[Path, dict] = {}
    with progress:
        task = progress.add_task("Scanning", total=len(targets))
        if options.threads > 1 and len(targets) > 1:
            with ThreadPoolExecutor(max_workers=options.threads) as pool:
                futures = {pool.submit(process_document, path, options, names[path]): path for path in targets}
                for future in as_completed(futures):
                    path = futures[future]
                    completed[path] = future.result()
                    display_result(completed[path], quiet=quiet)
                    progress.advance(task)
        else:
            for path in targets:
                completed[path] = process_document(path, options, names[path])
                display_result(completed[path], quiet=quiet)
                progress.advance(task)

    # Stable input ordering in the combined report, regardless of worker timing.
    records.extend(completed[path] for path in targets)
    summary = summarize_scan(records)
    elapsed = time.monotonic() - started
    batch_failed = False
    if options.batch_report:
        try:
            destination = generate_batch_report(
                records, summary, output_dir=options.output_dir,
                offline=options.offline, started_at=started_at, elapsed=elapsed,
            )
            if not quiet:
                click.echo(f"Batch report: {destination}")
        except Exception as exc:
            click.echo(f"[BATCH REPORT ERROR] {exc}", err=True)
            batch_failed = True
    if not quiet:
        click.echo(
            f"\nScan summary ({elapsed:.2f}s): {summary['scanned']} scanned, "
            f"{summary['errors']} errors, {summary['skipped']} skipped"
        )
        click.echo("  " + ", ".join(f"{summary[key]} {key}" for key in ("benign", "suspicious", "malicious", "unknown")))
        skipped = Counter(item["reason"] for item in records if item["status"] == "skipped")
        if skipped:
            click.echo("  Skips: " + ", ".join(f"{count} {reason}" for reason, count in sorted(skipped.items())))
    if summary["errors"] or summary["malicious"] or batch_failed:
        raise click.exceptions.Exit(1)
    if not targets:
        click.echo("No matching documents found to scan.", err=True)
        raise click.exceptions.Exit(2)


if __name__ == "__main__":
    cli()
