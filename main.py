#!/usr/bin/env python3
"""
IOC Inspector – Click-powered command-line interface
────────────────────────────────────────────────────
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List
from concurrent.futures import ThreadPoolExecutor

import click

from ioc_inspector_core import analyze
from ioc_inspector_core.exceptions import ParserError
from ioc_inspector_core.report_generator import generate_report
from logger import get_logger
from settings import REPORT_FORMATS

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Version string (shows "dev" when running from source tree)
# --------------------------------------------------------------------------- #
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_ver

    PKG_VER = _pkg_ver("ioc_inspector")
except (PackageNotFoundError, ModuleNotFoundError):
    PKG_VER = "dev"

# --------------------------------------------------------------------------- #
# Click CLI definition
# --------------------------------------------------------------------------- #
@click.command(
    context_settings=dict(help_option_names=["-h", "--help"]),
    epilog="Examples:\n"
           "  ioc-inspector --file invoices/bad.pdf --report\n"
           "  ioc-inspector --dir samples/ --json --quiet",
)
@click.version_option(PKG_VER, prog_name="IOC Inspector")
@click.option(
    "-f",
    "--file",
    "files",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="Scan a document (can be used multiple times)",
)
@click.option(
    "-d", "--dir",
    "dir_",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Recursively scan a directory",
)
@click.option(
    "--report",
    is_flag=True,
    help="Always write Markdown report (even if disabled in settings.py)",
)
@click.option(
    "--json",
    "json_",
    is_flag=True,
    help="Always write JSON report",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress console summary (errors still print)",
)
@click.option(
    "-t",
    "--threads",
    type=click.IntRange(1, 32),
    default=1,
    show_default=True,
    help="Number of concurrent threads",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Bump log level to DEBUG for troubleshooting",
)
def cli(
    files: tuple[Path, ...],
    dir_: Path | None,
    report: bool,
    json_: bool,
    quiet: bool,
    threads: int,
    debug: bool,
) -> None:
    """
    Static IOC extractor + reputation scorer for PDFs & Office documents.
    """
    if not (files or dir_):
        click.echo("Error: specify --file or --dir\n", err=True)
        click.echo(click.get_current_context().get_help(), err=True)
        sys.exit(2)

    if debug:
        get_logger().setLevel("DEBUG")

    if files:
        targets: List[Path] = list(files)
    else:
        assert dir_ is not None
        targets = [p for p in dir_.rglob("*") if p.is_file()]

    if not targets:
        log.error("No files found to scan.")
        sys.exit(2)

    want_md = report or "markdown" in REPORT_FORMATS
    want_json = json_ or "json" in REPORT_FORMATS


    def process(doc: Path) -> bool:
        try:
            outcome = analyze(doc)
        except ParserError as exc:
            log.error("ParserError analyzing %s: %s", doc.name, exc)
            if not quiet:
                click.echo(f"[PARSER ERROR] {doc}: {exc}", err=True)
            return True
        except Exception as exc:
            log.exception("Unexpected error analyzing %s", doc.name)
            if not quiet:
                click.echo(f"[UNEXPECTED ERROR] {doc}: {exc}", err=True)
            return True

        if not quiet:
            click.echo(f"{doc}: score={outcome['score']}  verdict={outcome['verdict']}")

        if want_md:
            generate_report(doc, outcome, fmt="markdown")
        if want_json:
            generate_report(doc, outcome, fmt="json")

        log.info(
            "%s analysed – score=%s verdict=%s",
            doc.name,
            outcome["score"],
            outcome["verdict"],
        )
        return outcome["verdict"] == "malicious"

    if threads > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            results = list(pool.map(process, targets))
        exit_bad = any(results)
    else:
        exit_bad = False
        for doc in targets:
            if process(doc):
                exit_bad = True

    sys.exit(1 if exit_bad else 0)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    try:
        cli()  # pylint: disable=no-value-for-parameter
    except KeyboardInterrupt:
        click.echo("\nInterrupted by user.", err=True)
        sys.exit(130)
