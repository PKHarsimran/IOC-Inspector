#!/usr/bin/env python3
"""
IOC Inspector - command-line entry point
───────────────────────────────────────
Usage examples
    $ python main.py --file samples/invoice.docx --report
    $ python main.py --dir incoming_docs/ --json --quiet
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ioc_inspector_core import analyze
from ioc_inspector_core.report_generator import generate_report
from logger import get_logger
from settings import REPORT_FORMATS

log = get_logger(__name__)


# ────────────────────────────────────────────────────────────────────────────────
# CLI parsing
# ────────────────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    """
    Collect and validate command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed arguments ready for use.
    """
    parser = argparse.ArgumentParser(
        prog="ioc-inspector",
        description="Static IOC extractor + reputation scorer for PDFs & Office docs.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", metavar="PATH", help="Scan a single document")
    group.add_argument("-d", "--dir", metavar="DIR", help="Recursively scan a directory")

    parser.add_argument(
        "--report", action="store_true", help="Always write a Markdown report"
    )
    parser.add_argument(
        "--json", action="store_true", help="Always write JSON alongside Markdown"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console summary (errors still print)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Set log level to DEBUG for troubleshooting",
    )
    return parser.parse_args()


# ────────────────────────────────────────────────────────────────────────────────
# Main programme
# ────────────────────────────────────────────────────────────────────────────────
def main() -> None:  # noqa: C901  (function intentionally procedural)
    args = _parse_args()

    # Optional verbose logging
    if args.debug:
        get_logger().setLevel("DEBUG")

    # Build list of targets
    targets: list[Path]
    if args.file:
        targets = [Path(args.file)]
    else:
        root = Path(args.dir)
        targets = [p for p in root.rglob("*") if p.is_file()]

    if not targets:
        log.error("No files found to scan.")
        sys.exit(2)

    # Flags controlling output formats
    want_md = args.report or "markdown" in REPORT_FORMATS
    want_js = args.json or "json" in REPORT_FORMATS

    exit_bad = False  # non-zero exit if any doc is malicious
    for doc in targets:
        try:
            outcome = analyze(doc)
        except Exception as err:  # pragma: no cover  – top-level catch
            log.exception("Error analysing %s", doc)
            if not args.quiet:
                print(f"[ERROR] {doc}: {err}")
            exit_bad = True
            continue

        # Console headline
        if not args.quiet:
            print(f"{doc}: score={outcome['score']}  verdict={outcome['verdict']}")

        # Persist reports
        if want_md:
            generate_report(doc, outcome, fmt="markdown")
        if want_js:
            generate_report(doc, outcome, fmt="json")

        # Log structured summary
        log.info(
            "%s analysed  –  score=%s  verdict=%s",
            doc.name,
            outcome["score"],
            outcome["verdict"],
        )

        # Mark exit status if malicious
        if outcome["verdict"] == "malicious":
            exit_bad = True

    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    main()
