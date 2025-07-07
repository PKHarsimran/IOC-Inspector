#!/usr/bin/env python3
"""
IOC Inspector – command-line driver
───────────────────────────────────
Examples:
    python main.py --file samples/invoice.docx --report
    python main.py --dir  incoming_docs/ --json --quiet
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import version
from pathlib import Path
from typing import List

from ioc_inspector_core import analyze
from ioc_inspector_core.report_generator import generate_report
from logger import get_logger
from settings import REPORT_FORMATS

log = get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# CLI parsing
# ──────────────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    """Collect and validate command-line arguments."""
    p = argparse.ArgumentParser(
        prog="ioc-inspector",
        description="Static IOC extractor + reputation scorer for PDFs & Office docs.",
    )

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file", metavar="PATH", help="Scan a single document")
    src.add_argument("-d", "--dir", metavar="DIR", help="Recursively scan a directory")

    p.add_argument("--report", action="store_true", help="Force Markdown output")
    p.add_argument("--json",   action="store_true", help="Force JSON output")
    p.add_argument("--quiet",  action="store_true", help="Suppress console summary")
    p.add_argument("--debug",  action="store_true", help="Enable DEBUG logging")
    p.add_argument("-v", "--version", action="version",
                   version=f"IOC Inspector {version('ioc-inspector')}")
    return p.parse_args()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:  # noqa: C901 (procedural by design)
    args = _parse_args()

    if args.debug:
        get_logger().setLevel("DEBUG")

    # Build list of targets ---------------------------------------------------
    targets: List[Path]
    if args.file:
        targets = [Path(args.file)]
    else:
        root = Path(args.dir)
        targets = [p for p in root.rglob("*") if p.is_file()]

    if not targets:
        log.error("No files found to scan.")
        sys.exit(2)

    want_md   = args.report or "markdown" in REPORT_FORMATS
    want_json = args.json  or "json"     in REPORT_FORMATS

    exit_bad = False  # non-zero exit if any doc is malicious
    for doc in targets:
        try:
            outcome = analyze(doc)
        except Exception as exc:  # pragma: no cover
            log.exception("Error analysing %s", doc)
            if not args.quiet:
                print(f"[ERROR] {doc}: {exc}")
            exit_bad = True
            continue

        # Console headline ----------------------------------------------------
        if not args.quiet:
            print(f"{doc}: score={outcome['score']}  verdict={outcome['verdict']}")

        # Persist reports -----------------------------------------------------
        if want_md:
            generate_report(doc, outcome, fmt="markdown")
        if want_json:
            generate_report(doc, outcome, fmt="json")

        log.info("%s analysed – score=%s verdict=%s",
                 doc.name, outcome["score"], outcome["verdict"])

        if outcome["verdict"] == "malicious":
            exit_bad = True

    sys.exit(1 if exit_bad else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
