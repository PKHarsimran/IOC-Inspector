#!/usr/bin/env python3
"""IOC Inspector – Command‑line entry point.

Usage examples:
    python main.py --file examples/sample_invoice.docx --report
    python main.py --dir ./suspicious_docs --json --quiet

Exits with 1 if any document is classified as malicious, else 0.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyzer import analyze  # high‑level dispatcher (to be implemented in analyzer/__init__.py)
from analyzer.report_generator import generate_report  # handles output formatting
from config import REPORT_FORMATS


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ioc‑inspector",
        description="Static malicious document analyzer for SOC analysts",
    )

    tgt = parser.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-f", "--file", metavar="PATH", help="Document file to scan")
    tgt.add_argument("-d", "--dir", metavar="DIR", help="Directory to recursively scan")

    parser.add_argument("--report", action="store_true", help="Write Markdown report (overrides config)")
    parser.add_argument("--json", action="store_true", help="Write JSON output (overrides config)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console summary")

    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # Build a list of targets
    if args.file:
        targets = [Path(args.file)]
    else:
        targets = [p for p in Path(args.dir).rglob("*") if p.is_file()]

    results = []
    for path in targets:
        try:
            outcome = analyze(path)
        except Exception as exc:  # pragma: no‑cover
            # Log parsing errors but continue processing other files
            if not args.quiet:
                print(f"[ERROR] {path}: {exc}")
            continue

        results.append((path, outcome))

        # Console summary
        if not args.quiet:
            print(f"{path}: score={outcome['score']} verdict={outcome['verdict']}")

        # Generate reports based on flags or config
        want_md = args.report or ("markdown" in REPORT_FORMATS)
        want_json = args.json or ("json" in REPORT_FORMATS)

        if want_md:
            generate_report(path, outcome, fmt="markdown")
        if want_json:
            generate_report(path, outcome, fmt="json")

    # Exit code: 1 if any malicious verdict, else 0
    if any(r[1]["verdict"] == "malicious" for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
