#!/usr/bin/env python3
"""
IOC Inspector – report writer
─────────────────────────────
• Markdown (human-readable)
• JSON    (machine-readable)

CSV export can be added later if needed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from logger import get_logger

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    """Return a GitHub-flavoured Markdown table."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate_report(path: Path, result: Dict, fmt: str = "markdown") -> None:
    """
    Write a report file for *path*.

    Parameters
    ----------
    path : Path
        Original document path.
    result : Dict
        Findings dict after heuristics scoring.
    fmt : str
        'markdown' (default) or 'json'.
    """
    stem = path.stem
    out_name = f"{stem}_report.{ 'md' if fmt == 'markdown' else 'json' }"
    out_path = REPORTS_DIR / out_name

    # ── JSON (machine-readable) ────────────────────────────────────────────
    if fmt == "json":
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        log.debug("Wrote JSON report → %s", out_path.relative_to(REPORTS_DIR.parent))
        return

    # ── Markdown (human-readable) ──────────────────────────────────────────
    lines: List[str] = []
    lines.append(f"# IOC Inspector Report – {path.name}\n")
    lines.append(
        f"**Verdict:** **{result['verdict'].upper()}**  \n"
        f"**Score:** {result['score']}\n"
    )

    if result.get("summary"):
        lines.append(f"> {result['summary']}\n")

    # URLs
    if result.get("urls"):
        rows = []
        for url in result["urls"]:
            rep = result.get("url_rep", {}).get(url, {})
            rows.append(
                [
                    f"`{url}`",
                    str(rep.get("vendors", 0)),
                    "⚠️" if rep.get("malicious") else "",
                ]
            )
        lines.append("\n### URLs\n")
        lines.append(_md_table(["URL", "VT vendors", "Flag"], rows))

    # IPs
    if result.get("ips"):
        rows = []
        for ip in result["ips"]:
            rep = result.get("ip_rep", {}).get(ip, {})
            rows.append(
                [
                    ip,
                    str(rep.get("abuse_confidence", 0)),
                    str(rep.get("total_reports", 0)),
                    "⚠️" if rep.get("malicious") else "",
                ]
            )
        lines.append("\n### IPs\n")
        lines.append(_md_table(["IP", "Confidence", "Reports", "Flag"], rows))

    # PDF-specific
    if result.get("type") == "pdf":
        lines.append(
            f"\n**Embedded files:** {result.get('embedded_files', 0)}  \n"
            f"**JavaScript objects:** {result.get('js_count', 0)}\n"
        )

    # Office macro info
    if result.get("macro"):
        kw = ", ".join(result.get("suspicious_keywords", []))
        lines.append(f"\n**Macros detected:** YES  \nSuspicious keywords: {kw}\n")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    log.debug("Wrote Markdown report -> %s", out_path.relative_to(REPORTS_DIR.parent))
