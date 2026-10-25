#!/usr/bin/env python3
"""
IOC Inspector – report writer
─────────────────────────────
• Markdown (human-readable)
• JSON    (machine-readable)
• CSV     (spreadsheet-friendly)
• JSONL   (one JSON object per line)
• HTML    (basic formatting)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

import jsonschema

from logger import get_logger

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports")).resolve()
REPORT_EXTENSIONS = {
    "markdown": "md", "json": "json", "csv": "csv", "jsonl": "jsonl", "html": "html",
}

# Load JSON schema for validation
SCHEMA_PATH = Path(__file__).with_name("report_schema.json")
with SCHEMA_PATH.open(encoding="utf-8") as fh:
    REPORT_SCHEMA = json.load(fh)

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


def _validate(data: Dict) -> None:
    """Validate report dict against the JSON schema."""
    jsonschema.validate(data, REPORT_SCHEMA)


def _lookup_status(result: dict, service: str, indicator: str, reputation: dict) -> str:
    info = result.get("enrichment", {}).get(service, {}).get("indicators", {}).get(indicator, {})
    if not info:
        return "success" if reputation else "not checked"
    reason = f" ({info['reason']})" if info.get("reason") else ""
    return info["status"] + reason


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate_report(
    path: Path, result: Dict, fmt: str = "markdown", *, output_stem: str | None = None,
    output_dir: Path | None = None,
) -> None:
    """
    Write a report file for *path*.

    Parameters
    ----------
    path : Path
        Original document path.
    result : Dict
        Findings dict after heuristics scoring.
    fmt : str
        'markdown' (default), 'json', 'csv', 'jsonl', or 'html'.
    output_stem : str | None
        Optional collision-free basename supplied by the batch CLI.
    output_dir : Path | None
        Output directory for this invocation, without changing global defaults.
    """
    if fmt not in REPORT_EXTENSIONS:
        raise ValueError(f"Unsupported report format: {fmt}")
    stem = output_stem or path.stem
    _validate(result)
    
    out_name = f"{stem}_report.{REPORT_EXTENSIONS[fmt]}"
    directory = output_dir if output_dir is not None else REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    out_path = directory / out_name

    # ── JSON (machine-readable) ────────────────────────────────────────────
    if fmt == "json":
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        log.debug("Wrote JSON report → %s", out_path)
        return

    if fmt == "jsonl":
        out_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
        log.debug("Wrote JSONL report → %s", out_path)
        return

    if fmt == "csv":
        import csv

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["field", "value"])
            for k, v in result.items():
                writer.writerow([k, json.dumps(v) if isinstance(v, (dict, list)) else v])
        log.debug("Wrote CSV report → %s", out_path)
        return


    # ── Markdown (human-readable) ──────────────────────────────────────────
    lines: List[str] = []
    lines.append(f"# IOC Inspector Report - {path.name}\n")
    lines.append(
        f"**Verdict:** **{result['verdict'].upper()}**  \n"
        f"**Score:** {result['score']}\n"
    )

    if result.get("summary"):
        lines.append(f"> {result['summary']}\n")

    if result.get("enrichment"):
        rows = []
        for service, info in result["enrichment"].items():
            rows.append([
                service, info["status"], info.get("reason") or "—",
                str(info.get("succeeded", 0)), str(info.get("failed", 0)),
                str(info.get("not_found", 0)), str(info.get("skipped", 0)),
            ])
        lines.append("\n### Reputation checks\n")
        lines.append(_md_table(["Service", "Status", "Reason", "Succeeded", "Failed", "Not found", "Skipped"], rows))

    # URLs
    if result.get("urls"):
        rows = []
        for url in result["urls"]:
            rep = result.get("url_rep", {}).get(url, {})
            rows.append(
                [
                    f"`{url}`",
                    str(rep.get("vendors", "not checked")),
                    _lookup_status(result, "virustotal", url, rep),
                    "⚠️" if rep.get("malicious") else "",
                ]
            )
        lines.append("\n### URLs\n")
        lines.append(_md_table(["URL", "VT vendors", "Lookup status", "Flag"], rows))

    # IPs
    if result.get("ips"):
        rows = []
        for ip in result["ips"]:
            rep = result.get("ip_rep", {}).get(ip, {})
            rows.append(
                [
                    ip,
                    str(rep.get("abuse_confidence", "not checked")),
                    str(rep.get("total_reports", "not checked")),
                    _lookup_status(result, "abuseipdb", ip, rep),
                    "⚠️" if rep.get("malicious") else "",
                ]
            )
        lines.append("\n### IPs\n")
        lines.append(_md_table(["IP", "Confidence", "Reports", "Lookup status", "Flag"], rows))

    # PDF-specific
    if result.get("type") == "pdf":
        lines.append(
            f"\n**Embedded files:** {result.get('embedded_files', 0)}  \n"
            f"**JavaScript objects:** {result.get('js_count', 0)}\n"
        )

    # Office-macro section
    if result.get("macro"):
        lines.append("\n### Macros\n")
        lines.append("**Detected:** YES  ")

        if result.get("autoexec_funcs"):
            lines.append(f"**Auto-exec triggers:** {', '.join(result['autoexec_funcs'])}  ")

        if result.get("suspicious_calls"):
            lines.append(
                f"**Suspicious calls:** {', '.join(result['suspicious_calls'])}  "
            )

        if result.get("string_obfuscation"):
            lines.append(
                f"**Obfuscation hits:** {result['string_obfuscation']}"
            )

        # keep keyword list for quick glance
        if result.get("suspicious_keywords"):
            kw = ", ".join(result["suspicious_keywords"])
            lines.append(f"\nSuspicious keywords: {kw}")

        lines.append("")  # blank line for spacing

    md_text = "\n".join(lines)

    if fmt == "html":
        escaped = md_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_text = f"<html><body><pre>{escaped}</pre></body></html>"
        out_path.write_text(html_text, encoding="utf-8")
        log.debug("Wrote HTML report -> %s", out_path)
        return

    out_path.write_text(md_text, encoding="utf-8")
    log.debug("Wrote Markdown report -> %s", out_path)


def generate_batch_report(
    records: list[dict], summary: dict, *, output_dir: Path,
    offline: bool, started_at: str, elapsed: float,
) -> Path:
    """Write one JSON manifest including findings, skips, and per-file errors."""
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / "batch_summary.json"
    payload = {
        "schema_version": 1, "started_at": started_at,
        "elapsed_seconds": round(elapsed, 3), "offline": offline,
        "summary": summary, "files": records,
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination
