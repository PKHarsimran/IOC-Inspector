"""
ioc_inspector_core – dispatcher
────────────────────────────────
Routes a document to the right parser, enriches the extracted IOCs,
then produces a final risk score & verdict.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from logger import get_logger
from .pdf_parser import parse_pdf
from .doc_parser import parse_office
from .url_reputation import lookup_urls
from .abuseipdb_check import lookup_ips
from .heuristics import score as score_doc
from .exceptions import ParserError

log = get_logger(__name__)

# Supported Office / RTF extensions
_OFFICE_EXT: set[str] = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".rtf",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _enrich(findings: Dict) -> None:
    """Augment URLs & IPs with reputation data (modifies dict in-place)."""
    findings["url_rep"] = lookup_urls(findings.get("urls", []))
    findings["ip_rep"]  = lookup_ips(findings.get("ips",  []))
    log.debug(
        "Enrichment done – %d URL rep, %d IP rep",
        len(findings["url_rep"]),
        len(findings["ip_rep"]),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────
def analyze(path: Path) -> Dict:
    """
    Analyse *path* and return a fully-scored findings dict.

    Parameters
    ----------
    path : Path
        Document to scan.

    Returns
    -------
    Dict
        Parsed IOCs + enrichment + `score` / `verdict`.
    """
    suffix = path.suffix.lower()

    # ── Parse ──────────────────────────────────────────────────────────────
    try:
        if suffix == ".pdf":
            log.debug("Dispatch %s as PDF", path.name)
            findings = parse_pdf(path)
        elif suffix in _OFFICE_EXT:
            log.debug("Dispatch %s as Office/RTF", path.name)
            findings = parse_office(path)
        else:
            log.warning("Unsupported extension for %s", path.name)
            return {
                "type": "unsupported",
                "score": 0,
                "verdict": "unknown",
                "summary": f"Unsupported file extension: {suffix}",
            }

    # ── Enrichment ─────────────────────────────────────────────────────────
        _enrich(findings)

    # ── Score & verdict ────────────────────────────────────────────────────
        scored = score_doc(findings)
        log.info(
            "%s scored -> %s (%d)",
            path.name,
            scored["verdict"],
            scored["score"],
        )
        return scored

    except ParserError as exc:
        log.error("ParserError during analysis of %s: %s", path.name, exc)
        raise  # propagate further
