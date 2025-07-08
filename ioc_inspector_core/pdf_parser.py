#!/usr/bin/env python3
"""
PDF parser for IOC Inspector
────────────────────────────
• Extracts URLs & IPs
• Counts embedded files
• Detects JavaScript
• Compatible with PyMuPDF 1.18 → current
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

import fitz  # PyMuPDF

from logger import get_logger

log = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Regex helpers
# ──────────────────────────────────────────────────────────────────────────────
_URL_RE = re.compile(r"https?://[\w.%/+&=?#~@:!\-]+", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _clean_urls(urls: List[str]) -> List[str]:
    """Strip trailing punctuation & deduplicate."""
    return sorted({u.rstrip(").,;’\"") for u in urls})


# ──────────────────────────────────────────────────────────────────────────────
# PyMuPDF API shim helpers
# ──────────────────────────────────────────────────────────────────────────────
def _count_embedded_files(doc: "fitz.Document") -> int:
    """Handle API rename (embeddedFileCount -> embfile_count)."""
    try:
        return int(doc.embeddedFileCount)  # ≤ 1.23
    except AttributeError:
        return int(getattr(doc, "embfile_count", lambda: 0)())  # ≥ 1.24


def _detect_javascript(doc: "fitz.Document") -> int:
    """Return 1 if any JavaScript present, else 0."""
    if hasattr(doc, "is_scripted"):
        return int(doc.is_scripted) or 0
    # Fallback: brute-scan raw xref streams
    for xref in range(1, doc.xref_length()):
        try:
            if b"/JavaScript" in doc.xref_stream_raw(xref):
                return 1
        except Exception:  # pragma: no cover
            pass
    return 0


def _page_text(page: "fitz.Page") -> str:
    """
    Normalise PyMuPDF text extraction across versions:
        1.18  -> page.getText("text")
        1.23  -> page.get_text("text")
        1.24+ -> page.get_text()
    """
    if hasattr(page, "get_text"):
        try:
            return page.get_text()
        except TypeError:
            return page.get_text("text")
    return page.getText("text")  # legacy


# ──────────────────────────────────────────────────────────────────────────────
# Main parser
# ──────────────────────────────────────────────────────────────────────────────
def parse_pdf(path: Path) -> Dict:
    """
    Parse *path* and return IOC findings dictionary.
    """
    urls: List[str] = []

    doc = fitz.open(path)
    try:
        for page in doc:
            # hyperlinks
            urls += [l.get("uri") for l in page.get_links() if l.get("uri")]
            # regex scrape from visible text
            urls += _URL_RE.findall(_page_text(page))

        urls = _clean_urls(urls)
        ips = sorted(set(_IP_RE.findall(" ".join(urls))))

        findings: Dict = {
            "type": "pdf",
            "urls": urls,
            "ips": ips,
            "embedded_files": _count_embedded_files(doc),
            "js_count": _detect_javascript(doc),
        }

        log.debug(
            "%s: pages=%d  URLs=%d  IPs=%d  embeds=%d  js=%d",
            path.name,
            doc.page_count,
            len(urls),
            len(ips),
            findings["embedded_files"],
            findings["js_count"],
        )
        return findings

    finally:
        doc.close()
