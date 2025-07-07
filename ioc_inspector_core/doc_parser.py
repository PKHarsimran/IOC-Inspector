"""
Office / RTF parser for IOC Inspector
─────────────────────────────────────
• Detects VBA macros via oletools.olevba
• Extracts URLs & IPs from macro code
• Flags suspicious VBA keywords
Returns a dict compatible with heuristics.py
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set

from oletools.olevba import VBA_Parser, VBA_Scanner

from logger import get_logger

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Regex helpers
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"https?://[\w.%/+&=?#~@:!\-]+", re.I)
_IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_urls(text: str) -> Set[str]:
    return set(_URL_RE.findall(text))


def _extract_ips(text: str) -> Set[str]:
    return set(_IP_RE.findall(text))


# --------------------------------------------------------------------------- #
# Main function
# --------------------------------------------------------------------------- #
def parse_office(path: Path) -> Dict:
    """
    Parse a DOC/DOCX/DOCM/XLS*/RTF file and return IOC findings.
    """
    findings: Dict = {
        "type": "office",
        "urls": [],
        "ips": [],
        "macro": False,
        "suspicious_keywords": [],
    }

    log.debug("Opening %s with oletools", path.name)
    vb = VBA_Parser(str(path))

    try:
        findings["macro"] = vb.detect_vba_macros()
        log.debug("%s – macro detected: %s", path.name, findings["macro"])

        if findings["macro"]:
            # Iterate over each macro stream
            for (_, stream_path, vba_filename, vba_code) in vb.extract_macros():
                log.debug("Scanning macro %s", vba_filename)

                # IOC extraction
                findings["urls"].extend(_extract_urls(vba_code))
                findings["ips"].extend(_extract_ips(vba_code))

                # Keyword scan (simple heuristic)
                scanner = VBA_Scanner(vba_code)
                kw_hits = [kw for kw, _, _ in scanner.scan()]
                findings["suspicious_keywords"].extend(kw_hits)

    except Exception as exc:        # pragma: no cover
        log.exception("oletools error on %s: %s", path.name, exc)

    finally:
        vb.close()

    # Deduplicate & sort for stable output
    findings["urls"] = sorted(set(findings["urls"]))
    findings["ips"]  = sorted(set(findings["ips"]))
    findings["suspicious_keywords"] = sorted(set(findings["suspicious_keywords"]))

    log.debug(
        "%s → %d URLs, %d IPs, %d keywords",
        path.name,
        len(findings["urls"]),
        len(findings["ips"]),
        len(findings["suspicious_keywords"]),
    )
    return findings
