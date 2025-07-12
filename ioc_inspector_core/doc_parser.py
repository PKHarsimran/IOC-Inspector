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
from typing import Any, Dict, Set

from oletools.olevba import VBA_Parser, VBA_Scanner
from .macro_analyzer import analyze as analyze_macros
from logger import get_logger
from ioc_inspector_core.exceptions import ParserError

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
def parse_office(path: Path) -> Dict[str, Any]:
    """
    Parse a DOC/DOCX/DOCM/XLS*/RTF file and return IOC findings.
    Raises ParserError on any failure.
    """
    findings: Dict[str, Any] = {
        "type": "office",
        "urls": [],
        "ips": [],
        "macro": False,
        "suspicious_keywords": [],
    }

    # Try to open the file with oletools
    try:
        vb = VBA_Parser(str(path))
    except Exception as exc:
        log.error("Failed to open Office file %s: %s", path.name, exc)
        raise ParserError(f"Failed to open Office file {path}: {exc}") from exc

    try:
        # Detect whether any macros are present
        findings["macro"] = vb.detect_vba_macros()
        log.debug("%s – macro detected: %s", path.name, findings["macro"])

        if findings["macro"]:
            # Deep-dive VBA analysis (autoexec, obfuscation, etc.)
            findings.update(analyze_macros(str(path)))

            # Extract URLs, IPs, and suspicious keywords from each macro
            for (_, stream_path, vba_filename, vba_code) in vb.extract_macros():
                log.debug("Scanning macro %s", vba_filename)

                findings["urls"].extend(_extract_urls(vba_code))
                findings["ips"].extend(_extract_ips(vba_code))

                scanner = VBA_Scanner(vba_code)
                kw_hits = [kw for kw, _, _ in scanner.scan()]
                findings["suspicious_keywords"].extend(kw_hits)

    except Exception as exc:
        log.error("Error parsing Office file %s: %s", path.name, exc)
        raise ParserError(f"Error parsing Office file {path}: {exc}") from exc

    finally:
        vb.close()

    # Deduplicate & sort for stable output
    findings["urls"] = sorted(set(findings["urls"]))
    findings["ips"] = sorted(set(findings["ips"]))
    findings["suspicious_keywords"] = sorted(set(findings["suspicious_keywords"]))

    log.debug(
        "%s -> %d URLs, %d IPs, %d keywords",
        path.name,
        len(findings["urls"]),
        len(findings["ips"]),
        len(findings["suspicious_keywords"]),
    )

    return findings
