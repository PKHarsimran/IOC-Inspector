"""
Office / RTF parser for IOC Inspector
─────────────────────────────────────
• Detects VBA macros via oletools.olevba
• Extracts URLs & IPs from macro code, OOXML text/links, and plain RTF
• Flags suspicious VBA keywords
Returns a dict compatible with heuristics.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from xml.etree import ElementTree
from zipfile import ZipFile, is_zipfile

from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools.rtfobj import is_rtf
from .macro_analyzer import analyze as analyze_macros
from logger import get_logger
from .exceptions import ParserError
from .indicators import extract_ips as _extract_ips, extract_urls as _extract_urls

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Document content
# --------------------------------------------------------------------------- #
def _document_text(path: Path) -> str:
    """Read OOXML text/relationship targets and plaintext RTF indicators."""
    if is_zipfile(path):
        parts: list[str] = []
        with ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith((".xml", ".rels")):
                    root = ElementTree.fromstring(archive.read(name))
                    parts.extend(root.itertext())
                    parts.extend(
                        node.attrib["Target"]
                        for node in root.iter()
                        if "Target" in node.attrib
                    )
        return " ".join(parts)
    if path.suffix.lower() == ".rtf":
        return path.read_bytes().decode("latin-1")
    return ""


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
        text = _document_text(path)
        findings["urls"].extend(_extract_urls(text))
        findings["ips"].extend(_extract_ips(text))

        # olevba explicitly rejects RTF; plain RTF has no VBA macros.
        if path.suffix.lower() == ".rtf" and is_rtf(text.encode("latin-1"), treat_str_as_data=True):
            findings["urls"] = sorted(set(findings["urls"]))
            findings["ips"] = sorted(set(findings["ips"]))
            return findings

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
                kw_hits = [keyword for kind, keyword, _ in scanner.scan() if kind == "Suspicious"]
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
