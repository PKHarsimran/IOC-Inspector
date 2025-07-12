"""
macro_analyzer.py
─────────────────
Deep-dive VBA inspection for Office documents.

* Detects auto-exec triggers (AutoOpen, Document_Open, …)
* Collects suspicious API calls (CreateObject, Shell, …)
* Flags simple string-obfuscation via long Base-64 blobs
* Notes whether the macro tries to drop a payload
* Records module names & sizes for quick triage

Returned keys plug straight into the existing findings → heuristics → report.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set

from oletools.olevba import VBA_Parser

# 100 + contiguous Base-64 chars (with up to two '=' padding chars)
_OBF_RE = r"[A-Za-z0-9+/]{100,}={0,2}"


def analyze(path: str | Path) -> Dict[str, object]:
    """
    Inspect the VBA inside an Office document and return structured findings.

    Parameters
    ----------
    path : str | Path
        Path to the DOC, DOCM, XLSM, etc. file.

    Returns
    -------
    dict
        {
            "autoexec_funcs": list[str],
            "suspicious_calls": list[str],
            "string_obfuscation": int,
            "has_drops_payload": bool,
            "macro_modules": list[dict[str, int]],
        }
    """
    vb = VBA_Parser(str(path))

    # Work with type-safe containers first …
    autoexec_funcs: Set[str] = set()
    suspicious_calls: Set[str] = set()
    macro_modules: List[Dict[str, int]] = []
    string_obfuscation: int = 0
    has_drops_payload: bool = False

    try:
        # ── Pass 1 : scan for auto-exec & suspicious keywords ──────────
        for kind, keyword, _ in vb.analyze_macros():
            if kind == "AutoExec":
                autoexec_funcs.add(keyword)
            elif kind == "Suspicious":
                suspicious_calls.add(keyword)

        # ── Pass 2 : per-module heuristics ────────────────────────────
        for (_, _, module_name, code) in vb.extract_macros():
            macro_modules.append({"name": module_name, "size": len(code)})

            # 1) String-obfuscation (long Base-64)
            if re.search(_OBF_RE, code):
                string_obfuscation += 1

            # 2) Payload-dropper heuristics (first hit wins)
            if (not has_drops_payload) and any(
                tag in code.lower() for tag in ("urldownloadtofile", "adodb.stream")
            ):
                has_drops_payload = True
    finally:
        vb.close()

    # ── Normalise sets → sorted lists for JSON-friendliness ───────────
    return {
        "autoexec_funcs": sorted(autoexec_funcs),
        "suspicious_calls": sorted(suspicious_calls),
        "string_obfuscation": string_obfuscation,
        "has_drops_payload": has_drops_payload,
        "macro_modules": macro_modules,
    }
