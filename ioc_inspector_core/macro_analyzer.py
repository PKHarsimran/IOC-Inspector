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
"""
Deep-dive VBA inspection for Office documents.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set

from oletools.olevba import VBA_Parser

_OBF_RE = r"[A-Za-z0-9+/]{100,}={0,2}"  # ≥100-char Base-64 blob


def analyze(path: str | Path) -> Dict[str, object]:
    """Return a structured summary of macro behaviour."""
    vb = VBA_Parser(str(path))

    autoexec_funcs: Set[str] = set()
    suspicious_calls: Set[str] = set()
    macro_modules: List[Dict[str, int]] = []
    string_obfuscation = 0
    has_drops_payload = False

    try:
        # ── pass 1: keyword scan ────────────────────────────────────────
        for kind, keyword, _ in vb.analyze_macros():
            if kind == "AutoExec":
                autoexec_funcs.add(keyword)
            elif kind == "Suspicious":
                suspicious_calls.add(keyword)

        # ── pass 2: per-module heuristics ──────────────────────────────
        for (_, _, module_name, code) in vb.extract_macros():
            macro_modules.append({"name": module_name, "size": len(code)})

            if re.search(_OBF_RE, code):
                string_obfuscation += 1

            if (not has_drops_payload) and any(
                tag in code.lower() for tag in ("urldownloadtofile", "adodb.stream")
            ):
                has_drops_payload = True
    finally:
        vb.close()

    return {
        "autoexec_funcs": sorted(autoexec_funcs),
        "suspicious_calls": sorted(suspicious_calls),
        "string_obfuscation": string_obfuscation,
        "has_drops_payload": has_drops_payload,
        "macro_modules": macro_modules,
    }

