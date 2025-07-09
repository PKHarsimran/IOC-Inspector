"""
macro_analyzer.py
─────────────────
Deep-dive VBA inspection for Office documents.

*   Detects auto-exec triggers (AutoOpen, Document_Open, …)
*   Collects suspicious API calls (CreateObject, Shell, …)
*   Flags simple string-obfuscation via long Base-64 blobs
*   Notes whether the macro tries to drop a payload
*   Records module names & sizes for quick triage

Returned keys plug straight into the existing findings → heuristics →
report pipeline.
"""

from __future__ import annotations

import re
from oletools.olevba import VBA_Parser

# 100+ contiguous Base-64 chars (with up to two '=' padding chars)
_OBF_RE = r"[A-Za-z0-9+/]{100,}={0,2}"


def analyze(path: str) -> dict:
    vb = VBA_Parser(path)
    out: dict[str, object] = {
        "autoexec_funcs": set(),
        "suspicious_calls": set(),
        "string_obfuscation": 0,      # number of regex hits
        "has_drops_payload": False,
        "macro_modules": [],          # [{name, size}, …]
    }

    try:
        # ── Pass 1: holistic scan for auto-exec & suspicious keywords ──
        for kind, keyword, _ in vb.analyze_macros():
            if kind == "AutoExec":
                out["autoexec_funcs"].add(keyword)
            elif kind == "Suspicious":
                out["suspicious_calls"].add(keyword)

        # ── Pass 2: per-module heuristics ─────────────────────────────
        for (_, _, module_name, code) in vb.extract_macros():
            out["macro_modules"].append({"name": module_name, "size": len(code)})

            # 1) String-obfuscation (long Base-64)
            if re.search(_OBF_RE, code):
                out["string_obfuscation"] += 1

            # 2) Payload dropper heuristics (first hit wins)
            if (
                not out["has_drops_payload"]
                and any(tag in code.lower() for tag in ("urldownloadtofile", "adodb.stream"))
            ):
                out["has_drops_payload"] = True
    finally:
        vb.close()

    # Normalise to JSON-friendly types
    out["autoexec_funcs"] = sorted(out["autoexec_funcs"])
    out["suspicious_calls"] = sorted(out["suspicious_calls"])
    return out
