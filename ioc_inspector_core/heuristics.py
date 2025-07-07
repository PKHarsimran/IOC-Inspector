"""
Heuristic scorer
────────────────
Combines static-analysis findings + reputation data → assigns
a 0-100 risk score and a verdict (benign · suspicious · malicious).
"""

from __future__ import annotations

from typing import Dict

from logger import get_logger
from settings import RISK_WEIGHTS, VT_THRESHOLD, ABUSE_CONFIDENCE_CUTOFF

log = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Core scoring
# --------------------------------------------------------------------------- #
def score(findings: Dict) -> Dict:
    """
    Mutate *findings* in-place, adding `score`, `verdict`, and `summary`.

    Returns the same dict for convenience.
    """
    total = 0
    reasons: list[str] = []

    # 1) Macro present
    if findings.get("macro"):
        total += RISK_WEIGHTS["macro"]
        reasons.append("macro detected")

    # 2) Suspicious VBA keywords
    kw = findings.get("suspicious_keywords", [])
    if kw:
        total += min(len(kw) * 2, 15)
        reasons.append("suspicious VBA keywords")

    # 3) Reputation – URLs
    for info in findings.get("url_rep", {}).values():
        if info.get("vendors", 0) >= VT_THRESHOLD:
            total += RISK_WEIGHTS["malicious_url"]
            reasons.append("malicious URL (VT)")

    # 4) Reputation – IPs
    for info in findings.get("ip_rep", {}).values():
        if info.get("abuse_confidence", 0) >= ABUSE_CONFIDENCE_CUTOFF:
            total += RISK_WEIGHTS["malicious_ip"]
            reasons.append("malicious IP (AbuseIPDB)")

    # 5) PDF-specific heuristics
    if findings.get("embedded_files", 0) > 0:
        total += 10
        reasons.append("embedded file(s)")
    if findings.get("js_count", 0) > 0:
        total += 10
        reasons.append("JavaScript in PDF")

    # Clamp to 100
    total = min(total, 100)

    # Verdict bands
    if total >= 70:
        verdict = "malicious"
    elif total >= 30:
        verdict = "suspicious"
    else:
        verdict = "benign"

    findings.update(
        score=total,
        verdict=verdict,
        summary=", ".join(reasons) if reasons else "No significant issues detected",
    )

    log.debug(
        "Scored %s → %s (%d)  /  reasons: %s",
        findings.get("name") or findings.get("type"),
        verdict,
        total,
        "; ".join(reasons) or "none",
    )
    return findings
