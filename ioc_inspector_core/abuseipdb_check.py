"""
AbuseIPDB enrichment
────────────────────
Look up every extracted IP address and return:

    {
        "1.2.3.4": {
            "abuse_confidence": 90,
            "total_reports":    42,
            "malicious":        True,
            "categories":       "DDoS Attack"
        },
        ...
    }
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Any

import requests

from logger import get_logger
from settings import ABUSE_CONFIDENCE_CUTOFF

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# API config
# --------------------------------------------------------------------------- #
_API_KEY   = os.getenv("ABUSEIPDB_API_KEY")
_ENDPOINT  = "https://api.abuseipdb.com/api/v2/check"
_HEADERS   = {"Accept": "application/json", "Key": _API_KEY or ""}
_MAX_AGE   = 90         # days of report history to consider
_RATE_PAUSE = 1.2       # seconds between requests (public-key friendly)


# --------------------------------------------------------------------------- #
# Public helper
# --------------------------------------------------------------------------- #
def lookup_ips(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Enrich *ips* with AbuseIPDB data.

    Parameters
    ----------
    ips : List[str]
        List of IPv4/IPv6 strings.

    Returns
    -------
    Dict[str, Dict]
        Per-IP reputation details.  Empty dict if API key is missing.
    """
    if not _API_KEY:
        log.debug("No ABUSEIPDB_API_KEY; skipping IP enrichment")
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for ip in ips:
        params = {"ipAddress": ip, "maxAgeInDays": _MAX_AGE}
        try:
            r = requests.get(
                _ENDPOINT, headers=_HEADERS, params=params, timeout=10
            )
            if r.status_code != 200:
                log.warning("AbuseIPDB %s → HTTP %s", ip, r.status_code)
                continue
            data = r.json().get("data", {})
        except Exception as exc:  # pragma: no cover
            log.exception("AbuseIPDB look-up failed for %s: %s", ip, exc)
            continue

        conf = int(data.get("abuseConfidenceScore", 0))
        out[ip] = {
            "abuse_confidence": conf,
            "total_reports":    data.get("totalReports", 0),
            "categories":       data.get("usageType") or "",
            "malicious":        conf >= ABUSE_CONFIDENCE_CUTOFF,
        }

        log.debug("AbuseIPDB %s → conf=%d, reports=%s", ip, conf, data.get("totalReports"))
        time.sleep(_RATE_PAUSE)  # stay under free-tier limit

    return out
