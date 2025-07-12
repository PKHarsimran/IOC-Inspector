"""
AbuseIPDB enrichment
────────────────────
Look up each extracted IP address and enrich with AbuseIPDB data.

Returns a dictionary:

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
from typing import Any, Dict, List, Union

import requests

from logger import get_logger
from settings import ABUSE_CONFIDENCE_CUTOFF

log = get_logger(__name__)

_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
_MAX_AGE = 90
_RATE_PAUSE = 1.2


def _fetch_abuse_data(ip: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "Key": _API_KEY}
    params: dict[str, Union[str, int]] = {
        "ipAddress": ip,
        "maxAgeInDays": _MAX_AGE,
    }

    response = requests.get(_ENDPOINT, headers=headers, params=params, timeout=10)

    if response.status_code != 200:
        log.warning("AbuseIPDB %s -> HTTP %s", ip, response.status_code)
        return {}

    return response.json().get("data", {})


def lookup_ips(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Look up and enrich IP addresses using AbuseIPDB.
    """
    if not _API_KEY:
        log.debug("No ABUSEIPDB_API_KEY provided; skipping IP enrichment.")
        return {}

    enriched_data: Dict[str, Dict[str, Any]] = {}

    for ip in ips:
        try:
            data = _fetch_abuse_data(ip)

            if not data:
                continue

            confidence = int(data.get("abuseConfidenceScore", 0))
            enriched_data[ip] = {
                "abuse_confidence": confidence,
                "total_reports": data.get("totalReports", 0),
                "categories": data.get("usageType", ""),
                "malicious": confidence >= ABUSE_CONFIDENCE_CUTOFF,
            }

            log.debug(
                "AbuseIPDB %s -> conf=%d, reports=%d",
                ip,
                confidence,
                enriched_data[ip]["total_reports"],
            )

        except requests.RequestException as exc:
            log.exception("AbuseIPDB request failed for %s: %s", ip, exc)

        except Exception as exc:
            log.exception("Unexpected error during AbuseIPDB enrichment for %s: %s", ip, exc)

        finally:
            time.sleep(_RATE_PAUSE)

    return enriched_data
