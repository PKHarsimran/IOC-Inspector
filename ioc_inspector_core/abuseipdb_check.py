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
from functools import lru_cache
from typing import Any, Dict, List, Union

import requests

from logger import get_logger
from settings import ABUSE_CONFIDENCE_CUTOFF
from .rate_limit import RateLimiter
from .reputation_status import LookupStatuses, record

log = get_logger(__name__)

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
_MAX_AGE = 90
_RATE_PAUSE = 1.2
_LIMITER = RateLimiter()


@lru_cache(maxsize=128)
def _fetch_abuse_data(ip: str, api_key: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "Key": api_key}
    params: dict[str, Union[str, int]] = {
        "ipAddress": ip,
        "maxAgeInDays": _MAX_AGE,
    }

    with _LIMITER.request(_RATE_PAUSE):
        response = requests.get(_ENDPOINT, headers=headers, params=params, timeout=10)

    if response.status_code != 200:
        log.warning("AbuseIPDB %s -> HTTP %s", ip, response.status_code)
        raise requests.HTTPError(f"HTTP {response.status_code}", response=response)

    return response.json().get("data", {})


def lookup_ips(
    ips: List[str], *, statuses: LookupStatuses | None = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Look up and enrich IP addresses using AbuseIPDB.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        for ip in ips:
            record(statuses, ip, "skipped", "no_api_key")
        log.debug("No ABUSEIPDB_API_KEY provided; skipping IP enrichment.")
        return {}

    enriched_data: Dict[str, Dict[str, Any]] = {}

    for ip in ips:
        try:
            data = _fetch_abuse_data(ip, api_key)

            if not data:
                raise ValueError("Empty AbuseIPDB response")

            confidence = int(data["abuseConfidenceScore"])
            if not 0 <= confidence <= 100:
                raise ValueError("Invalid abuse confidence")
            enriched_data[ip] = {
                "abuse_confidence": confidence,
                "total_reports": data.get("totalReports", 0),
                "categories": data.get("usageType", ""),
                "malicious": confidence >= ABUSE_CONFIDENCE_CUTOFF,
            }
            record(statuses, ip, "success")

            log.debug(
                "AbuseIPDB %s -> conf=%d, reports=%d",
                ip,
                confidence,
                enriched_data[ip]["total_reports"],
            )

        except requests.RequestException as exc:
            response = getattr(exc, "response", None)
            reason = f"http_{response.status_code}" if response is not None else "request_error"
            record(statuses, ip, "failed", reason)
            log.exception("AbuseIPDB request failed for %s: %s", ip, exc)

        except Exception as exc:
            record(statuses, ip, "failed", "invalid_response")
            log.exception("Unexpected error during AbuseIPDB enrichment for %s: %s", ip, exc)

    return enriched_data
