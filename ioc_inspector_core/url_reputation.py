"""
VirusTotal URL reputation
───────────────────────────
Takes a list of URLs -> returns:

    {
        "http://bad.com": {"vendors": 8, "malicious": True},
        ...
    }
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from typing import Dict, List, Union

import requests

from logger import get_logger
from settings import VT_THRESHOLD
from .rate_limit import RateLimiter
from .reputation_status import LookupStatuses, record

log = get_logger(__name__)

_ENDPOINT_SINGLE = "https://www.virustotal.com/api/v3/urls"
_RATE_PAUSE = 15  # seconds (public key = 4 req/min)
_LIMITER = RateLimiter()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _vt_url_id(url: str) -> str:
    """
    Encode the URL itself as unpadded base64url, as required by VT v3.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=128)
def _fetch_vt_report(url_id: str, api_key: str) -> requests.Response:
    headers = {"x-apikey": api_key}
    with _LIMITER.request(_RATE_PAUSE):
        return requests.get(f"{_ENDPOINT_SINGLE}/{url_id}", headers=headers, timeout=15)


def lookup_urls(
    urls: List[str], *, statuses: LookupStatuses | None = None,
) -> Dict[str, Dict[str, Union[int, bool]]]:
    """
    Perform VT look-ups; skip if no API key.

    Returns
    -------
    Dict[str, Dict]
        {url: {"vendors": int, "malicious": bool}}
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key or not urls:
        for url in urls:
            record(statuses, url, "skipped", "no_api_key")
        log.debug("No VT_API_KEY or URLs provided; skipping VT lookups.")
        return {}

    out: Dict[str, Dict[str, Union[int, bool]]] = {}
    for url in urls:
        url_id = _vt_url_id(url)
        try:
            r = _fetch_vt_report(url_id, api_key)
            if r.status_code != 200:
                record(statuses, url, "not_found" if r.status_code == 404 else "failed", f"http_{r.status_code}")
                log.debug("VT %s -> HTTP %s", url, r.status_code)
                continue

            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            vendors = int(stats["malicious"])
            if vendors < 0:
                raise ValueError("Negative vendor count")
            out[url] = {
                "vendors": vendors,
                "malicious": vendors >= VT_THRESHOLD,
            }
            record(statuses, url, "success")
            log.debug("VT %s -> %d malicious vendors", url, vendors)

        except requests.RequestException as exc:
            record(statuses, url, "failed", "request_error")
            log.warning("VT lookup failed for %s: %s", url, exc)
        except Exception as exc:
            record(statuses, url, "failed", "invalid_response")
            log.exception("VT lookup error for %s: %s", url, exc)

    return out
