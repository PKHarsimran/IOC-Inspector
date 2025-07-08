#!/usr/bin/env python3
"""
VirusTotal URL reputation
─────────────────────────
Takes a list of URLs -> returns:

    {
        "http://bad.com": {"vendors": 8, "malicious": True},
        ...
    }
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from typing import Dict, List

import requests

from logger import get_logger
from settings import VT_THRESHOLD

log = get_logger(__name__)

# --------------------------------------------------------------------------- #
# API config
# --------------------------------------------------------------------------- #
_VT_KEY = os.getenv("VT_API_KEY")
_ENDPOINT_SINGLE = "https://www.virustotal.com/api/v3/urls"
_RATE_PAUSE = 15                     # seconds (public key = 4 req/min)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _vt_url_id(url: str) -> str:
    """
    VirusTotal URL -> deterministic “URL ID” (sha256, base64url, no '=' pad).
    """
    digest = hashlib.sha256(url.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def lookup_urls(urls: List[str]) -> Dict[str, Dict[str, int | bool]]:
    """
    Perform VT look-ups; skip if no API key.

    Returns
    -------
    Dict[str, Dict]
        {url: {"vendors": int, "malicious": bool}}
    """
    out: Dict[str, Dict[str, int | bool]] = {}
    if not _VT_KEY or not urls:
        return out

    headers = {"x-apikey": _VT_KEY}

    for url in urls:
        url_id = _vt_url_id(url)
        try:
            r = requests.get(f"{_ENDPOINT_SINGLE}/{url_id}", headers=headers, timeout=15)
            if r.status_code != 200:
                log.debug("VT %s -> HTTP %s", url, r.status_code)
                continue

            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            vendors = stats.get("malicious", 0)
            out[url] = {
                "vendors": vendors,
                "malicious": vendors >= VT_THRESHOLD,
            }
            log.debug("VT %s -> %d malicious vendors", url, vendors)

            time.sleep(_RATE_PAUSE)  # stay within free-tier quota

        except Exception as exc:           # pragma: no cover
            log.exception("VT lookup error for %s: %s", url, exc)

    return out
