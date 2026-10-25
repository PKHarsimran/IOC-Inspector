"""Shared extraction of HTTP(S) URLs and valid IPv4 addresses."""

from __future__ import annotations

import re
from ipaddress import IPv4Address

_URL_RE = re.compile(r"https?://[^\s<>\"\\{}]+", re.I)
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w)")


def extract_urls(text: str) -> set[str]:
    urls = set()
    for match in _URL_RE.findall(text):
        url = match.rstrip(".,;’'")
        # Preserve balanced parentheses in URLs, but remove prose delimiters.
        while url.endswith(")") and url.count(")") > url.count("("):
            url = url[:-1]
        urls.add(url)
    return urls


def extract_ips(text: str) -> set[str]:
    ips = set()
    for candidate in _IP_RE.findall(text):
        try:
            ips.add(str(IPv4Address(candidate)))
        except ValueError:
            continue
    return ips
