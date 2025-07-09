"""
IOC Inspector – central configuration
──────────────────────────────────────
• Pulls API keys & knobs from a local .env file (not committed)
• Defines heuristic weights and report formats
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ───────────────────────────────────────────────────────────────────────────────
# Environment
# -----------------------------------------------------------------------------
# Load variables from `.env` that sits in project root. Keys in the *real*
# environment always win (`override=False`).
# -----------------------------------------------------------------------------
load_dotenv(Path(__file__).with_name(".env"), override=False)

# ───────────────────────────────────────────────────────────────────────────────
# External API keys (required for reputation look-ups)
# -----------------------------------------------------------------------------
VT_API_KEY        = os.getenv("VT_API_KEY")        # VirusTotal
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") # AbuseIPDB

# ───────────────────────────────────────────────────────────────────────────────
# Heuristic scoring weights  (rough total ≈ 100)
# Adjust to fit your risk appetite.
# -----------------------------------------------------------------------------
RISK_WEIGHTS: dict[str, int] = {
    "macro":          25,  # any VBA macro present
    "autoexec": 15,  # AutoOpen / Document_Open, etc.
    "obfuscation":    20,  # base64 / XOR strings, etc.
    "susp_call": 5,  # CreateObject, Shell, URLDownloadToFile…
    "malicious_url":  30,  # VT vendors ≥ VT_THRESHOLD
    "malicious_ip":   25,  # AbuseIPDB confidence ≥ cutoff
}

# ───────────────────────────────────────────────────────────────────────────────
# Reputation-service thresholds
# -----------------------------------------------------------------------------
VT_THRESHOLD            = int(os.getenv("VT_THRESHOLD", 5))   # VT vendors
ABUSE_CONFIDENCE_CUTOFF = int(os.getenv("ABUSE_CONFIDENCE_CUTOFF", 70))  # %

# ───────────────────────────────────────────────────────────────────────────────
# Output formats written by default
# Can be overridden per run:  --report / --json flags
# -----------------------------------------------------------------------------
REPORT_FORMATS: list[str] = os.getenv(
    "REPORT_FORMATS", "markdown,json"
).split(",")

