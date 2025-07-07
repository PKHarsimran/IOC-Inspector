#!/usr/bin/env python3
"""
Shared logger for IOC Inspector
───────────────────────────────
• Console + rotating-file output
• Log level can be bumped via env  (LOG_LEVEL=DEBUG)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

# ──────────────────────────────────────────────────────────────────────────────
# Paths & formatting
# ──────────────────────────────────────────────────────────────────────────────
_LOG_DIR  = Path(__file__).with_name("logs")
_LOG_DIR.mkdir(exist_ok=True)
_LOG_FILE = _LOG_DIR / "ioc_inspector.log"

_FMT = logging.Formatter(
    "%(asctime)s  [%(levelname)s]  %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# honour env var, default INFO
_DEFAULT_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


# ──────────────────────────────────────────────────────────────────────────────
# Public helper
# ──────────────────────────────────────────────────────────────────────────────
def get_logger(name: str = "ioc_inspector") -> logging.Logger:
    """
    Return a configured logger.  Reuses existing handlers so every call is cheap.

    Parameters
    ----------
    name : str
        Logging namespace, usually `__name__`.
    """
    log = logging.getLogger(name)
    if log.handlers:           # already initialised → just return
        return log

    log.setLevel(_DEFAULT_LEVEL)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_FMT)
    log.addHandler(console)

    # Rotating-file handler (≈2 MB × 3 files)
    fileh = RotatingFileHandler(_LOG_FILE, maxBytes=2_000_000, backupCount=3)
    fileh.setFormatter(_FMT)
    log.addHandler(fileh)

    # Avoid duplicate logs if root logger configured elsewhere
    log.propagate = False
    return log
