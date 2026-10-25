#!/usr/bin/env python3
"""
Shared logger for IOC Inspector
───────────────────────────────
• Console + rotating-file output
• Raise verbosity with  LOG_LEVEL=DEBUG   or   --debug flag
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

# ─────────────────────────────────────────────────────────────────────────────
# Paths & formatting
# ─────────────────────────────────────────────────────────────────────────────
LOG_DIR   = Path(os.getenv("LOG_DIR", "logs")).resolve()
LOG_FILE  = LOG_DIR / "ioc_inspector.log"
LOG_DIR.mkdir(parents=True, exist_ok=True)

_FMT = logging.Formatter(
    fmt="%(asctime)s  [%(levelname)s]  %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Honour env var, default INFO
_DEFAULT_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
_LOGGERS: dict[str, logging.Logger] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Public helper
# ─────────────────────────────────────────────────────────────────────────────
def get_logger(name: str = "ioc_inspector") -> logging.Logger:
    """
    Return (and cache) a configured logger.

    Parameters
    ----------
    name : str
        Logging namespace—usually just `__name__`.
    """
    log = logging.getLogger(name)
    _LOGGERS[name] = log
    if log.handlers:            # already initialised -> reuse
        return log

    log.setLevel(_DEFAULT_LEVEL)

    # ▸ Console
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(_FMT)
    log.addHandler(stream)

    # ▸ Rotating file  (≈2 MB × 3 files)
    fileh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=int(os.getenv("LOG_MAX_BYTES", 2_000_000)),
        backupCount=int(os.getenv("LOG_BACKUP_COUNT", 3)),
    )
    fileh.setFormatter(_FMT)
    log.addHandler(fileh)

    # Prevent double-logging if root configured elsewhere
    log.propagate = True
    return log


def configure_logging(
    *, quiet: bool = False, debug: bool = False, console_level: str | None = None,
) -> None:
    """Apply CLI verbosity to all project loggers and console handlers."""
    level = "DEBUG" if debug else _DEFAULT_LEVEL
    for log in _LOGGERS.values():
        log.setLevel(level)
        for handler in log.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler
            ):
                handler.setLevel("ERROR" if quiet else console_level or level)
