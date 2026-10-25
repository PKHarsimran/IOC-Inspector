"""Serialize reputation requests and space their start times across threads."""

from __future__ import annotations

import time
from contextlib import contextmanager
from threading import Lock
from typing import Iterator


class RateLimiter:
    def __init__(self) -> None:
        self._lock = Lock()
        self._last_request: float | None = None

    @contextmanager
    def request(self, interval: float) -> Iterator[None]:
        with self._lock:
            if self._last_request is not None:
                delay = interval - (time.monotonic() - self._last_request)
                if delay > 0:
                    time.sleep(delay)
            self._last_request = time.monotonic()
            yield
