from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from ioc_inspector_core import rate_limit


def test_threaded_requests_are_spaced_even_after_failure(monkeypatch):
    now = [0.0]
    starts = []
    def sleep(delay):
        now[0] += delay
    monkeypatch.setattr(rate_limit, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep))
    limiter = rate_limit.RateLimiter()

    def fetch(index):
        with limiter.request(15):
            starts.append(now[0])
    with pytest.raises(ValueError):
        with limiter.request(15):
            starts.append(now[0])
            raise ValueError("failed request")
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(fetch, range(3)))
    assert starts == [0.0, 15.0, 30.0, 45.0]
