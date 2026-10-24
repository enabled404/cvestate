from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    """Async token bucket rate limiter.

    Tokens refill at `rate` per second up to `capacity`.
    Each call to acquire() consumes one token, sleeping if the bucket is empty.
    """

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate  # tokens added per second
        self._capacity = capacity  # max token bucket size
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self._capacity,
            self._tokens + elapsed * self._rate,
        )
        self._last_refill = now

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) / self._rate
            await asyncio.sleep(wait)


class _NullLimiter:
    """Null-object rate limiter (plan 1.3).

    Implements the same async ``acquire()`` interface as
    :class:`TokenBucketRateLimiter` but never throttles. Useful where a limiter
    is structurally required but rate limiting is undesired (e.g. local-only
    endpoints, tests, or APIs with no published rate limit).
    """

    async def acquire(self) -> None:
        return
