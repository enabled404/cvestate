"""Async parallel API fan-out helpers (plan 6.3).

Many enrichment tools in this server query several upstream APIs (NVD, EPSS,
KEV, VirusTotal, VulnCheck, ...) to assemble a single answer. Issuing those
requests sequentially adds their latencies; issuing them concurrently bounds the
overall latency to roughly the slowest single call.

This module provides :func:`fan_out`, a small wrapper around
:func:`asyncio.gather` that:

* runs all supplied coroutines concurrently,
* never lets one failing coroutine abort the others
  (``return_exceptions=True``),
* converts any raised :class:`Exception` into ``None`` so callers get a clean
  ``list`` of results aligned positionally with the inputs,
* enforces a *global* timeout across the whole batch, and
* on a global timeout still returns a best-effort list of ``None`` values that
  matches the number of coroutines passed in, so partial results stay usable and
  callers can keep indexing into the result list without special-casing the
  timeout path.

``asyncio.timeout`` only exists on Python 3.11+. For Python 3.10 we fall back to
``asyncio.wait_for`` wrapping the gather, which yields equivalent semantics.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable
from typing import Any

__all__ = ["fan_out"]

# ``asyncio.timeout`` was added in Python 3.11. Detect once at import time so the
# hot path does not repeatedly re-check the interpreter version.
_HAS_ASYNCIO_TIMEOUT = sys.version_info >= (3, 11)


def _normalize(results: list[Any]) -> list[Any]:
    """Map any exception entry in *results* to ``None``, in place-safe fashion.

    ``asyncio.gather(..., return_exceptions=True)`` returns either a result or an
    ``Exception`` instance per coroutine. Callers of :func:`fan_out` expect plain
    values or ``None``, so collapse every exception (including
    :class:`asyncio.CancelledError`, which is a ``BaseException`` on 3.8+ and is
    handled explicitly below) into ``None``.
    """
    normalized: list[Any] = []
    for item in results:
        if isinstance(item, BaseException):
            normalized.append(None)
        else:
            normalized.append(item)
    return normalized


async def fan_out(*coros: Awaitable[Any], timeout: float = 20.0) -> list[Any]:
    """Run *coros* concurrently and return a positionally aligned result list.

    Each coroutine's successful result occupies the same index in the returned
    list as it had in the argument list. Any coroutine that raises an exception
    contributes ``None`` at its position instead of propagating the error.

    If the whole batch exceeds *timeout* seconds, a best-effort list of ``None``
    values with the same length as *coros* is returned so callers can still index
    into it safely (partial results are intentionally sacrificed for a
    predictable shape; individual per-coroutine results are not recoverable once
    the global timeout fires because the pending tasks are cancelled).

    Args:
        *coros: Awaitables (typically coroutine objects) to execute concurrently.
        timeout: Maximum number of seconds to wait for the entire batch. Must be
            positive; non-positive values are treated as "no timeout".

    Returns:
        A list of length ``len(coros)`` containing each coroutine's result or
        ``None`` for failures / timeout.
    """
    arity = len(coros)
    if arity == 0:
        return []

    # ``gather`` schedules the coroutines as tasks; we keep a reference so we can
    # ensure they are awaited/cancelled cleanly on the timeout path and avoid
    # "coroutine was never awaited" / "task was destroyed but pending" warnings.
    gathered = asyncio.gather(*coros, return_exceptions=True)

    # A non-positive timeout means "wait indefinitely".
    no_timeout = timeout is None or timeout <= 0

    try:
        if no_timeout:
            results = await gathered
        elif _HAS_ASYNCIO_TIMEOUT:
            async with asyncio.timeout(timeout):
                results = await gathered
        else:  # Python 3.10 fallback.
            results = await asyncio.wait_for(gathered, timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        # On timeout, ``asyncio.timeout`` cancels the inner gather; ``wait_for``
        # cancels and awaits the future for us. In both cases make sure the
        # gather future is finished so its child tasks are not left dangling.
        gathered.cancel()
        try:
            await gathered
        except (asyncio.CancelledError, asyncio.TimeoutError, TimeoutError):
            pass
        except Exception:
            # Any other error surfacing during cleanup is irrelevant; we are
            # already returning the all-None best-effort result.
            pass
        return [None] * arity

    return _normalize(results)
