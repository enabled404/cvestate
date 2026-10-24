"""Fixed-interval (deterministic) async retry helper for httpx requests.

This module provides :func:`get_with_fixed_retry`, a thin wrapper around
``httpx.AsyncClient.get`` that retries transient failures using a **constant**
wait between attempts rather than exponential backoff.

Why fixed-interval instead of exponential backoff?
--------------------------------------------------
Exponential backoff grows the wait after every failure (2s, 4s, 8s, ...), so
each retry "accumulates authority" over the schedule — later retries dominate
the total latency budget and the worst-case wall-clock time becomes hard to
bound and reason about. This helper deliberately uses **no authority
accumulation**: every retry waits exactly the same ``interval`` seconds. That
makes the timing fully deterministic and the worst-case added latency a simple,
predictable product::

    worst_case_added_latency = retries * interval

For example, ``retries=3, interval=2.0`` adds at most 6.0 seconds of sleeping
regardless of how many of the attempts fail. This predictability is preferable
for tools that run inside an MCP request with a tight, user-visible latency
budget, where an unbounded exponential schedule could blow past timeouts.

Retries are attempted on:

* :class:`httpx.TransportError` — connection/read/write/timeout-level transport
  failures (this is the base class for ``ConnectError``, ``ReadTimeout``,
  ``ConnectTimeout``, ``PoolTimeout``, etc.).
* :class:`httpx.HTTPStatusError` — raised by the ``raise_for_status()`` call on
  any 4xx/5xx response, so non-2xx responses are treated as retryable.

The last raised exception is re-raised once all attempts are exhausted, so
callers see the genuine underlying error instead of a synthetic one.

Call sites may override ``retries``/``interval``/``timeout`` with the project's
``config.MAX_RETRIES``/``config.REQUEST_TIMEOUT`` values; this module keeps
sensible standalone defaults and intentionally does not import ``config`` so it
stays free of project-wide import side effects.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Exceptions that are considered transient and therefore worth retrying.
# httpx.TransportError covers connection/timeout-level transport problems;
# httpx.HTTPStatusError is produced by raise_for_status() for 4xx/5xx replies.
_RETRYABLE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.TransportError,
    httpx.HTTPStatusError,
)


async def get_with_fixed_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 3,
    interval: float = 2.0,
    timeout: float = 30.0,
    **kwargs: Any,
) -> httpx.Response:
    """Perform an HTTP GET with deterministic fixed-interval retries.

    Each attempt issues ``client.get(url, timeout=timeout, **kwargs)`` and then
    calls :meth:`httpx.Response.raise_for_status`. On a retryable failure the
    coroutine sleeps for a **constant** ``interval`` seconds before the next
    attempt — there is no exponential growth ("no authority accumulation"), so
    the worst-case added latency is bounded by ``retries * interval``.

    Args:
        client: An open :class:`httpx.AsyncClient` used to issue the request.
        url: The absolute URL to GET. Host allow-listing / validation is the
            caller's responsibility (see ``utils.validators``).
        retries: Number of *additional* attempts after the first one. With the
            default of ``3`` the request is tried up to ``1 + 3 = 4`` times.
            Values ``<= 0`` mean "try exactly once, never retry". Pass
            ``config.MAX_RETRIES`` here to honour the project configuration.
        interval: Constant number of seconds to sleep between attempts. There is
            no backoff multiplier; every wait is identical.
        timeout: Per-attempt request timeout in seconds, forwarded to
            ``client.get``. Pass ``config.REQUEST_TIMEOUT`` here to honour the
            project configuration.
        **kwargs: Extra keyword arguments forwarded verbatim to
            ``client.get`` (e.g. ``headers``, ``params``, ``follow_redirects``).

    Returns:
        The successful :class:`httpx.Response` (already validated by
        ``raise_for_status``, so its status is 2xx/3xx).

    Raises:
        httpx.HTTPStatusError: If the final attempt returned a 4xx/5xx status.
        httpx.TransportError: If the final attempt failed at the transport
            level. The exact subclass of the *last* failure is propagated.
        Exception: Any non-retryable exception raised by ``client.get`` is
            propagated immediately without being retried.
    """
    # Total number of attempts is the first try plus the retry budget.
    # A non-positive retry budget collapses to a single attempt.
    total_attempts = 1 + max(retries, 0)
    last_exc: BaseException | None = None

    for attempt in range(1, total_attempts + 1):
        try:
            response = await client.get(url, timeout=timeout, **kwargs)
            # Treat any 4xx/5xx as a retryable failure by surfacing it as an
            # httpx.HTTPStatusError, which our except clause below catches.
            response.raise_for_status()
            return response
        except _RETRYABLE_EXCEPTIONS as exc:
            last_exc = exc
            if attempt < total_attempts:
                logger.warning(
                    "GET attempt %d/%d failed (%s: %s); retrying in %.1fs",
                    attempt,
                    total_attempts,
                    type(exc).__name__,
                    exc,
                    interval,
                )
                # Constant wait — deterministic, no exponential growth.
                await asyncio.sleep(interval)
            else:
                logger.warning(
                    "GET attempt %d/%d failed (%s: %s); no retries left",
                    attempt,
                    total_attempts,
                    type(exc).__name__,
                    exc,
                )

    # All attempts exhausted: re-raise the genuine last error. ``last_exc`` is
    # guaranteed to be set because the loop ran at least once and either
    # returned or recorded the exception.
    assert last_exc is not None  # for type-checkers; loop always populates it
    raise last_exc
