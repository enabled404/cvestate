"""Async VulnCheck NVD2 client — transparent NVD fallback source.

VulnCheck mirrors the NIST NVD 2.0 feed ("NVD++") and serves single-CVE
lookups through its ``/v3/index/{index}`` API. The records it returns are
field-for-field compatible with NIST's official NVD 2.0 CVE objects, which
makes VulnCheck a drop-in fallback when the primary NIST NVD endpoint is
rate limited, throttled, or unreachable.

This module exposes :func:`fetch_cve_vulncheck`, which queries the VulnCheck
index for one CVE and returns the CVE record in the **same shape** that the
existing :mod:`cve_mcp.api.nvd_client` parser consumes — i.e. the object that
NIST places at ``response["vulnerabilities"][0]["cve"]``. VulnCheck wraps the
identical object as a bare element of its ``data`` array (no ``cve`` wrapper),
so this client unwraps ``data[0]`` and hands back a dict that
``CVERecord.model_validate(...)`` can ingest unchanged.

Design notes
------------
* The Bearer token is read from :data:`cve_mcp.config.VULNCHECK_TOKEN`. When no
  token is configured the client returns ``None`` immediately (graceful no-op)
  so callers can treat "no fallback configured" the same as "fallback found
  nothing".
* The endpoint base is :data:`cve_mcp.config.VULNCHECK_BASE`. The
  ``nist-nvd2`` index is the byte-shape-compatible NIST mirror; the
  ``vulncheck-nvd2`` index is VulnCheck's enriched variant. Both return the
  standard NVD 2.0 fields the existing parser needs (id, descriptions,
  metrics, weaknesses, configurations, references, published, lastModified,
  vulnStatus, sourceIdentifier), so either configured base works as a
  fallback.
* Network / auth / rate-limit failures (timeout, 401, 403, 429, 5xx, malformed
  JSON, oversized body) are handled gracefully: the function logs the reason
  and returns ``None`` instead of raising, so a failed fallback never breaks
  the caller's primary flow. 429 responses are retried with backoff.

API reference: https://docs.vulncheck.com/api/v3/indices
NVD 2.0 schema: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from cve_mcp.cache.sqlite_cache import TTL_CVE, VulnCache
from cve_mcp.config import (
    MAX_RESPONSE_BYTES,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    VULNCHECK_BASE,
    VULNCHECK_TOKEN,
)
from cve_mcp.utils.validators import normalize_cve, sanitize_url_for_log

logger = logging.getLogger(__name__)

# Backoff schedule (seconds) used for retryable VulnCheck responses (429/5xx).
# Community tier allows 1,000 req/min, so short backoffs are sufficient.
_RETRY_DELAYS: list[float] = [2.0, 4.0, 8.0]


def _headers() -> dict[str, str]:
    """Build request headers including the Bearer authorization token."""
    return {
        "Authorization": f"Bearer {VULNCHECK_TOKEN}",
        "Accept": "application/json",
    }


def _extract_cve_record(payload: dict) -> dict | None:
    """Return the NVD-2.0-shaped CVE object from a VulnCheck envelope.

    VulnCheck wraps results as::

        {"_meta": {...}, "data": [ <cve-object>, ... ]}

    where each ``data`` element is the same object NIST nests under
    ``vulnerabilities[i]["cve"]``. For a single-CVE ``?cve=`` query there is at
    most one element. Returns the first record, or ``None`` when the index has
    no match for the requested CVE.
    """
    if not isinstance(payload, dict):
        return None

    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return None

    record = data[0]
    # Some index variants may still nest the object under a "cve" key; unwrap
    # defensively so the returned dict is always the bare NVD 2.0 CVE object.
    if isinstance(record, dict) and "cve" in record and isinstance(record["cve"], dict):
        record = record["cve"]

    if not isinstance(record, dict) or not record.get("id"):
        return None

    return record


async def fetch_cve_vulncheck(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache | None = None,
) -> dict | None:
    """Fetch a single CVE from VulnCheck as an NVD fallback.

    Parameters
    ----------
    cve_id:
        The CVE identifier (e.g. ``"CVE-2024-23334"``). It is normalized and
        validated; an invalid identifier yields ``None``.
    client:
        A shared :class:`httpx.AsyncClient` (typically ``AppContext.client``).
    cache:
        Optional :class:`~cve_mcp.cache.sqlite_cache.VulnCache`. When supplied,
        successful lookups are cached for ``TTL_CVE`` and served from cache on
        subsequent calls.

    Returns
    -------
    dict | None
        The CVE record in NIST NVD 2.0 shape (the object normally found at
        ``response["vulnerabilities"][0]["cve"]``), suitable for
        ``CVERecord.model_validate(...)``. Returns ``None`` when no token is
        configured, the CVE is invalid, the lookup finds nothing, or any
        network/auth/rate-limit/parse error occurs.
    """
    # Graceful no-op when the fallback source is not configured.
    if not VULNCHECK_TOKEN:
        logger.debug("VulnCheck fallback skipped: VULNCHECK_TOKEN not set")
        return None

    normalized = normalize_cve(cve_id)
    if normalized is None:
        logger.debug("VulnCheck fallback skipped: invalid CVE id %r", cve_id)
        return None

    cache_key = f"vulncheck:cve:{normalized}"
    if cache is not None:
        cached = await cache.get(cache_key)
        if cached:
            logger.debug("VulnCheck cache hit for %s", normalized)
            return cached  # type: ignore[return-value]

    params = {"cve": normalized}
    log_url = sanitize_url_for_log(f"{VULNCHECK_BASE}?cve={normalized}")
    logger.debug("VulnCheck fetch: %s", log_url)

    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(
                VULNCHECK_BASE,
                params=params,
                headers=_headers(),
                timeout=REQUEST_TIMEOUT,
            )

            status = resp.status_code

            # Auth failures are not retryable and indicate a bad/expired token.
            if status in (401, 403):
                logger.warning(
                    "VulnCheck auth failed (HTTP %d) for %s — check VULNCHECK_TOKEN "
                    "(community tokens expire after 30 days of inactivity)",
                    status,
                    normalized,
                )
                return None

            # Rate limit / transient server errors are retryable with backoff.
            if status == 429 or 500 <= status < 600:
                delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
                logger.warning(
                    "VulnCheck transient error (HTTP %d) for %s, retry %d/%d after %.0fs",
                    status,
                    normalized,
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
                )
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    continue
                logger.warning(
                    "VulnCheck gave up after %d attempts (HTTP %d) for %s",
                    MAX_RETRIES,
                    status,
                    normalized,
                )
                return None

            # 404 — index has no such CVE; treat as "not found", not an error.
            if status == 404:
                logger.debug("VulnCheck has no record for %s (HTTP 404)", normalized)
                return None

            resp.raise_for_status()

            # Guard against oversized bodies before parsing JSON.
            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                logger.warning("VulnCheck response too large (Content-Length) for %s", normalized)
                return None
            if len(resp.content) > MAX_RESPONSE_BYTES:
                logger.warning("VulnCheck response too large (body) for %s", normalized)
                return None

            payload = resp.json()
            record = _extract_cve_record(payload)
            if record is None:
                logger.debug("VulnCheck returned no usable record for %s", normalized)
                return None

            if cache is not None:
                await cache.set(cache_key, record, TTL_CVE)

            logger.info("VulnCheck fallback resolved %s", normalized)
            return record

        except httpx.TimeoutException as exc:
            delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
            logger.warning(
                "VulnCheck timeout for %s, retry %d/%d: %s",
                normalized,
                attempt + 1,
                MAX_RETRIES,
                exc,
            )
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
                continue
            return None

        except httpx.RequestError as exc:
            delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
            logger.warning(
                "VulnCheck network error for %s, retry %d/%d: %s",
                normalized,
                attempt + 1,
                MAX_RETRIES,
                exc,
            )
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
                continue
            return None

        except (ValueError, KeyError, TypeError) as exc:
            # JSON decode error or unexpected structure — not retryable.
            logger.warning("VulnCheck parse error for %s: %s", normalized, exc)
            return None

    return None
