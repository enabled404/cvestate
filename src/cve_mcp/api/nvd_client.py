from __future__ import annotations

import asyncio
import logging

import httpx

from cve_mcp.api.rate_limiter import TokenBucketRateLimiter
from cve_mcp.cache.sqlite_cache import TTL_CVE, TTL_SEARCH, VulnCache
from cve_mcp.config import (
    MAX_RESPONSE_BYTES,
    MAX_RETRIES,
    MAX_SEARCH_LIMIT,
    NVD_API_KEY,
    NVD_BASE,
)
from cve_mcp.models import CVERecord
from cve_mcp.utils.validators import sanitize_keyword, sanitize_url_for_log

logger = logging.getLogger(__name__)

_RETRY_DELAYS = [6.0, 12.0, 24.0]


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


async def validate_nvd_key(client: httpx.AsyncClient) -> None:
    if not NVD_API_KEY:
        logger.warning("NVD_API_KEY not set — using unauthenticated rate limit (5 req/30s)")
        return
    try:
        resp = await client.get(
            NVD_BASE,
            params={"resultsPerPage": 1},
            headers=_headers(),
        )
        if resp.status_code == 403:
            raise RuntimeError(
                "NVD API key is invalid or rejected (HTTP 403). Set a valid NVD_API_KEY."
            )
        logger.info("NVD API key validated (status %d)", resp.status_code)
    except httpx.RequestError as exc:
        logger.warning("Could not validate NVD key (network error): %s", exc)


async def fetch_cve(
    cve_id: str,
    client: httpx.AsyncClient,
    limiter: TokenBucketRateLimiter,
    cache: VulnCache,
) -> CVERecord | None:
    cache_key = f"cve:{cve_id}"
    cached = await cache.get(cache_key)
    if cached:
        return CVERecord.model_validate(cached)

    await limiter.acquire()

    url = NVD_BASE
    params = {"cveId": cve_id}

    log_url = sanitize_url_for_log(f"{url}?cveId={cve_id}")
    logger.debug("NVD fetch: %s", log_url)

    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(url, params=params, headers=_headers())

            if resp.status_code in (429, 503):
                delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
                logger.warning(
                    "NVD rate limited (HTTP %d), retry %d/%d after %.0fs",
                    resp.status_code,
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
                )
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    continue
                raise httpx.HTTPStatusError(
                    f"NVD rate limit (HTTP {resp.status_code})",
                    request=resp.request,
                    response=resp,
                )

            resp.raise_for_status()

            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("Response too large (Content-Length)")

            data_bytes = resp.content
            if len(data_bytes) > MAX_RESPONSE_BYTES:
                raise ValueError("Response too large (actual body)")

            data = resp.json()

            if data.get("totalResults", 0) == 0:
                return None

            cve_data = data["vulnerabilities"][0]["cve"]
            record = CVERecord.model_validate(cve_data)
            await cache.set(cache_key, cve_data, TTL_CVE)
            return record

        except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as exc:
            if attempt < MAX_RETRIES - 1 and isinstance(exc, (httpx.RequestError,)):
                delay = _RETRY_DELAYS[attempt]
                logger.warning("NVD request error, retry %d/%d: %s", attempt + 1, MAX_RETRIES, exc)
                await asyncio.sleep(delay)
                continue
            raise

    return None


async def search_nvd(
    query: str,
    severity: str,
    limit: int,
    client: httpx.AsyncClient,
    limiter: TokenBucketRateLimiter,
    cache: VulnCache,
) -> list[dict] | None:
    safe_query = sanitize_keyword(query)
    if safe_query is None:
        return None

    limit = min(limit, MAX_SEARCH_LIMIT)
    cache_key = f"search:{safe_query}:{severity}:{limit}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    await limiter.acquire()

    params: dict = {"keywordSearch": safe_query, "resultsPerPage": limit}
    if severity:
        params["cvssV3Severity"] = severity.upper()

    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(NVD_BASE, params=params, headers=_headers())

            if resp.status_code in (429, 503):
                delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    continue
                resp.raise_for_status()

            resp.raise_for_status()

            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("Response too large (Content-Length)")
            data_bytes = resp.content
            if len(data_bytes) > MAX_RESPONSE_BYTES:
                raise ValueError("Response too large (actual body)")

            data = resp.json()
            results = [v["cve"] for v in data.get("vulnerabilities", [])]
            await cache.set(cache_key, results, TTL_SEARCH)
            return results

        except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as exc:
            if attempt < MAX_RETRIES - 1 and isinstance(exc, httpx.RequestError):
                await asyncio.sleep(_RETRY_DELAYS[attempt])
                continue
            raise

    return []
