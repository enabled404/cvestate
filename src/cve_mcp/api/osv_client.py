from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import TTL_OSV, VulnCache
from cve_mcp.config import MAX_RESPONSE_BYTES, OSV_BASE

logger = logging.getLogger(__name__)


async def query_package(
    name: str,
    ecosystem: str,
    version: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    cache_key = f"osv:{ecosystem}:{name}:{version}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    try:
        resp = await client.post(f"{OSV_BASE}/query", json=payload)
        resp.raise_for_status()

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("OSV response too large (Content-Length)")
        data_bytes = resp.content
        if len(data_bytes) > MAX_RESPONSE_BYTES:
            raise ValueError("OSV response too large (actual body)")

        data = resp.json()
        # OSV returns {"vulns": [...]} or {} when no results
        vulns = data.get("vulns", [])
        await cache.set(cache_key, vulns, TTL_OSV)
        return vulns

    except httpx.HTTPStatusError as exc:
        logger.error("OSV query failed (HTTP %d): %s", exc.response.status_code, exc)
        raise
    except httpx.RequestError as exc:
        logger.error("OSV network error: %s", exc)
        raise
