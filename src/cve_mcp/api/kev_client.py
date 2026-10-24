from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import TTL_KEV, VulnCache
from cve_mcp.config import CISA_KEV_URL, KEV_FALLBACK, MAX_RESPONSE_BYTES
from cve_mcp.models import KEVEntry

logger = logging.getLogger(__name__)


async def fetch_kev_catalog(
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[KEVEntry]:
    cache_key = "kev:catalog"
    cached = await cache.get(cache_key)
    if cached is not None:
        return [KEVEntry.model_validate(e) for e in cached]

    urls_to_try = [CISA_KEV_URL, KEV_FALLBACK]
    last_exc: Exception | None = None

    for url in urls_to_try:
        try:
            resp = await client.get(url)
            resp.raise_for_status()

            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("KEV response too large (Content-Length)")
            data_bytes = resp.content
            if len(data_bytes) > MAX_RESPONSE_BYTES:
                raise ValueError("KEV response too large (actual body)")

            data = resp.json()
            raw_entries = data.get("vulnerabilities", [])
            catalog = [KEVEntry.model_validate(e) for e in raw_entries]
            await cache.set(cache_key, [e.model_dump() for e in catalog], TTL_KEV)
            logger.info("KEV catalog loaded from %s (%d entries)", url, len(catalog))
            return catalog

        except Exception as exc:
            logger.warning("Failed to load KEV from %s: %s", url, exc)
            last_exc = exc
            continue

    logger.error("All KEV sources failed. Last error: %s", last_exc)
    return []


def lookup_kev(catalog: list[KEVEntry], cve_id: str) -> KEVEntry | None:
    return next((e for e in catalog if e.cveID == cve_id), None)
