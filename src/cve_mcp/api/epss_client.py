from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import TTL_EPSS, VulnCache
from cve_mcp.config import EPSS_BASE, MAX_RESPONSE_BYTES
from cve_mcp.models import EPSSScore

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 30


async def get_epss(
    cve_ids: list[str],
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[EPSSScore]:
    results: list[EPSSScore] = []
    uncached: list[str] = []

    for cve_id in cve_ids:
        key = f"epss:{cve_id}"
        cached = await cache.get(key)
        if cached:
            results.append(EPSSScore.model_validate(cached))
        else:
            uncached.append(cve_id)

    if not uncached:
        return results

    # Process in chunks of 30
    for i in range(0, len(uncached), _CHUNK_SIZE):
        chunk = uncached[i : i + _CHUNK_SIZE]
        cve_param = ",".join(chunk)
        try:
            resp = await client.get(
                EPSS_BASE,
                params={"cve": cve_param, "limit": len(chunk)},
            )
            resp.raise_for_status()

            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("EPSS response too large (Content-Length)")
            data_bytes = resp.content
            if len(data_bytes) > MAX_RESPONSE_BYTES:
                raise ValueError("EPSS response too large (actual body)")

            data = resp.json()
            for entry in data.get("data", []):
                score = EPSSScore.model_validate(entry)
                await cache.set(f"epss:{score.cve}", score.model_dump(), TTL_EPSS)
                results.append(score)

        except httpx.HTTPStatusError as exc:
            logger.error("EPSS query failed (HTTP %d): %s", exc.response.status_code, exc)
            raise
        except httpx.RequestError as exc:
            logger.error("EPSS network error: %s", exc)
            raise

    return results
