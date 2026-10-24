from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import SHODAN_BASE, SHODAN_KEY

logger = logging.getLogger(__name__)
TTL_SHODAN = 3600 * 12  # 12 hours


async def shodan_host_lookup(ip: str, client: httpx.AsyncClient, cache: VulnCache) -> dict | None:
    if not SHODAN_KEY:
        return {"error": "SHODAN_KEY not configured. Get a free API key at https://shodan.io"}

    cache_key = f"shodan:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    try:
        resp = await client.get(
            f"{SHODAN_BASE}/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
        )
        if resp.status_code == 404:
            return {"ip": ip, "found": False}
        resp.raise_for_status()
        data = resp.json()
        result = {
            "ip": ip,
            "found": True,
            "org": data.get("org", ""),
            "country_code": data.get("country_code", ""),
            "os": data.get("os", ""),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": list(data.get("vulns", {}).keys()),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", ""),
            "services": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport"),
                    "product": s.get("product", ""),
                    "version": s.get("version", ""),
                }
                for s in data.get("data", [])[:10]
            ],
        }
        await cache.set(cache_key, result, TTL_SHODAN)
        return result
    except httpx.HTTPStatusError as exc:
        logger.error("Shodan error for %s: HTTP %d", ip, exc.response.status_code)
        raise
    except Exception as exc:
        logger.error("Shodan error for %s: %s", ip, exc)
        raise
