from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import MAX_RESPONSE_BYTES, RANSOMWHERE_BASE

logger = logging.getLogger(__name__)

TTL_RANSOMWARE = 86400  # 24 hours
TTL_FEED = 3600  # 1 hour


async def check_ransomware_intel(
    bitcoin_address: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Look up a Bitcoin address against Ransomwhere for ransomware family attribution."""
    cache_key = f"ransomware:{bitcoin_address}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    result: dict = {
        "address": bitcoin_address,
        "family": "",
        "found": False,
        "transactions": 0,
        "entries": [],
    }

    try:
        resp = await client.get(
            f"{RANSOMWHERE_BASE}/lookup",
            params={"address": bitcoin_address},
        )

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("Ransomwhere response too large (Content-Length)")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("Ransomwhere response too large (actual body)")

        if resp.status_code == 200:
            body = resp.json()
            entries = body.get("result", [])

            if entries:
                result["found"] = True
                result["transactions"] = len(entries)

                # Use the first entry's family as the primary family
                first = entries[0]
                result["family"] = first.get("family", "")

                # Collect all entries with normalized timestamps
                for entry in entries[:20]:  # Cap at 20 entries
                    created_at = entry.get("createdAt")
                    dt_str = ""
                    if created_at:
                        try:
                            dt_str = datetime.fromtimestamp(
                                created_at / 1000, tz=timezone.utc
                            ).isoformat()
                        except (ValueError, OSError):
                            dt_str = str(created_at)

                    result["entries"].append(
                        {
                            "address": entry.get("address", ""),
                            "family": entry.get("family", ""),
                            "created_at": dt_str,
                            "usd_equivalent": entry.get("usd_equivalent", 0),
                        }
                    )
        elif resp.status_code == 404:
            pass  # Address not found — normal behavior

    except Exception as exc:
        logger.warning("Ransomwhere error for %s: %s", bitcoin_address, exc)

    await cache.set(cache_key, result, TTL_RANSOMWARE)
    return result


async def get_ransomware_feed(
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    """Fetch the latest ransomware address feed from Ransomwhere."""
    cache_key = "ransomware:feed"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        resp = await client.get(f"{RANSOMWHERE_BASE}/feed")

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("Ransomwhere feed too large (Content-Length)")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("Ransomwhere feed too large (actual body)")

        if resp.status_code == 200:
            body = resp.json()
            entries = body.get("result", [])

            feed: list[dict] = []
            for entry in entries[:100]:  # Cap at 100 entries
                created_at = entry.get("createdAt")
                dt_str = ""
                if created_at:
                    try:
                        dt_str = datetime.fromtimestamp(
                            created_at / 1000, tz=timezone.utc
                        ).isoformat()
                    except (ValueError, OSError):
                        dt_str = str(created_at)

                feed.append(
                    {
                        "address": entry.get("address", ""),
                        "family": entry.get("family", ""),
                        "created_at": dt_str,
                        "usd_equivalent": entry.get("usd_equivalent", 0),
                    }
                )

            await cache.set(cache_key, feed, TTL_FEED)
            return feed

    except Exception as exc:
        logger.warning("Ransomwhere feed error: %s", exc)

    return []
