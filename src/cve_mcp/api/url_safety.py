from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import MAX_RESPONSE_BYTES, URLSCAN_BASE, URLSCAN_KEY

logger = logging.getLogger(__name__)

TTL_URL = 3600  # 1 hour


async def check_url_safety(
    url_or_domain: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Check a URL or domain against URLScan.io for safety verdicts."""
    cache_key = f"urlscan:{url_or_domain}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    result: dict = {
        "url": url_or_domain,
        "domain": "",
        "malicious": False,
        "score": 0,
        "categories": [],
        "screenshot": "",
        "results_count": 0,
        "scans": [],
    }

    # Build query — URLScan uses ElasticSearch query syntax
    # For domains, use the domain: prefix
    domain = url_or_domain
    if "://" in url_or_domain:
        # Extract domain from URL
        domain = url_or_domain.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    query = f"domain:{domain}"

    headers: dict[str, str] = {}
    if URLSCAN_KEY:
        headers["API-Key"] = URLSCAN_KEY

    try:
        resp = await client.get(
            f"{URLSCAN_BASE}/search/",
            params={"q": query, "size": 5},
            headers=headers,
        )

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("URLScan response too large (Content-Length)")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("URLScan response too large (actual body)")

        if resp.status_code == 200:
            body = resp.json()
            results = body.get("results", [])
            result["results_count"] = len(results)
            result["domain"] = domain

            for scan in results:
                page = scan.get("page", {})
                verdicts = scan.get("verdicts", {})
                overall = verdicts.get("overall", {})

                scan_entry = {
                    "url": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "asn": page.get("asn", ""),
                    "asnname": page.get("asnname", ""),
                    "malicious": overall.get("malicious", False),
                }
                result["scans"].append(scan_entry)

            # Use the first result's verdict as the overall verdict
            if results:
                first = results[0]
                first_verdicts = first.get("verdicts", {}).get("overall", {})
                result["malicious"] = first_verdicts.get("malicious", False)
                result["score"] = first_verdicts.get("score", 0)
                result["categories"] = first_verdicts.get("categories", [])
                result["screenshot"] = first.get("screenshot", "")

    except Exception as exc:
        logger.warning("URLScan.io error for %s: %s", url_or_domain, exc)

    await cache.set(cache_key, result, TTL_URL)
    return result
