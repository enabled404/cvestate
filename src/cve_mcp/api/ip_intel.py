from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import (
    ABUSEIPDB_BASE,
    ABUSEIPDB_KEY,
    GREYNOISE_API_KEY,
    GREYNOISE_BASE,
)

logger = logging.getLogger(__name__)
TTL_IP = 3600  # 1 hour


async def check_ip_reputation(ip: str, client: httpx.AsyncClient, cache: VulnCache) -> dict:
    cache_key = f"ip:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    result = {
        "ip": ip,
        "abuse_score": 0,
        "country_code": "",
        "isp": "",
        "is_tor": False,
        "total_reports": 0,
        "noise": False,
        "riot": False,
        "classification": "",
        "noise_name": "",
        "abuseipdb_checked": False,
        "greynoise_checked": False,
    }

    # AbuseIPDB
    if ABUSEIPDB_KEY:
        try:
            resp = await client.get(
                f"{ABUSEIPDB_BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result.update(
                    {
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "country_code": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "is_tor": data.get("isTor", False),
                        "total_reports": data.get("totalReports", 0),
                        "abuseipdb_checked": True,
                    }
                )
        except Exception as exc:
            logger.warning("AbuseIPDB error for %s: %s", ip, exc)

    # GreyNoise (requires API key since /v3/community was deprecated Jan 2026)
    if GREYNOISE_API_KEY:
        try:
            resp = await client.get(
                f"{GREYNOISE_BASE}/ip/{ip}",
                headers={"key": GREYNOISE_API_KEY},
            )
            if resp.status_code == 200:
                gn = resp.json()
                result.update(
                    {
                        "noise": gn.get("noise", False),
                        "riot": gn.get("riot", False),
                        "classification": gn.get("classification", ""),
                        "noise_name": gn.get("name", ""),
                        "greynoise_checked": True,
                    }
                )
            elif resp.status_code == 404:
                result["greynoise_checked"] = True  # IP not seen by GreyNoise
        except Exception as exc:
            logger.warning("GreyNoise error for %s: %s", ip, exc)
    else:
        result["greynoise_checked"] = False
        result["greynoise"] = {
            "available": False,
            "message": "GREYNOISE_API_KEY not configured — get a free key at greynoise.io",
        }

    await cache.set(cache_key, result, TTL_IP)
    return result
