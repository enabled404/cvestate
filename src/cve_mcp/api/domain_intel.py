from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import (
    CIRCL_PDNS_BASE,
    CIRCL_PDNS_PASS,
    CIRCL_PDNS_USER,
    CRTSH_BASE,
)

logger = logging.getLogger(__name__)
TTL_DOMAIN = 3600 * 6  # 6 hours


async def get_domain_intel(domain: str, client: httpx.AsyncClient, cache: VulnCache) -> dict:
    cache_key = f"domain:{domain}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    result = {"domain": domain, "certificates": [], "subdomains": [], "pdns_records": []}

    # crt.sh certificate transparency
    try:
        resp = await client.get(f"{CRTSH_BASE}/", params={"q": domain, "output": "json"})
        if resp.status_code == 200 and resp.content:
            certs = resp.json()[:50]  # cap at 50
            result["certificates"] = [
                {
                    "name": c.get("name_value", ""),
                    "issuer": c.get("issuer_name", ""),
                    "not_before": c.get("not_before", ""),
                    "not_after": c.get("not_after", ""),
                }
                for c in certs
            ]
            # Extract unique subdomains
            seen = set()
            for c in certs:
                for name in c.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen:
                        seen.add(name)
                        result["subdomains"].append(name)
            result["subdomains"] = result["subdomains"][:50]
    except Exception as exc:
        logger.warning("crt.sh error for %s: %s", domain, exc)

    # CIRCL PDNS (requires credentials)
    if CIRCL_PDNS_USER and CIRCL_PDNS_PASS:
        try:
            resp = await client.get(
                f"{CIRCL_PDNS_BASE}/{domain}",
                headers={"Accept": "application/json"},
                auth=(CIRCL_PDNS_USER, CIRCL_PDNS_PASS),
            )
            if resp.status_code == 200 and resp.content:
                lines = resp.text.strip().split("\n")
                import json

                records = []
                for line in lines[:20]:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
                result["pdns_records"] = records
        except Exception as exc:
            logger.warning("CIRCL PDNS error for %s: %s", domain, exc)

    await cache.set(cache_key, result, TTL_DOMAIN)
    return result


async def passive_dns_lookup(
    ip_or_domain: str, client: httpx.AsyncClient, cache: VulnCache
) -> dict | list[dict]:
    if not CIRCL_PDNS_USER or not CIRCL_PDNS_PASS:
        return {
            "error": "CIRCL PDNS requires credentials — contact https://www.circl.lu/contact/ to register",
            "results": [],
            "query": ip_or_domain,
        }

    cache_key = f"pdns:{ip_or_domain}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    try:
        resp = await client.get(
            f"{CIRCL_PDNS_BASE}/{ip_or_domain}",
            headers={"Accept": "application/json"},
            auth=(CIRCL_PDNS_USER, CIRCL_PDNS_PASS),
        )
        if resp.status_code == 200 and resp.content:
            import json

            records = []
            for line in resp.text.strip().split("\n")[:30]:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
            await cache.set(cache_key, records, TTL_DOMAIN)
            return records
    except Exception as exc:
        logger.warning("CIRCL PDNS lookup error for %s: %s", ip_or_domain, exc)
    return []
