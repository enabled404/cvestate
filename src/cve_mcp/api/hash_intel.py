from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import (
    MALWAREBAZAAR_BASE,
    MAX_RESPONSE_BYTES,
    VIRUSTOTAL_BASE,
    VIRUSTOTAL_KEY,
)

logger = logging.getLogger(__name__)

TTL_HASH = 86400  # 24 hours


async def lookup_file_hash(
    hash_str: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Look up a file hash against MalwareBazaar and VirusTotal."""
    cache_key = f"hash:{hash_str}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    result: dict = {
        "hash": hash_str,
        "found": False,
        "file_name": "",
        "file_type": "",
        "malware_family": "",
        "tags": [],
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_undetected": 0,
        "vt_total": 0,
        "mb_checked": False,
        "vt_checked": False,
    }

    # ── MalwareBazaar (free, no key required) ───────────────────────────────
    try:
        resp = await client.post(
            f"{MALWAREBAZAAR_BASE}/",
            data={"query": "get_info", "hash": hash_str},
        )

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("MalwareBazaar response too large (Content-Length)")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("MalwareBazaar response too large (actual body)")

        if resp.status_code == 200:
            body = resp.json()
            result["mb_checked"] = True
            if body.get("query_status") == "ok" and body.get("data"):
                sample = body["data"][0]
                result["found"] = True
                result["file_name"] = sample.get("file_name", "")
                result["file_type"] = sample.get("file_type_mime", "")
                result["malware_family"] = sample.get("signature") or ""
                result["tags"] = sample.get("tags") or []
    except Exception as exc:
        logger.warning("MalwareBazaar error for %s: %s", hash_str, exc)

    # ── VirusTotal v3 (requires API key) ────────────────────────────────────
    if VIRUSTOTAL_KEY:
        try:
            resp = await client.get(
                f"{VIRUSTOTAL_BASE}/files/{hash_str}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
            )

            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("VirusTotal response too large (Content-Length)")
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise ValueError("VirusTotal response too large (actual body)")

            result["vt_checked"] = True
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                timeout = stats.get("timeout", 0)
                result["vt_malicious"] = malicious
                result["vt_suspicious"] = suspicious
                result["vt_undetected"] = undetected
                result["vt_total"] = malicious + suspicious + undetected + timeout
                result["found"] = True
                # Fill in file info from VT if MalwareBazaar didn't have it
                if not result["file_name"]:
                    result["file_name"] = attrs.get("meaningful_name", "")
                if not result["file_type"]:
                    result["file_type"] = attrs.get("type_description", "")
            elif resp.status_code == 404:
                pass  # Hash not found in VT — normal behavior
        except Exception as exc:
            logger.warning("VirusTotal error for %s: %s", hash_str, exc)

    await cache.set(cache_key, result, TTL_HASH)
    return result
