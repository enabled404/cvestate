from __future__ import annotations

import logging

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import (
    MAX_RESPONSE_BYTES,
    REDHAT_SECURITY_BASE,
    UBUNTU_SECURITY_BASE,
)

logger = logging.getLogger(__name__)

TTL_ADVISORY = 14400  # 4 hours

# MSRC Security Update Guide API (SUG v2.0) — the CVRF base in config is for
# monthly documents; for per-CVE lookup the SUG vulnerability endpoint is used.
_MSRC_SUG_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"


async def _fetch_msrc(cve_id: str, client: httpx.AsyncClient) -> list[dict]:
    """Fetch Microsoft Security Response Center advisory data for a CVE."""
    try:
        resp = await client.get(
            _MSRC_SUG_URL,
            params={"$filter": f"cveNumber eq '{cve_id}'"},
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("MSRC response too large")

        data = resp.json()
        entries = data.get("value", [])
        results = []
        for entry in entries[:20]:
            results.append(
                {
                    "cve_id": entry.get("cveNumber", cve_id),
                    "title": entry.get("cveTitle", ""),
                    "severity": entry.get("severity", ""),
                    "impact": entry.get("impact", ""),
                    "product": entry.get("productTree", [{}])[0].get("name", "")
                    if entry.get("productTree")
                    else "",
                    "article_url": entry.get("articleUrl1", ""),
                    "kb_articles": entry.get("kbArticles", []),
                    "release_date": entry.get("releaseDate", ""),
                }
            )
        return results

    except httpx.HTTPStatusError as exc:
        logger.warning("MSRC query failed (HTTP %d) for %s", exc.response.status_code, cve_id)
        return []
    except Exception as exc:
        logger.warning("MSRC error for %s: %s", cve_id, exc)
        return []


async def _fetch_redhat(cve_id: str, client: httpx.AsyncClient) -> list[dict]:
    """Fetch Red Hat Security advisory data for a CVE."""
    try:
        resp = await client.get(
            f"{REDHAT_SECURITY_BASE}/cve/{cve_id}.json",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("Red Hat response too large")

        data = resp.json()
        results = []

        severity = data.get("threat_severity", "")
        public_date = data.get("public_date", "")
        bugzilla_url = data.get("bugzilla", {}).get("url", "")
        bugzilla_desc = data.get("bugzilla", {}).get("description", "")
        cvss3_score = data.get("cvss3", {}).get("cvss3_base_score", "")
        cvss3_vector = data.get("cvss3", {}).get("cvss3_scoring_vector", "")
        cwe = data.get("cwe", "")
        statement = data.get("statement", "")

        for release in data.get("affected_release", []):
            results.append(
                {
                    "product_name": release.get("product_name", ""),
                    "advisory": release.get("advisory", ""),
                    "package": release.get("package", ""),
                    "release_date": release.get("release_date", ""),
                    "cpe": release.get("cpe", ""),
                    "fixed_state": "affected",
                    "severity": severity,
                    "public_date": public_date,
                    "bugzilla_url": bugzilla_url,
                    "bugzilla_description": bugzilla_desc,
                    "cvss3_score": cvss3_score,
                    "cvss3_vector": cvss3_vector,
                    "cwe": cwe,
                }
            )

        # Also include package_state entries (not affected, will not fix, etc.)
        for pkg_state in data.get("package_state", []):
            results.append(
                {
                    "product_name": pkg_state.get("product_name", ""),
                    "advisory": "",
                    "package": pkg_state.get("package_name", ""),
                    "release_date": "",
                    "cpe": pkg_state.get("cpe", ""),
                    "fixed_state": pkg_state.get("fix_state", ""),
                    "severity": severity,
                    "public_date": public_date,
                    "bugzilla_url": bugzilla_url,
                    "bugzilla_description": bugzilla_desc,
                    "cvss3_score": cvss3_score,
                    "cvss3_vector": cvss3_vector,
                    "cwe": cwe,
                }
            )

        # If no affected_release, still return base info
        if not results and (severity or public_date):
            results.append(
                {
                    "product_name": "",
                    "advisory": "",
                    "package": "",
                    "release_date": "",
                    "cpe": "",
                    "severity": severity,
                    "public_date": public_date,
                    "bugzilla_url": bugzilla_url,
                    "bugzilla_description": bugzilla_desc,
                    "cvss3_score": cvss3_score,
                    "cvss3_vector": cvss3_vector,
                    "cwe": cwe,
                    "statement": statement,
                }
            )

        return results

    except httpx.HTTPStatusError as exc:
        logger.warning("Red Hat query failed (HTTP %d) for %s", exc.response.status_code, cve_id)
        return []
    except Exception as exc:
        logger.warning("Red Hat error for %s: %s", cve_id, exc)
        return []


async def _fetch_ubuntu(cve_id: str, client: httpx.AsyncClient) -> list[dict]:
    """Fetch Ubuntu Security advisory data for a CVE.

    Note: Ubuntu Security API is experimental and may change without notice.
    """
    try:
        resp = await client.get(
            f"{UBUNTU_SECURITY_BASE}/{cve_id}.json",
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("Ubuntu response too large")

        data = resp.json()
        results = []

        description = data.get("description", "")
        ubuntu_description = data.get("ubuntu_description", "")
        priority = data.get("priority", "")
        status_list = data.get("status", "")
        data.get("notes", [])
        references = data.get("references", [])
        bugs = data.get("bugs", [])
        data.get("patches", {})

        # Parse per-package status if available
        if isinstance(status_list, list):
            for status_entry in status_list:
                if isinstance(status_entry, dict):
                    results.append(
                        {
                            "package": status_entry.get("package", ""),
                            "release": status_entry.get("release", ""),
                            "status": status_entry.get("status", ""),
                            "description": description,
                            "priority": priority,
                        }
                    )
        elif isinstance(status_list, dict):
            # status can be dict keyed by package name
            for pkg_name, releases in status_list.items():
                if isinstance(releases, dict):
                    for release_name, status_info in releases.items():
                        status_val = (
                            status_info
                            if isinstance(status_info, str)
                            else status_info.get("status", "")
                        )
                        results.append(
                            {
                                "package": pkg_name,
                                "release": release_name,
                                "status": status_val,
                                "description": description,
                                "priority": priority,
                            }
                        )

        # If no per-package status, return base info
        if not results:
            results.append(
                {
                    "package": "",
                    "release": "",
                    "status": "",
                    "description": description,
                    "ubuntu_description": ubuntu_description,
                    "priority": priority,
                    "references": references[:10] if isinstance(references, list) else [],
                    "bugs": bugs[:10] if isinstance(bugs, list) else [],
                }
            )

        return results

    except httpx.HTTPStatusError as exc:
        logger.warning("Ubuntu query failed (HTTP %d) for %s", exc.response.status_code, cve_id)
        return []
    except Exception as exc:
        logger.warning("Ubuntu error for %s: %s", cve_id, exc)
        return []


async def get_vendor_advisory(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Fetch vendor advisories from Microsoft, Red Hat, and Ubuntu for a CVE.

    Returns a dict with cve_id and lists for microsoft, redhat, ubuntu results.
    """
    cache_key = f"advisory:{cve_id}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    import asyncio

    msrc_task = asyncio.create_task(_fetch_msrc(cve_id, client))
    redhat_task = asyncio.create_task(_fetch_redhat(cve_id, client))
    ubuntu_task = asyncio.create_task(_fetch_ubuntu(cve_id, client))

    msrc_results, redhat_results, ubuntu_results = await asyncio.gather(
        msrc_task, redhat_task, ubuntu_task
    )

    result = {
        "cve_id": cve_id,
        "microsoft": msrc_results,
        "redhat": redhat_results,
        "ubuntu": ubuntu_results,
    }

    await cache.set(cache_key, result, TTL_ADVISORY)
    return result
