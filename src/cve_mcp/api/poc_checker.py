from __future__ import annotations

import asyncio
import csv
import io
import logging
from datetime import datetime, timezone

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import GITHUB_TOKEN

logger = logging.getLogger(__name__)

EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
NUCLEI_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_REPO_SEARCH_URL = "https://api.github.com/search/repositories"
MAX_EXPLOITDB_BYTES = 8 * 1024 * 1024  # 8 MB
TTL_POC = 3600
TTL_EXPLOITDB = 86400

_CONFIDENCE_LABEL_MAP = {
    "WEAPONIZED": "Weaponized exploit exists",
    "PUBLIC_EXPLOIT_REMOTE": "Public exploit available",
    "PUBLIC_EXPLOIT": "Exploit code available",
    "PUBLIC_POC_HIGH_QUALITY": "High-quality PoC exists",
    "PUBLIC_POC_LOW_QUALITY": "Low-quality PoC found",
    "NONE": "No public PoC found",
}


def _score_github_repo(repo: dict) -> int:
    score = 0
    stars = repo.get("stargazers_count", 0)
    if stars > 100:
        score += 3
    elif stars > 10:
        score += 2
    if not repo.get("fork", True):
        score += 2
    lang = repo.get("language") or ""
    if lang in [
        "Python",
        "C",
        "C++",
        "Ruby",
        "Go",
        "JavaScript",
        "TypeScript",
        "Rust",
        "Java",
        "PHP",
    ]:
        score += 1
    desc = (repo.get("description") or "").lower()
    if "exploit" in desc:
        score += 1
    if "poc" in desc:
        score += 1
    return score


async def _search_github_pocs(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    cache_key = f"poc:github:{cve_id}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    seen_ids: set[int] = set()
    all_repos: list[dict] = []

    queries = [
        {"q": cve_id, "sort": "stars", "order": "desc", "per_page": 20},
        {"q": f"{cve_id} exploit", "sort": "stars", "order": "desc", "per_page": 10},
    ]

    for params in queries:
        try:
            resp = await client.get(GITHUB_REPO_SEARCH_URL, params=params, headers=headers)
            if resp.status_code == 403:
                logger.warning("GitHub API rate limited during PoC search for %s", cve_id)
                continue
            if resp.status_code == 422:
                logger.warning("GitHub search validation error for %s", cve_id)
                continue
            resp.raise_for_status()
            data = resp.json()
            for repo in data.get("items", []):
                repo_id = repo.get("id")
                if repo_id and repo_id not in seen_ids:
                    seen_ids.add(repo_id)
                    all_repos.append(repo)
        except httpx.HTTPStatusError as exc:
            logger.error(
                "GitHub PoC search failed (HTTP %d) for %s",
                exc.response.status_code,
                cve_id,
            )
        except Exception as exc:
            logger.error("GitHub PoC search error for %s: %s", cve_id, exc)

    results = []
    for repo in all_repos:
        score = _score_github_repo(repo)
        if score >= 2:
            results.append(
                {
                    "name": repo.get("name", ""),
                    "full_name": repo.get("full_name", ""),
                    "html_url": repo.get("html_url", ""),
                    "stars": repo.get("stargazers_count", 0),
                    "description": (repo.get("description") or "")[:500],
                    "language": repo.get("language", ""),
                    "fork": repo.get("fork", False),
                    "score": score,
                }
            )

    await cache.set(cache_key, results, TTL_POC)
    return results


async def _get_exploitdb_csv(
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> str:
    cache_key = "exploitdb:csv"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        resp = await client.get(EXPLOITDB_CSV_URL, follow_redirects=True)
        resp.raise_for_status()

        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_EXPLOITDB_BYTES:
            logger.warning("ExploitDB CSV too large (%s bytes), skipping", content_length)
            return ""

        if len(resp.content) > MAX_EXPLOITDB_BYTES:
            logger.warning("ExploitDB CSV response body too large, skipping")
            return ""

        csv_text = resp.text
        await cache.set(cache_key, csv_text, TTL_EXPLOITDB)
        return csv_text
    except Exception as exc:
        logger.error("Failed to fetch ExploitDB CSV: %s", exc)
        return ""


async def _search_exploitdb(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    csv_text = await _get_exploitdb_csv(client, cache)
    if not csv_text:
        return []

    cve_upper = cve_id.upper()
    results = []

    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            codes_value = row.get("codes") or ""
            # codes are semicolon-separated (e.g. "CVE-2009-3699;OSVDB-58726")
            codes_list = [c.strip().upper() for c in codes_value.split(";") if c.strip()]
            if cve_upper in codes_list:
                results.append(
                    {
                        "id": row.get("id", ""),
                        "file": row.get("file", ""),
                        "description": row.get("description", ""),
                        "date_published": row.get("date_published", ""),
                        "author": row.get("author", ""),
                        "type": row.get("type", ""),
                        "platform": row.get("platform", ""),
                        "port": row.get("port", ""),
                    }
                )
    except Exception as exc:
        logger.error("Failed to parse ExploitDB CSV: %s", exc)

    return results


async def _search_nuclei_templates(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    cache_key = f"poc:nuclei:{cve_id}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    results = []
    try:
        resp = await client.get(
            NUCLEI_SEARCH_URL,
            params={"q": f"{cve_id} repo:projectdiscovery/nuclei-templates"},
            headers=headers,
        )
        if resp.status_code == 403:
            logger.warning("GitHub API rate limited during Nuclei search for %s", cve_id)
            await cache.set(cache_key, results, TTL_POC)
            return results
        if resp.status_code == 422:
            logger.warning("GitHub code search validation error for %s", cve_id)
            await cache.set(cache_key, results, TTL_POC)
            return results
        resp.raise_for_status()

        data = resp.json()
        for item in data.get("items", []):
            results.append(
                {
                    "name": item.get("name", ""),
                    "html_url": item.get("html_url", ""),
                    "path": item.get("path", ""),
                }
            )
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Nuclei template search failed (HTTP %d) for %s",
            exc.response.status_code,
            cve_id,
        )
    except Exception as exc:
        logger.error("Nuclei template search error for %s: %s", cve_id, exc)

    await cache.set(cache_key, results, TTL_POC)
    return results


def _determine_confidence(
    github_repos: list[dict],
    exploitdb_entries: list[dict],
    nuclei_templates: list[dict],
) -> str:
    if exploitdb_entries:
        return "PUBLIC_EXPLOIT_REMOTE"
    if github_repos and any(r.get("score", 0) >= 5 for r in github_repos):
        return "PUBLIC_EXPLOIT"
    if nuclei_templates or (github_repos and any(r.get("score", 0) >= 3 for r in github_repos)):
        return "PUBLIC_POC_HIGH_QUALITY"
    if github_repos:
        return "PUBLIC_POC_LOW_QUALITY"
    return "NONE"


async def search_poc_existence(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
    include_github: bool = True,
    include_exploitdb: bool = True,
) -> dict:
    cache_key = f"poc:exists:{cve_id}:{include_github}:{include_exploitdb}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    coroutines = []
    source_keys = []

    # Always include Nuclei
    coroutines.append(_search_nuclei_templates(cve_id, client, cache))
    source_keys.append("nuclei")

    if include_github:
        coroutines.append(_search_github_pocs(cve_id, client, cache))
        source_keys.append("github")

    if include_exploitdb:
        coroutines.append(_search_exploitdb(cve_id, client, cache))
        source_keys.append("exploitdb")

    raw_results = await asyncio.gather(*coroutines, return_exceptions=True)

    resolved: dict[str, list[dict]] = {}
    for key, result in zip(source_keys, raw_results, strict=False):
        if isinstance(result, BaseException):
            logger.warning("PoC source %s failed for %s: %s", key, cve_id, result)
            resolved[key] = []
        else:
            resolved[key] = result

    github_repos = resolved.get("github", [])
    exploitdb_entries = resolved.get("exploitdb", [])
    nuclei_templates = resolved.get("nuclei", [])

    confidence = _determine_confidence(github_repos, exploitdb_entries, nuclei_templates)

    result = {
        "cve_id": cve_id,
        "confidence": confidence,
        "confidence_label": _CONFIDENCE_LABEL_MAP[confidence],
        "github_results": github_repos,
        "exploitdb_results": exploitdb_entries,
        "nuclei_templates": nuclei_templates,
        "total_sources_found": len(github_repos) + len(exploitdb_entries) + len(nuclei_templates),
        "search_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    await cache.set(cache_key, result, TTL_POC)
    return result
