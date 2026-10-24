from __future__ import annotations

import json
import logging
import re

import defusedxml.ElementTree as ET
import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import GITHUB_TOKEN, MAX_RESPONSE_BYTES, OSV_BASE

logger = logging.getLogger(__name__)

TTL_DEP_SCAN = 1800  # 30 minutes
_MAX_BATCH = 1000  # OSV batch limit per request


# ── Format Parsers ──────────────────────────────────────────────────────────


def _parse_requirements_txt(text: str) -> list[dict]:
    """Parse pip requirements.txt lines like 'requests==2.28.0' or 'flask>=2.0'."""
    results: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match: name (==|>=|<=|~=|!=|>|<) version
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~]+)\s*([A-Za-z0-9_.\-\*]+)", line)
        if m:
            results.append(
                {
                    "name": m.group(1).strip(),
                    "ecosystem": "PyPI",
                    "version": m.group(3).strip(),
                }
            )
        else:
            # Bare package name without version
            bare = re.match(r"^([A-Za-z0-9_.\-]+)\s*$", line)
            if bare:
                results.append(
                    {
                        "name": bare.group(1).strip(),
                        "ecosystem": "PyPI",
                        "version": "",
                    }
                )
    return results


def _parse_package_json(text: str) -> list[dict]:
    """Parse package.json dependencies and devDependencies."""
    results: list[dict] = []
    try:
        pkg = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return results

    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = pkg.get(key, {})
        if not isinstance(deps, dict):
            continue
        for name, ver_spec in deps.items():
            # Strip semver range prefixes: ^, ~, >=, <=, >, <, =
            version = re.sub(r"^[\^~>=<\s]+", "", str(ver_spec)).strip()
            # Handle "latest", "*", or empty
            if version in ("*", "latest", ""):
                version = ""
            results.append(
                {
                    "name": name,
                    "ecosystem": "npm",
                    "version": version,
                }
            )
    return results


def _parse_pom_xml(text: str) -> list[dict]:
    """Parse Maven pom.xml <dependency> blocks."""
    results: list[dict] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return results

    # Handle Maven namespace
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    ns = ns_match.group(1) if ns_match else ""
    prefix = f"{{{ns}}}" if ns else ""

    for dep in root.iter(f"{prefix}dependency"):
        group_id = dep.findtext(f"{prefix}groupId", "").strip()
        artifact_id = dep.findtext(f"{prefix}artifactId", "").strip()
        version = dep.findtext(f"{prefix}version", "").strip()
        if group_id and artifact_id:
            # Skip property references like ${project.version}
            if version.startswith("${"):
                version = ""
            results.append(
                {
                    "name": f"{group_id}:{artifact_id}",
                    "ecosystem": "Maven",
                    "version": version,
                }
            )
    return results


def _parse_generic_lines(text: str) -> list[dict]:
    """Parse generic 'name:ecosystem:version' lines."""
    results: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            results.append(
                {
                    "name": parts[0].strip(),
                    "ecosystem": parts[1].strip(),
                    "version": parts[2].strip(),
                }
            )
    return results


def parse_dependency_list(raw_text: str) -> list[dict]:
    """Auto-detect format and parse dependency list into [{name, ecosystem, version}].

    Supported formats:
      - requirements.txt (pip)
      - package.json (npm)
      - pom.xml (Maven)
      - generic "name:ecosystem:version" lines
    """
    MAX_INPUT_SIZE = 1_000_000
    if len(raw_text) > MAX_INPUT_SIZE:
        return [{"error": f"Input too large: {len(raw_text)} chars (max {MAX_INPUT_SIZE})"}]

    text = raw_text.strip()
    if not text:
        return []

    # Detect package.json (JSON with dependencies key)
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
            if any(k in parsed for k in ("dependencies", "devDependencies", "peerDependencies")):
                return _parse_package_json(text)
        except (json.JSONDecodeError, ValueError):
            pass

    # Detect pom.xml (XML with <project or <dependency)
    if text.lstrip().startswith("<?xml") or "<project" in text[:500]:
        result = _parse_pom_xml(text)
        if result:
            return result

    # Detect requirements.txt (lines with == or >= operators)
    if re.search(r"^[A-Za-z0-9_.\-]+\s*[><=!~]=", text, re.MULTILINE):
        return _parse_requirements_txt(text)

    # Fallback: try generic name:ecosystem:version format
    generic = _parse_generic_lines(text)
    if generic:
        return generic

    # Last resort: try requirements.txt parser for bare package names
    return _parse_requirements_txt(text)


# ── OSV Batch Scanner ───────────────────────────────────────────────────────


async def scan_dependencies_bulk(
    packages: list[dict],
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> list[dict]:
    """Scan a list of packages for known vulnerabilities using OSV.dev batch API.

    Args:
        packages: List of {"name": str, "ecosystem": str, "version": str} dicts.
        client: Shared httpx async client.
        cache: SQLite cache instance.

    Returns:
        List of dicts for packages with vulnerabilities found:
        [{"package", "ecosystem", "version", "vuln_count", "vulns": [...top 5]}]
    """
    if not packages:
        return []

    # Deduplicate and check cache first
    uncached: list[tuple[int, dict]] = []  # (original_index, package)
    results_map: dict[int, list[dict]] = {}

    for i, pkg in enumerate(packages):
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        ver = pkg.get("version", "")
        cache_key = f"osv_bulk:{eco}:{name}:{ver}"
        cached = await cache.get(cache_key)
        if cached is not None:
            results_map[i] = cached
        else:
            uncached.append((i, pkg))

    # Batch uncached packages, max 1000 per request
    for batch_start in range(0, len(uncached), _MAX_BATCH):
        batch = uncached[batch_start : batch_start + _MAX_BATCH]
        queries = []
        for _, pkg in batch:
            q: dict = {
                "package": {
                    "name": pkg.get("name", ""),
                    "ecosystem": pkg.get("ecosystem", ""),
                },
            }
            ver = pkg.get("version", "")
            if ver:
                q["version"] = ver
            queries.append(q)

        try:
            resp = await client.post(
                f"{OSV_BASE}/querybatch",
                json={"queries": queries},
            )
            resp.raise_for_status()

            if len(resp.content) > MAX_RESPONSE_BYTES:
                logger.warning("OSV querybatch response too large (%d bytes)", len(resp.content))
                continue

            data = resp.json()
            batch_results = data.get("results", [])

            for j, (orig_idx, pkg) in enumerate(batch):
                vulns = []
                if j < len(batch_results):
                    vulns = batch_results[j].get("vulns", [])

                # Cache individual results
                name = pkg.get("name", "")
                eco = pkg.get("ecosystem", "")
                ver = pkg.get("version", "")
                cache_key = f"osv_bulk:{eco}:{name}:{ver}"
                await cache.set(cache_key, vulns, TTL_DEP_SCAN)
                results_map[orig_idx] = vulns

        except httpx.HTTPStatusError as exc:
            logger.error(
                "OSV querybatch failed (HTTP %d): %s",
                exc.response.status_code,
                exc,
            )
        except httpx.RequestError as exc:
            logger.error("OSV querybatch network error: %s", exc)

    # Build output: only packages with vulnerabilities
    output: list[dict] = []
    for i, pkg in enumerate(packages):
        vulns = results_map.get(i, [])
        if not vulns:
            continue

        # Keep top 5 vulns, sorted by severity hint (CRITICAL > HIGH > ...)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns = sorted(
            vulns,
            key=lambda v: severity_order.get(_extract_severity(v), 4),
        )
        top_vulns = [
            {
                "id": v.get("id", ""),
                "summary": v.get("summary", v.get("details", ""))[:200],
                "aliases": v.get("aliases", []),
                "severity": _extract_severity(v),
                "references": [r.get("url", "") for r in v.get("references", [])[:3]],
            }
            for v in sorted_vulns[:5]
        ]

        output.append(
            {
                "package": pkg.get("name", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "version": pkg.get("version", ""),
                "vuln_count": len(vulns),
                "vulns": top_vulns,
            }
        )

    return output


def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity string from an OSV vulnerability record."""
    severity_list = vuln.get("severity", [])
    if not severity_list:
        # Try to infer from database_specific or ecosystem_specific
        db_specific = vuln.get("database_specific", {})
        return db_specific.get("severity", "UNKNOWN")

    # OSV severity uses CVSS scoring
    best = "UNKNOWN"
    best_score = -1.0
    for sev in severity_list:
        score_str = sev.get("score", "")
        sev_type = sev.get("type", "")
        # Try parsing CVSS vector for base score
        if sev_type in ("CVSS_V3", "CVSS_V2") and isinstance(score_str, str):
            # Extract base score from CVSS vector if present
            cvss_match = re.search(r"CVSS:\d\.\d/AV:", score_str)
            if cvss_match:
                # Use vector presence as indicator; map to severity buckets
                if best_score < 0:
                    best = "MEDIUM"  # Default when vector exists but no score
                    best_score = 5.0

    if best == "UNKNOWN":
        # Check affected[].ecosystem_specific.severity
        for affected in vuln.get("affected", []):
            eco_sev = affected.get("ecosystem_specific", {}).get("severity", "")
            if eco_sev:
                return eco_sev.upper()

    return best


# ── GitHub Secret Exposure Scanner ──────────────────────────────────────────


async def scan_repo_secrets(
    search_term: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Search GitHub public repos for potential secret/credential exposure.

    Uses the GitHub code search API to find files in public repositories
    that may contain exposed secrets related to the search term.

    This is a demonstration of exposure detection in public repos only.
    Intended for authorized security research and awareness.

    Args:
        search_term: CVE ID or keyword to search for (e.g. "CVE-2024-1234"
                     or "AWS_SECRET_ACCESS_KEY").
        client: Shared httpx async client.
        cache: SQLite cache instance.

    Returns:
        Dict with search results and matched files.
    """
    cache_key = f"gh_secrets:{search_term}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    result: dict = {
        "search_term": search_term,
        "total_count": 0,
        "matches": [],
        "searched": False,
    }

    if not GITHUB_TOKEN:
        result["error"] = (
            "GITHUB_TOKEN not configured. Set GITHUB_TOKEN env var for GitHub API access."
        )
        return result

    # Common secret patterns to search alongside the term
    secret_patterns = [
        f"{search_term}+in:file",
        f"{search_term} password+in:file",
        f"{search_term} secret+in:file",
        f"{search_term} api_key+in:file",
    ]

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    all_matches: list[dict] = []
    total = 0

    for pattern in secret_patterns[:2]:  # Limit to 2 searches to conserve rate
        try:
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": pattern, "per_page": 5},
                headers=headers,
            )

            if resp.status_code == 403:
                logger.warning("GitHub rate limit hit for secret scan")
                break
            if resp.status_code == 422:
                logger.warning("GitHub rejected search query: %s", pattern)
                continue

            resp.raise_for_status()
            data = resp.json()
            total += data.get("total_count", 0)

            for item in data.get("items", [])[:5]:
                repo = item.get("repository", {})
                match_entry = {
                    "file_name": item.get("name", ""),
                    "file_path": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file_url": item.get("html_url", ""),
                    "score": item.get("score", 0),
                }
                # Deduplicate by file URL
                if not any(m["file_url"] == match_entry["file_url"] for m in all_matches):
                    all_matches.append(match_entry)

        except httpx.HTTPStatusError as exc:
            logger.error(
                "GitHub code search failed (HTTP %d): %s",
                exc.response.status_code,
                exc,
            )
        except httpx.RequestError as exc:
            logger.error("GitHub code search network error: %s", exc)

    result["total_count"] = total
    result["matches"] = all_matches[:10]  # Cap at 10
    result["searched"] = True

    await cache.set(cache_key, result, TTL_DEP_SCAN)
    return result
