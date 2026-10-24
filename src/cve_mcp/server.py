"""CVE/Vulnerability MCP Server — entry point and tool/resource/prompt registry.

SECURITY NOTE (Unit 42 MCP "sampling" attack vector, plan 3.3):
    This server NEVER registers a sampling handler and NEVER issues a
    ``sampling/createMessage`` request back to the MCP client. Server-initiated
    sampling lets a (potentially compromised or malicious) server ask the host
    LLM to generate arbitrary text on its behalf — a documented prompt-injection
    / data-exfiltration vector. All LLM interaction here is strictly
    client-driven (the model calls our tools); the server only ever *responds*.
    Do not add ``ctx.session.create_message(...)`` or a sampling callback.

SECURITY NOTE (SSRF, plan 3.4): any NEW code path that takes user input and
    turns it into an outbound URL must pass it through
    ``validators.validate_scheme`` / ``validators.validate_outbound_url`` before
    fetching. The orchestrator and resources added in v0.2.0 only call upstream
    APIs through the existing, host-allowlisted client modules.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [cve-mcp] %(levelname)s: %(message)s",
)

import httpx
from mcp.server.fastmcp import Context, FastMCP

from cve_mcp.api.attack_mapping import get_attack_mapping as _map_cve_to_attack
from cve_mcp.api.cve_timeline import get_cve_timeline as _compute_cve_timeline
from cve_mcp.api.dependency_scan import (
    parse_dependency_list,
)
from cve_mcp.api.dependency_scan import (
    scan_dependencies_bulk as _scan_dependencies_bulk,
)
from cve_mcp.api.dependency_scan import (
    scan_repo_secrets as _scan_repo_secrets,
)
from cve_mcp.api.domain_intel import get_domain_intel as _get_domain_intel
from cve_mcp.api.domain_intel import passive_dns_lookup as _passive_dns_lookup
from cve_mcp.api.epss_client import get_epss
from cve_mcp.api.exploit_intel import check_exploit_availability as _search_exploits
from cve_mcp.api.hash_intel import lookup_file_hash as _lookup_file_hash
from cve_mcp.api.ip_intel import check_ip_reputation as _check_ip_reputation
from cve_mcp.api.kev_client import fetch_kev_catalog, lookup_kev
from cve_mcp.api.malware_intel import lookup_malware_family as _lookup_malware_family
from cve_mcp.api.nvd_client import fetch_cve, search_nvd, validate_nvd_key
from cve_mcp.api.osv_client import query_package
from cve_mcp.api.poc_checker import search_poc_existence
from cve_mcp.api.ransomware_intel import check_ransomware_intel as _check_ransomware_intel
from cve_mcp.api.rate_limiter import TokenBucketRateLimiter
from cve_mcp.api.shodan_client import shodan_host_lookup as _shodan_host_lookup
from cve_mcp.api.url_safety import check_url_safety as _check_url_safety
from cve_mcp.api.vendor_advisory import get_vendor_advisory as _get_vendor_advisories
from cve_mcp.api.vulncheck_client import fetch_cve_vulncheck
from cve_mcp.audit import record as audit_record
from cve_mcp.audit import setup_audit_log
from cve_mcp.cache.sqlite_cache import TTL_CVSS, VulnCache
from cve_mcp.config import (
    AUDIT_LOG_PATH,
    CACHE_DB_PATH,
    NVD_BURST,
    NVD_RATE,
    REQUEST_TIMEOUT,
    get_secret,
)
from cve_mcp.models import CVERecord, KEVEntry
from cve_mcp.utils.fanout import fan_out
from cve_mcp.utils.risk_scorer import score_cve
from cve_mcp.utils.ssvc import ssvc_decision
from cve_mcp.utils.validators import normalize_cve, validate_hash, validate_ip_address

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    client: httpx.AsyncClient
    cache: VulnCache
    limiter: TokenBucketRateLimiter
    kev_catalog: list[KEVEntry]


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    cache_path = Path(CACHE_DB_PATH).expanduser()
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    setup_audit_log(AUDIT_LOG_PATH)

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        verify=True,
        follow_redirects=True,
        max_redirects=3,
    ) as client:
        try:
            await validate_nvd_key(client)
        except Exception as e:
            logger.warning(
                "NVD unavailable at startup: %s — NVD-dependent tools will return errors until NVD recovers",
                e,
            )
        cache = VulnCache(str(cache_path))
        await cache.initialize()
        limiter = TokenBucketRateLimiter(rate=NVD_RATE, capacity=NVD_BURST)
        catalog = await fetch_kev_catalog(client, cache)
        app_ctx = AppContext(client=client, cache=cache, limiter=limiter, kev_catalog=catalog)
        # Mirror state for Context-less resource handlers (kev://catalog,
        # epss://scores/{cve_id}). Resources are read outside a tool request, so
        # they cannot use ctx; expose the pre-warmed catalog + shared client/cache.
        global _kev_catalog_snapshot, _app_context_ref
        _kev_catalog_snapshot = catalog
        _app_context_ref = app_ctx
        try:
            yield app_ctx
        finally:
            _app_context_ref = None
            _kev_catalog_snapshot = []
            await cache.close()


mcp = FastMCP("cve-mcp", lifespan=app_lifespan)

# Server + scoring metadata surfaced by health_check / triage_cve.
try:  # __version__ lives in the package __init__
    from cve_mcp import __version__ as SERVER_VERSION
except Exception:  # pragma: no cover - extremely defensive
    SERVER_VERSION = "1.0.0"

# The numeric risk scorer's version (kept in lockstep with risk_scorer.score_cve).
SCORING_VERSION = "1.0"

# Optional API keys reported (yes/no only) by health_check. The label is for
# humans; the env_name is looked up via config.get_secret so the raw value is
# NEVER materialised in the output.
_OPTIONAL_KEY_NAMES: tuple[tuple[str, str], ...] = (
    ("NVD", "NVD_API_KEY"),
    ("GitHub", "GITHUB_TOKEN"),
    ("VulnCheck", "VULNCHECK_TOKEN"),
    ("AbuseIPDB", "ABUSEIPDB_KEY"),
    ("VirusTotal", "VIRUSTOTAL_KEY"),
    ("URLScan", "URLSCAN_KEY"),
    ("Shodan", "SHODAN_KEY"),
    ("GreyNoise", "GREYNOISE_API_KEY"),
    ("CIRCL-user", "CIRCL_PDNS_USER"),
    ("CIRCL-pass", "CIRCL_PDNS_PASS"),
)


def _get_app(ctx) -> AppContext:
    return ctx.request_context.lifespan_context


# Snapshot wiring for resources (resources have no Context param). The KEV
# catalog is pre-warmed once at startup into AppContext; we mirror it here so
# the kev://catalog resource can render without a request context. Likewise we
# stash the AppContext so EPSS resource reads can reuse the shared client/cache.
# These are (re)populated by app_lifespan on startup and cleared on shutdown.
_kev_catalog_snapshot: list[KEVEntry] = []
_app_context_ref: AppContext | None = None


def _resource_app() -> AppContext | None:
    return _app_context_ref


async def _compute_tool_manifest_hash() -> str:
    """Return a stable SHA-256 over every registered tool's public definition.

    Uses the verified FastMCP enumeration API (``await mcp.list_tools()`` returns
    ``list[mcp.types.Tool]``). For each tool we keep only the stable, contract-
    relevant fields — ``name``, ``description``, and the camelCase ``inputSchema``
    (the JSON Schema of arguments) — drop volatile fields (``meta``/``execution``),
    sort the list by tool name, and hash the canonical JSON. A change to any
    tool's name, docstring/description, or argument schema changes the hash,
    which lets clients pin/verify the tool surface.
    """
    tools = await mcp.list_tools()
    manifest: list[dict] = []
    for t in tools:
        dumped = t.model_dump(mode="json")
        manifest.append(
            {
                "name": dumped.get("name"),
                "description": dumped.get("description"),
                "inputSchema": dumped.get("inputSchema"),
            }
        )
    manifest.sort(key=lambda d: d.get("name") or "")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Tool 1: lookup_cve ──────────────────────────────────────────────────────


@mcp.tool()
async def lookup_cve(cve_id: str, ctx: Context = None) -> str:
    """Look up a CVE by ID from NVD. Returns full details including CVSS scores,
    description, weaknesses, and CISA KEV status.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}
    cve_id_clean = normalize_cve(cve_id)
    if not cve_id_clean:
        audit_record("lookup_cve", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)
    try:
        record = await asyncio.wait_for(
            fetch_cve(cve_id_clean, app.client, app.limiter, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("lookup_cve", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds. NVD may be under maintenance."
    except Exception as exc:
        msg = str(exc)
        if "rate limit" in msg.lower() or "429" in msg:
            audit_record("lookup_cve", params, "rate_limited", (time.monotonic() - start) * 1000)
            return "NVD rate limit exceeded. Retry in ~30 seconds."
        audit_record("lookup_cve", params, "error", (time.monotonic() - start) * 1000)
        return f"Error fetching CVE: {exc}"

    if record is None:
        audit_record("lookup_cve", params, "not_found", (time.monotonic() - start) * 1000)
        return f"CVE {cve_id_clean} not found in NVD."

    kev = lookup_kev(app.kev_catalog, cve_id_clean)
    duration = (time.monotonic() - start) * 1000
    audit_record("lookup_cve", params, "ok", duration)
    return _format_cve(record, kev)


# ── Tool 2: search_cves ─────────────────────────────────────────────────────


@mcp.tool()
async def search_cves(query: str, severity: str = "", limit: int = 10, ctx: Context = None) -> str:
    """Search NVD for CVEs by keyword and optional severity filter.

    Args:
        query: Keyword to search (letters, numbers, spaces, hyphens, dots — max 200 chars)
        severity: Optional CVSS v3 severity filter: NONE, LOW, MEDIUM, HIGH, CRITICAL
        limit: Max results (1–50, default 10)
    """
    start = time.monotonic()
    params = {"query": query, "severity": severity, "limit": limit}

    app = _get_app(ctx)
    try:
        results = await asyncio.wait_for(
            search_nvd(query, severity, limit, app.client, app.limiter, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("search_cves", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds. NVD may be under maintenance."
    except Exception as exc:
        msg = str(exc)
        if "rate limit" in msg.lower() or "429" in msg:
            audit_record("search_cves", params, "rate_limited", (time.monotonic() - start) * 1000)
            return "NVD rate limit exceeded. Retry in ~30 seconds."
        audit_record("search_cves", params, "error", (time.monotonic() - start) * 1000)
        return f"Search error: {exc}"

    if results is None:
        audit_record("search_cves", params, "invalid_input", (time.monotonic() - start) * 1000)
        return "Invalid search query. Use only letters, numbers, spaces, hyphens, and dots (max 200 chars)."

    duration = (time.monotonic() - start) * 1000
    audit_record("search_cves", params, "ok", duration)

    if not results:
        return f"No CVEs found matching '{query}'."

    lines = [f"CVE Search Results for '{query}' ({len(results)} found)\n"]
    for cve in results:
        cve_id = cve.get("id", "N/A")
        desc = _get_description(cve.get("descriptions", []))
        score = _get_base_score(cve.get("metrics", {}))
        lines.append(f"  {cve_id}  Score: {score}  {desc[:100]}{'...' if len(desc) > 100 else ''}")
    return "\n".join(lines)


# ── Tool 3: check_package_vulns ─────────────────────────────────────────────


@mcp.tool()
async def check_package_vulns(
    package: str, ecosystem: str, version: str = "", ctx: Context = None
) -> str:
    """Check a package for known vulnerabilities via OSV.dev.

    Args:
        package: Package name (e.g. log4j-core, requests, lodash)
        ecosystem: Package ecosystem — PyPI, npm, Go, Maven, NuGet, crates.io,
                   Packagist, Hex, RubyGems, Android, CocoaPods, GitHub Actions
        version: Optional specific version to check (e.g. 2.14.1)
    """
    start = time.monotonic()
    params = {"package": package, "ecosystem": ecosystem, "version": version}
    app = _get_app(ctx)
    try:
        vulns = await asyncio.wait_for(
            query_package(package, ecosystem, version, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("check_package_vulns", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("check_package_vulns", params, "error", (time.monotonic() - start) * 1000)
        return f"OSV query error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("check_package_vulns", params, "ok", duration)

    if not vulns:
        ver_str = f" {version}" if version else ""
        return f"No known vulnerabilities found for {ecosystem}/{package}{ver_str}."

    lines = [f"{len(vulns)} vulnerabilities found in {ecosystem}/{package}:\n"]
    for v in vulns[:20]:
        osv_id = v.get("id", "N/A")
        summary = v.get("summary", v.get("details", "No description")[:120])
        aliases = ", ".join(v.get("aliases", [])[:3])
        alias_str = f"  ({aliases})" if aliases else ""
        lines.append(f"  {osv_id}{alias_str}: {summary}")
    if len(vulns) > 20:
        lines.append(f"  ... and {len(vulns) - 20} more")
    return "\n".join(lines)


# ── Tool 4: get_epss_score ──────────────────────────────────────────────────


@mcp.tool()
async def get_epss_score(cve_ids: str, ctx: Context = None) -> str:
    """Get EPSS (Exploit Prediction Scoring System) scores for one or more CVEs.

    Args:
        cve_ids: Comma-separated CVE IDs (e.g. CVE-2021-44228,CVE-2022-22965)
    """
    start = time.monotonic()
    params = {"cve_ids": cve_ids}

    raw_ids = [x.strip() for x in cve_ids.split(",") if x.strip()]
    valid_ids = []
    for cid in raw_ids:
        clean = normalize_cve(cid)
        if clean:
            valid_ids.append(clean)
        else:
            audit_record("get_epss_score", params, "invalid_input", 0)
            return f"Invalid CVE ID: '{cid}'. Expected format: CVE-YYYY-NNNNN"

    if not valid_ids:
        audit_record("get_epss_score", params, "invalid_input", 0)
        return "No valid CVE IDs provided."

    app = _get_app(ctx)
    try:
        scores = await asyncio.wait_for(
            get_epss(valid_ids, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("get_epss_score", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("get_epss_score", params, "error", (time.monotonic() - start) * 1000)
        return f"EPSS query error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("get_epss_score", params, "ok", duration)

    if not scores:
        return f"No EPSS data found for: {', '.join(valid_ids)}"

    lines = ["EPSS Scores:\n"]
    for s in sorted(scores, key=lambda x: x.epss, reverse=True):
        bar = "█" * int(s.epss * 20)
        lines.append(
            f"  {s.cve}  {s.epss * 100:5.2f}%  [{bar:<20}]  "
            f"Percentile: {s.percentile * 100:.1f}th  (as of {s.date})"
        )
    return "\n".join(lines)


# ── Tool 5: check_kev ───────────────────────────────────────────────────────


@mcp.tool()
async def check_kev(cve_id: str, ctx: Context = None) -> str:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("check_kev", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)
    entry = lookup_kev(app.kev_catalog, clean)
    duration = (time.monotonic() - start) * 1000

    if entry is None:
        audit_record("check_kev", params, "not_found", duration)
        return f"{clean} is NOT in the CISA KEV catalog."

    audit_record("check_kev", params, "ok", duration)
    ransomware = entry.knownRansomwareCampaignUse or "Unknown"
    return (
        f"{clean} IS in the CISA KEV catalog.\n\n"
        f"  Vendor/Product:  {entry.vendorProject} — {entry.product}\n"
        f"  Vulnerability:   {entry.vulnerabilityName}\n"
        f"  Date Added:      {entry.dateAdded}\n"
        f"  Remediation Due: {entry.dueDate}\n"
        f"  Ransomware Use:  {ransomware}"
    )


# ── Tool 6: parse_cvss ──────────────────────────────────────────────────────


@mcp.tool()
async def parse_cvss(vector: str, ctx: Context = None) -> str:
    """Parse and explain a CVSS vector string (v2, v3.x, or v4.0).

    Args:
        vector: CVSS vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    """
    start = time.monotonic()
    params = {"vector": vector}
    app = _get_app(ctx)
    cache_key = f"cvss:{vector}"

    cached = await app.cache.get(cache_key)
    if cached:
        audit_record("parse_cvss", params, "ok", (time.monotonic() - start) * 1000)
        return cached.get("result", "")

    try:
        from cvss import CVSS2, CVSS3, CVSSError

        try:
            from cvss import CVSS4
        except ImportError:
            CVSS4 = None

        v = vector.strip()
        upper = v.upper()

        if CVSS4 is not None and upper.startswith("CVSS:4.0/"):
            c = CVSS4(v)
        elif upper.startswith("CVSS:3."):
            c = CVSS3(v)
        elif upper.startswith("CVSS:2."):
            c = CVSS2(v)
        elif not upper.startswith("CVSS:"):
            # Legacy v2 vectors have no prefix
            c = CVSS2(v)
        else:
            raise CVSSError("Unknown version prefix")

        scores = c.scores()
        base_score = scores[0]
        severity = c.severities()[0]
        result = (
            f"CVSS Vector Analysis\n\n"
            f"  Vector:    {v}\n"
            f"  Version:   {c.minor_version if hasattr(c, 'minor_version') else 'N/A'}\n"
            f"  Base Score: {base_score} ({severity})\n"
        )
        if len(scores) > 1 and scores[1]:
            result += f"  Temporal:  {scores[1]}\n"
        if len(scores) > 2 and scores[2]:
            result += f"  Environmental: {scores[2]}\n"

        await app.cache.set(cache_key, {"result": result}, TTL_CVSS)
        audit_record("parse_cvss", params, "ok", (time.monotonic() - start) * 1000)
        return result

    except Exception as exc:
        from cvss import CVSSError as _CVSSError

        if isinstance(exc, _CVSSError) or "invalid" in str(exc).lower():
            audit_record("parse_cvss", params, "invalid_input", (time.monotonic() - start) * 1000)
            return (
                "Unsupported CVSS vector. Provide CVSS:2.0/..., CVSS:3.x/..., or CVSS:4.0/...\n"
                f"Error: {exc}"
            )
        audit_record("parse_cvss", params, "error", (time.monotonic() - start) * 1000)
        return f"CVSS parse error: {exc}"


# ── Tool 7: get_cve_summary ─────────────────────────────────────────────────


@mcp.tool()
async def get_cve_summary(cve_id: str, ctx: Context = None) -> str:
    """Get a comprehensive one-page summary of a CVE: severity, EPSS, KEV status,
    description, weaknesses, and timeline. Fetches NVD + EPSS concurrently.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("get_cve_summary", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)

    nvd_task = asyncio.create_task(fetch_cve(clean, app.client, app.limiter, app.cache))
    epss_task = asyncio.create_task(get_epss([clean], app.client, app.cache))

    try:
        nvd_res, epss_res = await asyncio.wait_for(
            asyncio.gather(nvd_task, epss_task, return_exceptions=True),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("get_cve_summary", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds. NVD may be under maintenance."

    nvd_data = nvd_res if not isinstance(nvd_res, Exception) else None
    epss_list = epss_res if not isinstance(epss_res, Exception) else []
    epss_data = epss_list[0] if epss_list else None
    kev_entry = lookup_kev(app.kev_catalog, clean)

    if nvd_data is None and not isinstance(nvd_res, Exception):
        audit_record("get_cve_summary", params, "not_found", (time.monotonic() - start) * 1000)
        return f"CVE {clean} not found in NVD."

    duration = (time.monotonic() - start) * 1000
    audit_record("get_cve_summary", params, "ok", duration)
    return _format_summary(clean, nvd_data, epss_data, kev_entry)


# ── Tool 8: health_check ────────────────────────────────────────────────────


@mcp.tool()
async def health_check(ctx: Context = None) -> str:
    """Check the health of the CVE MCP server: NVD connectivity, KEV catalog
    status, cache, risk scoring version, tool manifest hash, and which optional
    API keys are configured (names only — never the key values).

    Note: This tool pings NVD without rate limiting — do not call it in a loop.
    """
    start = time.monotonic()
    app = _get_app(ctx)
    lines = ["CVE MCP Server — Health Check\n"]

    lines.append(f"  Version:      {SERVER_VERSION}")
    lines.append(f"  Scoring:      v{SCORING_VERSION} (risk_scorer)")

    # NVD connectivity (no rate limiter — this is a health probe only)
    try:
        resp = await asyncio.wait_for(
            app.client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"resultsPerPage": 1},
            ),
            timeout=10.0,
        )
        lines.append(f"  NVD API:      OK (HTTP {resp.status_code})")
    except asyncio.TimeoutError:
        lines.append("  NVD API:      TIMEOUT (>10s)")
    except Exception as exc:
        lines.append(f"  NVD API:      ERROR — {exc}")

    # KEV catalog
    kev_count = len(app.kev_catalog)
    if kev_count > 0:
        lines.append(f"  KEV Catalog:  OK ({kev_count} entries)")
    else:
        lines.append("  KEV Catalog:  EMPTY (load failed or not yet fetched)")

    # Cache — probe with a tiny round-trip so a broken DB shows as ERROR.
    try:
        await app.cache.set("health:probe", {"ok": True}, 60)
        probe = await app.cache.get("health:probe")
        cache_ok = bool(probe and probe.get("ok") is True)
        lines.append(
            f"  Cache:        {'OK (SQLite, WAL)' if cache_ok else 'DEGRADED (read-back mismatch)'}"
        )
    except Exception as exc:
        lines.append(f"  Cache:        ERROR — {exc}")

    # Tool manifest hash — stable SHA-256 over registered tool definitions.
    try:
        manifest_hash = await _compute_tool_manifest_hash()
        lines.append(f"  Tool Manifest: {manifest_hash}")
    except Exception as exc:  # pragma: no cover - defensive
        lines.append(f"  Tool Manifest: ERROR — {exc}")

    # Optional API keys — report ONLY configured yes/no, never the value.
    lines.append("\n  Optional API keys (configured? value never shown):")
    for label, env_name in _OPTIONAL_KEY_NAMES:
        configured = "yes" if get_secret(env_name) else "no"
        lines.append(f"    {label:<12} {configured}")

    duration = (time.monotonic() - start) * 1000
    audit_record("health_check", {}, "ok", duration)
    return "\n".join(lines)


# ── Formatting helpers ───────────────────────────────────────────────────────


def _get_description(descriptions: list[dict]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "No description") if descriptions else "No description"


def _get_base_score(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            severity = entries[0].get("cvssData", {}).get("baseSeverity", "")
            if score is not None:
                return f"{score} ({severity})"
    return "N/A"


def _get_vector(metrics: dict) -> tuple[str, str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0].get("cvssData", {})
            return (
                d.get("vectorString", ""),
                str(d.get("baseScore", "")),
                d.get("baseSeverity", ""),
            )
    return ("", "", "")


def _get_weaknesses(weaknesses: list[dict]) -> list[str]:
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-Other":
                cwes.append(val)
    return cwes


def _format_cve(record, kev_entry) -> str:
    desc = _get_description(record.descriptions)
    vector_str, score, severity = _get_vector(record.metrics)
    cwes = _get_weaknesses(record.weaknesses)
    kev_str = "YES" if kev_entry else "NO"
    if kev_entry:
        kev_str += f" (Added {kev_entry.dateAdded}, Ransomware: {kev_entry.knownRansomwareCampaignUse or 'Unknown'})"

    lines = [
        f"=== {record.id} ===\n",
        f"Status:    {record.vulnStatus}",
        f"Published: {record.published[:10] if record.published else 'N/A'}",
        f"Updated:   {record.lastModified[:10] if record.lastModified else 'N/A'}",
        f"CISA KEV:  {kev_str}",
    ]
    if score:
        lines.append(f"Score:     {score} {severity}")
    if vector_str:
        lines.append(f"Vector:    {vector_str}")
    if cwes:
        lines.append(f"Weaknesses: {', '.join(cwes)}")
    lines.append(f"\nDescription:\n{desc}")
    return "\n".join(lines)


def _format_summary(cve_id: str, record, epss, kev_entry) -> str:
    lines = [f"=== {cve_id} Summary ===\n"]

    if record:
        vector_str, score, severity = _get_vector(record.metrics)
        if score and severity:
            lines.append(f"SEVERITY: {severity} ({score})")
        if vector_str:
            lines.append(f"Vector: {vector_str}")
    else:
        lines.append("SEVERITY: (NVD data unavailable)")

    lines.append("\nEXPLOIT RISK:")
    if epss:
        lines.append(f"  EPSS Score:  {float(epss.epss) * 100:.2f}% probability of exploitation")
        lines.append(f"  Percentile:  {float(epss.percentile) * 100:.2f}th")
    else:
        lines.append("  EPSS Score:  (unavailable)")

    if kev_entry:
        ransomware = kev_entry.knownRansomwareCampaignUse or "Unknown"
        lines.append(
            f"  CISA KEV:    YES — Added {kev_entry.dateAdded}, "
            f"Due {kev_entry.dueDate}, Ransomware: {ransomware}"
        )
    else:
        lines.append("  CISA KEV:    NO")

    if record:
        desc = _get_description(record.descriptions)
        lines.append(f"\nDESCRIPTION:\n{desc}")
        cwes = _get_weaknesses(record.weaknesses)
        lines.append(
            f"\nSTATUS: {record.vulnStatus} | "
            f"Published: {record.published[:10] if record.published else 'N/A'} | "
            f"Updated: {record.lastModified[:10] if record.lastModified else 'N/A'}"
        )
        if cwes:
            lines.append(f"Weaknesses: {', '.join(cwes)}")

    return "\n".join(lines)


# ── Tool 9: check_ip_reputation ─────────────────────────────────────────────


@mcp.tool()
async def check_ip_reputation(ip: str, ctx: Context = None) -> str:
    """Check an IP address reputation via AbuseIPDB and GreyNoise Community.
    Returns abuse confidence score, country, ISP, Tor status, and noise classification.

    Args:
        ip: IPv4 or IPv6 address to check (e.g. 1.2.3.4 or 2001:db8::1)
    """
    start = time.monotonic()
    params = {"ip": ip}

    try:
        clean_ip = validate_ip_address(ip)
    except ValueError as e:
        audit_record("check_ip_reputation", params, "invalid_input", 0)
        return f"Invalid IP address: {e}"

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _check_ip_reputation(clean_ip, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("check_ip_reputation", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("check_ip_reputation", params, "error", (time.monotonic() - start) * 1000)
        return f"IP reputation lookup error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("check_ip_reputation", params, "ok", duration)

    risk = result.get("risk_level", "NONE")
    abuse = result.get("abuse_score", 0)
    noise = result.get("noise", False)
    riot = result.get("riot", False)
    classification = result.get("classification", "")
    lines = [
        f"=== IP Reputation: {clean_ip} ===\n",
        f"  Risk Level:      {risk}",
        f"  Abuse Score:     {abuse}/100  (AbuseIPDB)",
        f"  Country:         {result.get('country_code', 'N/A')}",
        f"  ISP:             {result.get('isp', 'N/A')}",
        f"  Total Reports:   {result.get('total_reports', 0)}",
        f"  Tor Exit Node:   {'YES' if result.get('is_tor') else 'NO'}",
        f"  GreyNoise Noise: {'YES' if noise else 'NO'}  (internet scanner/shodan crawl)",
        f"  GreyNoise RIOT:  {'YES' if riot else 'NO'}  (known benign, e.g. CDN)",
    ]
    if classification:
        lines.append(f"  Classification:  {classification}  ({result.get('noise_name', '')})")
    if result.get("last_reported_at"):
        lines.append(f"  Last Reported:   {result.get('last_reported_at', '')}")
    if not result.get("abuseipdb_checked", True) and not result.get("abuse_score"):
        lines.append("\n  Note: ABUSEIPDB_KEY not set — abuse score unavailable.")
    return "\n".join(lines)


# ── Tool 10: get_domain_intel ────────────────────────────────────────────────


@mcp.tool()
async def get_domain_intel(domain: str, ctx: Context = None) -> str:
    """Get domain intelligence: certificate transparency logs (crt.sh) and
    passive DNS records (CIRCL PDNS). Returns subdomains and certificate history.

    Args:
        domain: Domain name to investigate (e.g. example.com)
    """
    start = time.monotonic()
    params = {"domain": domain}

    domain_clean = domain.strip().lower()
    if not domain_clean or len(domain_clean) > 253 or " " in domain_clean:
        audit_record("get_domain_intel", params, "invalid_input", 0)
        return "Invalid domain name. Provide a valid hostname (e.g. example.com)."

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _get_domain_intel(domain_clean, app.client, app.cache),
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        audit_record("get_domain_intel", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 20 seconds."
    except Exception as exc:
        audit_record("get_domain_intel", params, "error", (time.monotonic() - start) * 1000)
        return f"Domain intel error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("get_domain_intel", params, "ok", duration)

    certs = result.get("certificates", [])
    subs = result.get("subdomains", [])
    pdns = result.get("pdns_records", [])

    lines = [f"=== Domain Intelligence: {domain_clean} ===\n"]
    lines.append(f"  Certificates found:  {len(certs)}  (via crt.sh)")
    if certs:
        lines.append("  Recent certificates:")
        for c in certs[:5]:
            lines.append(
                f"    {c.get('name', '')}  [{c.get('not_before', '')[:10]} → {c.get('not_after', '')[:10]}]"
            )
        if len(certs) > 5:
            lines.append(f"    ... and {len(certs) - 5} more")

    lines.append(f"\n  Unique subdomains:   {len(subs)}")
    if subs:
        for sub in subs[:20]:
            lines.append(f"    {sub}")
        if len(subs) > 20:
            lines.append(f"    ... and {len(subs) - 20} more")

    lines.append(f"\n  Passive DNS records: {len(pdns)}  (via CIRCL PDNS)")
    for rec in pdns[:10]:
        lines.append(
            f"    {rec.get('rrtype', '?'):6s}  {rec.get('rrname', '')} → {rec.get('rdata', '')}  "
            f"(seen {rec.get('time_first', '')[:10]} – {rec.get('time_last', '')[:10]})"
        )

    return "\n".join(lines)


# ── Tool 11: passive_dns_lookup ──────────────────────────────────────────────


@mcp.tool()
async def passive_dns_lookup(ip_or_domain: str, ctx: Context = None) -> str:
    """Query CIRCL Passive DNS for historical DNS resolutions of an IP or domain.
    Shows what hostnames have resolved to this IP, or what IPs a domain has pointed to.

    Args:
        ip_or_domain: IPv4/IPv6 address or domain name to query
    """
    start = time.monotonic()
    params = {"ip_or_domain": ip_or_domain}

    target = ip_or_domain.strip().lower()
    if not target or len(target) > 253:
        audit_record("passive_dns_lookup", params, "invalid_input", 0)
        return "Invalid input. Provide an IP address or domain name."

    app = _get_app(ctx)
    try:
        records = await asyncio.wait_for(
            _passive_dns_lookup(target, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("passive_dns_lookup", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("passive_dns_lookup", params, "error", (time.monotonic() - start) * 1000)
        return f"Passive DNS error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("passive_dns_lookup", params, "ok", duration)

    if isinstance(records, dict):
        err = records.get("error", "CIRCL PDNS returned an error.")
        audit_record("passive_dns_lookup", params, "error", (time.monotonic() - start) * 1000)
        return err

    if not records:
        return f"No passive DNS records found for '{target}' in CIRCL PDNS."

    lines = [f"Passive DNS for {target}  ({len(records)} records)\n"]
    for rec in records:
        lines.append(
            f"  {rec.get('rrtype', '?'):6s}  {rec.get('rrname', '')} → {rec.get('rdata', '')}  "
            f"count={rec.get('count', '?')}  "
            f"({rec.get('time_first', '')[:10]} – {rec.get('time_last', '')[:10]})"
        )
    return "\n".join(lines)


# ── Tool 12: shodan_host_lookup ──────────────────────────────────────────────


@mcp.tool()
async def shodan_host_lookup(ip: str, ctx: Context = None) -> str:
    """Look up a host on Shodan: open ports, running services, OS, CVEs on the host.
    Requires SHODAN_KEY environment variable.

    Args:
        ip: IPv4 address to look up (e.g. 8.8.8.8)
    """
    start = time.monotonic()
    params = {"ip": ip}

    try:
        clean_ip = validate_ip_address(ip)
    except ValueError as e:
        audit_record("shodan_host_lookup", params, "invalid_input", 0)
        return f"Invalid IP address: {e}"

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _shodan_host_lookup(clean_ip, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("shodan_host_lookup", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("shodan_host_lookup", params, "error", (time.monotonic() - start) * 1000)
        return f"Shodan lookup error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("shodan_host_lookup", params, "ok", duration)

    if result is None:
        return f"No Shodan data found for {clean_ip}."
    if "error" in result:
        return result["error"]
    if not result.get("found", True):
        return f"Host {clean_ip} not found in Shodan."

    ports = result.get("ports", [])
    vulns = result.get("vulns", [])
    services = result.get("services", [])
    hostnames = result.get("hostnames", [])

    lines = [
        f"=== Shodan Host: {clean_ip} ===\n",
        f"  Org:        {result.get('org', 'N/A')}",
        f"  Country:    {result.get('country_code', 'N/A')}",
        f"  OS:         {result.get('os', 'N/A')}",
        f"  Last Scan:  {result.get('last_update', 'N/A')}",
    ]
    if hostnames:
        lines.append(f"  Hostnames:  {', '.join(hostnames[:5])}")
    lines.append(f"\n  Open Ports ({len(ports)}):  {', '.join(str(p) for p in sorted(ports)[:20])}")
    if services:
        lines.append("\n  Services:")
        for svc in services[:10]:
            product = svc.get("product", "")
            version = svc.get("version", "")
            svc_str = f"    :{svc.get('port')} {svc.get('transport', 'tcp')}"
            if product:
                svc_str += f"  {product}"
            if version:
                svc_str += f" {version}"
            lines.append(svc_str)
    if vulns:
        lines.append(f"\n  CVEs on host ({len(vulns)}):  {', '.join(vulns[:10])}")
        if len(vulns) > 10:
            lines.append(f"    ... and {len(vulns) - 10} more")
    return "\n".join(lines)


# ── Tool 13: lookup_file_hash ────────────────────────────────────────────────


@mcp.tool()
async def lookup_file_hash(hash_str: str, ctx: Context = None) -> str:
    """Look up a file hash (MD5/SHA1/SHA256) against MalwareBazaar and VirusTotal.
    Returns malware family, detection stats, and file metadata.

    Args:
        hash_str: MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) hash
    """
    start = time.monotonic()
    params = {"hash_str": hash_str}

    clean_hash = validate_hash(hash_str)
    if not clean_hash:
        audit_record("lookup_file_hash", params, "invalid_input", 0)
        return (
            "Invalid hash format. Provide MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex).\n"
            f"Got: '{hash_str[:64]}...'"
            if len(hash_str) > 64
            else f"Got: '{hash_str}'"
        )

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _lookup_file_hash(clean_hash, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("lookup_file_hash", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("lookup_file_hash", params, "error", (time.monotonic() - start) * 1000)
        return f"Hash lookup error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("lookup_file_hash", params, "ok", duration)

    if not result.get("found"):
        sources = []
        if result.get("mb_checked"):
            sources.append("MalwareBazaar")
        if result.get("vt_checked"):
            sources.append("VirusTotal")
        src_str = " or ".join(sources) if sources else "any source"
        return f"Hash {clean_hash} not found in {src_str}."

    lines = [
        f"=== File Hash: {clean_hash} ===\n",
        f"  File Name:    {result.get('file_name', 'N/A')}",
        f"  File Type:    {result.get('file_type', 'N/A')}",
        f"  Malware:      {result.get('malware_family', 'N/A') or 'Unknown family'}",
    ]
    tags = result.get("tags", [])
    if tags:
        lines.append(f"  Tags:         {', '.join(tags[:10])}")

    vt_total = result.get("vt_total", 0)
    if vt_total:
        mal = result.get("vt_malicious", 0)
        sus = result.get("vt_suspicious", 0)
        lines.append(
            f"\n  VirusTotal:   {mal} malicious, {sus} suspicious out of {vt_total} engines"
        )
        detection_rate = (mal + sus) / vt_total * 100 if vt_total else 0
        lines.append(f"  Detection:    {detection_rate:.1f}%")
    elif not result.get("vt_checked"):
        lines.append("\n  Note: VIRUSTOTAL_KEY not set — VT stats unavailable.")
    return "\n".join(lines)


# ── Tool 14: check_url_safety ────────────────────────────────────────────────


@mcp.tool()
async def check_url_safety(url_or_domain: str, ctx: Context = None) -> str:
    """Check a URL or domain for malicious activity via URLScan.io.
    Returns scan verdicts, malicious flag, score, and categories.

    Args:
        url_or_domain: URL (https://example.com/path) or bare domain (example.com)
    """
    start = time.monotonic()
    params = {"url_or_domain": url_or_domain}

    target = url_or_domain.strip()
    if not target or len(target) > 2048:
        audit_record("check_url_safety", params, "invalid_input", 0)
        return "Invalid URL or domain. Provide a URL (https://...) or domain name."

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _check_url_safety(target, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("check_url_safety", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("check_url_safety", params, "error", (time.monotonic() - start) * 1000)
        return f"URL safety check error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("check_url_safety", params, "ok", duration)

    count = result.get("results_count", 0)
    if count == 0:
        return f"No URLScan.io results found for '{result.get('domain', target)}'."

    malicious = result.get("malicious", False)
    score = result.get("score", 0)
    categories = result.get("categories", [])

    lines = [
        f"=== URL Safety: {result.get('domain', target)} ===\n",
        f"  Verdict:      {'MALICIOUS' if malicious else 'CLEAN'}",
        f"  Score:        {score}",
        f"  Scans found:  {count}",
    ]
    if categories:
        lines.append(f"  Categories:   {', '.join(categories)}")
    screenshot = result.get("screenshot", "")
    if screenshot:
        lines.append(f"  Screenshot:   {screenshot}")

    scans = result.get("scans", [])
    if len(scans) > 1:
        lines.append("\n  Individual scan verdicts:")
        for s in scans[:5]:
            verdict_str = "MALICIOUS" if s.get("malicious") else "clean"
            lines.append(f"    {s.get('url', '')}  [{verdict_str}]  {s.get('ip', '')}")

    return "\n".join(lines)


# ── Tool 15: lookup_malware_family ───────────────────────────────────────────


@mcp.tool()
async def lookup_malware_family(ioc: str, ctx: Context = None) -> str:
    """Look up an IOC (IP, domain, URL, or hash) against ThreatFox for malware
    family attribution. Returns confidence level, IOC type, and threat classification.

    Args:
        ioc: Indicator of Compromise — IP address, domain, URL, MD5/SHA256 hash
    """
    start = time.monotonic()
    params = {"ioc": ioc}

    ioc_clean = ioc.strip()
    if not ioc_clean or len(ioc_clean) > 512:
        audit_record("lookup_malware_family", params, "invalid_input", 0)
        return "Invalid IOC. Provide an IP address, domain, URL, or file hash."

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _lookup_malware_family(ioc_clean, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("lookup_malware_family", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("lookup_malware_family", params, "error", (time.monotonic() - start) * 1000)
        return f"Malware family lookup error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("lookup_malware_family", params, "ok", duration)

    if not result.get("found"):
        return f"IOC '{ioc_clean}' not found in ThreatFox database."

    confidence = result.get("confidence", 0)
    tags = result.get("tags", [])
    lines = [
        f"=== ThreatFox IOC: {ioc_clean} ===\n",
        f"  IOC Type:       {result.get('ioc_type', 'N/A')}",
        f"  Malware Family: {result.get('malware_family', 'N/A')}",
        f"  Threat Type:    {result.get('threat_type', 'N/A')}",
        f"  Confidence:     {confidence}/100",
    ]
    alias = result.get("malware_alias", "")
    if alias:
        lines.append(f"  Aliases:        {alias}")
    if tags:
        lines.append(f"  Tags:           {', '.join(tags[:10])}")
    if result.get("first_seen"):
        lines.append(f"  First Seen:     {result.get('first_seen', '')[:10]}")
    if result.get("last_seen"):
        lines.append(f"  Last Seen:      {result.get('last_seen', '')[:10]}")
    if result.get("reference"):
        lines.append(f"  Reference:      {result.get('reference', '')}")
    return "\n".join(lines)


# ── Tool 16: check_ransomware_intel ─────────────────────────────────────────


@mcp.tool()
async def check_ransomware_intel(bitcoin_address: str, ctx: Context = None) -> str:
    """Check if a Bitcoin address is associated with a known ransomware family
    using the Ransomwhere database.

    Args:
        bitcoin_address: Bitcoin wallet address to look up (P2PKH, P2SH, or bech32)
    """
    start = time.monotonic()
    params = {"bitcoin_address": bitcoin_address}

    addr = bitcoin_address.strip()
    # Bitcoin addresses: 25-62 chars, alphanumeric (base58 or bech32)
    if not addr or len(addr) < 25 or len(addr) > 90:
        audit_record("check_ransomware_intel", params, "invalid_input", 0)
        return "Invalid Bitcoin address. Provide a valid P2PKH (1...), P2SH (3...), or bech32 (bc1...) address."

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _check_ransomware_intel(addr, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("check_ransomware_intel", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record("check_ransomware_intel", params, "error", (time.monotonic() - start) * 1000)
        return f"Ransomware intel error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("check_ransomware_intel", params, "ok", duration)

    if not result.get("found"):
        return f"Bitcoin address {addr} not found in Ransomwhere database."

    lines = [
        f"=== Ransomware Intel: {addr} ===\n",
        f"  Ransomware Family:  {result.get('family', 'Unknown')}",
        f"  Transactions found: {result.get('transactions', 0)}",
    ]
    entries = result.get("entries", [])
    if entries:
        lines.append("\n  Recent entries:")
        for e in entries[:5]:
            usd = e.get("usd_equivalent", 0)
            usd_str = f"  ${usd:,.2f}" if usd else ""
            lines.append(f"    {e.get('family', '?')}  {e.get('created_at', '')[:10]}{usd_str}")
    return "\n".join(lines)


# ── Tool 17: get_vendor_advisory ─────────────────────────────────────────────


@mcp.tool()
async def get_vendor_advisory(cve_id: str, ctx: Context = None) -> str:
    """Fetch vendor security advisories for a CVE from Microsoft (MSRC),
    Red Hat, and Ubuntu. Shows patch availability and affected products.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("get_vendor_advisory", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _get_vendor_advisories(clean, app.client, app.cache),
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        audit_record("get_vendor_advisory", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 20 seconds."
    except Exception as exc:
        audit_record("get_vendor_advisory", params, "error", (time.monotonic() - start) * 1000)
        return f"Vendor advisory error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("get_vendor_advisory", params, "ok", duration)

    ms = result.get("microsoft", [])
    rh = result.get("redhat", [])
    ub = result.get("ubuntu", [])

    if not ms and not rh and not ub:
        return f"No vendor advisories found for {clean} in Microsoft, Red Hat, or Ubuntu databases."

    lines = [f"=== Vendor Advisories: {clean} ===\n"]

    if ms:
        lines.append(f"Microsoft MSRC  ({len(ms)} entries):")
        for a in ms[:5]:
            severity = a.get("severity", "")
            product = a.get("product", "")
            title = a.get("title", "")
            url = a.get("article_url", "")
            lines.append(f"  [{severity}] {product}  {title}")
            if url:
                lines.append(f"           {url}")
    else:
        lines.append("Microsoft MSRC: No advisory found.")

    lines.append("")

    if rh:
        lines.append(f"Red Hat Security  ({len(rh)} entries):")
        for a in rh[:5]:
            pkg = a.get("package", "")
            adv = a.get("advisory", "")
            sev = a.get("severity", "")
            rel = a.get("release_date", "")[:10]
            lines.append(f"  [{sev}] {pkg}  {adv}  {rel}")
    else:
        lines.append("Red Hat Security: No advisory found.")

    lines.append("")

    if ub:
        lines.append(f"Ubuntu Security  ({len(ub)} entries):")
        seen_pkgs: set[str] = set()
        for a in ub[:10]:
            pkg = a.get("package", "")
            release = a.get("release", "")
            status = a.get("status", "")
            priority = a.get("priority", "")
            if pkg and pkg not in seen_pkgs:
                seen_pkgs.add(pkg)
                lines.append(f"  {pkg}  ({release})  status={status}  priority={priority}")
    else:
        lines.append("Ubuntu Security: No advisory found.")

    return "\n".join(lines)


# ── Tool 18: check_exploit_availability ─────────────────────────────────────


@mcp.tool()
async def check_exploit_availability(cve_id: str, ctx: Context = None) -> str:
    """Search GitHub for public proof-of-concept (PoC) exploit repositories for a CVE.
    Results are sorted by star count to surface the most credible exploits first.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("check_exploit_availability", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _search_exploits(clean, app.client, app.cache),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record(
            "check_exploit_availability", params, "error", (time.monotonic() - start) * 1000
        )
        return "Request timed out after 15 seconds."
    except Exception as exc:
        audit_record(
            "check_exploit_availability", params, "error", (time.monotonic() - start) * 1000
        )
        return f"Exploit search error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("check_exploit_availability", params, "ok", duration)

    pocs = result.get("github_pocs", [])
    if not pocs:
        return f"No public PoC repositories found on GitHub for {clean}."

    lines = [
        f"=== Exploit Availability: {clean} ===\n",
        f"  Public PoCs found: {result.get('poc_count', len(pocs))}  (via GitHub search)\n",
    ]
    for poc in pocs:
        stars = poc.get("stars", 0)
        forks = poc.get("forks", 0)
        lang = poc.get("language", "")
        desc = poc.get("description", "")
        lines.append(f"  {poc.get('repo', '')}  ★{stars} ⑂{forks}  [{lang}]")
        if desc:
            lines.append(f"    {desc[:120]}")
        lines.append(f"    {poc.get('url', '')}  (updated {poc.get('updated_at', '')[:10]})")
        lines.append("")
    return "\n".join(lines)


# ── Tool 19: get_attack_mapping ──────────────────────────────────────────────


@mcp.tool()
async def get_attack_mapping(cve_id: str, ctx: Context = None) -> str:
    """Map a CVE to MITRE ATT&CK techniques and associated threat groups.
    Downloads the ATT&CK dataset lazily (cached 24h). Searches technique
    descriptions and references for the CVE ID.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("get_attack_mapping", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _map_cve_to_attack(clean, app.client, app.cache),
            timeout=60.0,  # ATT&CK dataset can take time on first load
        )
    except asyncio.TimeoutError:
        audit_record("get_attack_mapping", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 60 seconds (ATT&CK dataset may be loading — retry shortly)."
    except Exception as exc:
        audit_record("get_attack_mapping", params, "error", (time.monotonic() - start) * 1000)
        return f"ATT&CK mapping error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("get_attack_mapping", params, "ok", duration)

    techniques = result.get("techniques", [])
    groups = result.get("threat_groups", [])

    if not techniques:
        return f"No MITRE ATT&CK techniques found referencing {clean}."

    lines = [
        f"=== ATT&CK Mapping: {clean} ===\n",
        f"  Techniques found: {len(techniques)}",
        f"  Threat groups using these techniques: {len(groups)}\n",
    ]
    for t in techniques[:10]:
        tactic_str = ", ".join(t.get("tactics", []))
        lines.append(f"  {t.get('technique_id', '?')}  {t.get('name', '')}")
        if tactic_str:
            lines.append(f"    Tactics: {tactic_str}")
        if t.get("url"):
            lines.append(f"    {t.get('url', '')}")
        desc = t.get("description", "")
        if desc:
            lines.append(f"    {desc[:200]}...")
        lines.append("")

    if groups:
        lines.append("  Threat groups using these techniques:")
        for g in groups[:15]:
            lines.append(f"    {g}")

    return "\n".join(lines)


# ── Tool 20: get_cve_timeline ────────────────────────────────────────────────


@mcp.tool()
async def get_cve_timeline(cve_id: str, ctx: Context = None) -> str:
    """Build a complete CVE lifecycle timeline: NVD publication date, EPSS score history,
    CISA KEV addition date, patch lag, and exploit window estimation.

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228)
    """
    start = time.monotonic()
    params = {"cve_id": cve_id}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("get_cve_timeline", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    app = _get_app(ctx)

    nvd_task = asyncio.create_task(fetch_cve(clean, app.client, app.limiter, app.cache))
    epss_task = asyncio.create_task(get_epss([clean], app.client, app.cache))

    try:
        nvd_res, epss_res = await asyncio.wait_for(
            asyncio.gather(nvd_task, epss_task, return_exceptions=True),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        audit_record("get_cve_timeline", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 15 seconds."

    nvd_data = nvd_res if not isinstance(nvd_res, Exception) else None
    epss_list = epss_res if not isinstance(epss_res, Exception) else []
    kev_entry = lookup_kev(app.kev_catalog, clean)

    timeline = _compute_cve_timeline(clean, nvd_data, epss_list, kev_entry)

    duration = (time.monotonic() - start) * 1000
    audit_record("get_cve_timeline", params, "ok", duration)

    lines = [f"=== CVE Timeline: {clean} ===\n"]

    nvd_pub = timeline.get("nvd_published", "")
    nvd_mod = timeline.get("nvd_last_modified", "")
    if nvd_pub:
        lines.append(f"  NVD Published:     {nvd_pub[:10]}")
    if nvd_mod:
        lines.append(f"  NVD Last Modified: {nvd_mod[:10]}")

    epss_score = timeline.get("epss_score", 0.0)
    epss_pct = timeline.get("epss_percentile", 0.0)
    epss_date = timeline.get("epss_date", "")
    if epss_score:
        lines.append(
            f"  EPSS Score:        {epss_score * 100:.2f}%  "
            f"(percentile: {epss_pct * 100:.1f}th, as of {epss_date[:10] if epss_date else 'N/A'})"
        )

    kev_date = timeline.get("kev_date_added", "")
    kev_due = timeline.get("kev_due_date", "")
    kev_ransom = timeline.get("kev_ransomware", "")
    if kev_date:
        lines.append(
            f"  CISA KEV Added:    {kev_date[:10]}  (due {kev_due[:10] if kev_due else 'N/A'})"
        )
        if kev_ransom:
            lines.append(f"  Ransomware Use:    {kev_ransom}")
    else:
        lines.append("  CISA KEV:          Not in catalog")

    lines.append("")
    patch_lag = timeline.get("patch_lag_days", -1)
    if patch_lag >= 0:
        lines.append(f"  Patch Lag:         {patch_lag} days  (NVD publication → KEV addition)")
    exploit_window = timeline.get("exploit_window_days", -1)
    if exploit_window >= 0:
        lines.append(
            f"  Exploit Window:    {exploit_window} days  (NVD publication → first EPSS >50% or KEV)"
        )

    return "\n".join(lines)


# ── Tool 21: scan_dependencies ───────────────────────────────────────────────


@mcp.tool()
async def scan_dependencies(dependency_list: str, ctx: Context = None) -> str:
    """Bulk scan application dependencies for known CVEs via OSV.dev.
    Supports requirements.txt (PyPI), package.json (npm), pom.xml (Maven),
    or generic 'name:ecosystem:version' lines. Returns only vulnerable packages.

    Args:
        dependency_list: Raw contents of requirements.txt, package.json, pom.xml,
                         or newline-separated 'name:ecosystem:version' entries.
                         Max 1000 packages per call.
    """
    start = time.monotonic()
    params = {"dependency_list": f"[{len(dependency_list)} chars]"}

    if not dependency_list.strip():
        audit_record("scan_dependencies", params, "invalid_input", 0)
        return "Empty dependency list provided."

    packages = parse_dependency_list(dependency_list)
    if not packages:
        audit_record("scan_dependencies", params, "invalid_input", 0)
        return (
            "Could not parse any packages from the input.\n"
            "Supported formats: requirements.txt, package.json, pom.xml, "
            "or 'name:ecosystem:version' lines."
        )

    # Cap at 1000 packages per OSV batch limit
    packages = packages[:1000]

    app = _get_app(ctx)
    try:
        results = await asyncio.wait_for(
            _scan_dependencies_bulk(packages, app.client, app.cache),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        audit_record("scan_dependencies", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 60 seconds."
    except Exception as exc:
        audit_record("scan_dependencies", params, "error", (time.monotonic() - start) * 1000)
        return f"Dependency scan error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("scan_dependencies", params, "ok", duration)

    if not results:
        return f"No known vulnerabilities found in {len(packages)} scanned packages. (via OSV.dev)"

    lines = [
        f"Dependency Scan Results  ({len(results)} vulnerable out of {len(packages)} packages)\n"
    ]
    for pkg in results:
        eco = pkg.get("ecosystem", "")
        name = pkg.get("package", "")
        ver = pkg.get("version", "")
        count = pkg.get("vuln_count", 0)
        ver_str = f"@{ver}" if ver else ""
        lines.append(f"  {eco}/{name}{ver_str}  →  {count} vulnerability/vulnerabilities")
        for v in pkg.get("vulns", []):
            sev = v.get("severity", "UNKNOWN")
            vid = v.get("id", "")
            aliases = v.get("aliases", [])
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), "")
            alias_str = f"  ({cve_alias})" if cve_alias else ""
            summary = v.get("summary", "")[:100]
            lines.append(f"    [{sev}] {vid}{alias_str}: {summary}")
        lines.append("")
    return "\n".join(lines)


# ── Tool 22: scan_container_packages ────────────────────────────────────────


@mcp.tool()
async def scan_container_packages(packages: str, ctx: Context = None) -> str:
    """Scan container image packages (Alpine, Debian, Ubuntu OS packages) for
    known CVEs via OSV.dev. Input should be 'name:ecosystem:version' lines,
    one package per line, e.g. from 'apk info -v' or 'dpkg -l' output.

    Supported ecosystems: Alpine, Debian, Ubuntu, and any OSV-supported ecosystem.

    Args:
        packages: Newline-separated 'name:ecosystem:version' entries.
                  Example:
                    openssl:Alpine:3.0.7-r0
                    musl:Alpine:1.2.4_r2
                    libssl3:Debian:3.0.7-1
    """
    start = time.monotonic()
    params = {"packages": f"[{len(packages)} chars]"}

    if not packages.strip():
        audit_record("scan_container_packages", params, "invalid_input", 0)
        return (
            "Empty package list. Provide 'name:ecosystem:version' lines.\n"
            "Example: openssl:Alpine:3.0.7-r0"
        )

    pkg_list = parse_dependency_list(packages)
    if not pkg_list:
        audit_record("scan_container_packages", params, "invalid_input", 0)
        return (
            "Could not parse any packages. Use 'name:ecosystem:version' format.\n"
            "Supported ecosystems: Alpine, Debian, Ubuntu, PyPI, npm, Maven, etc."
        )

    pkg_list = pkg_list[:1000]

    app = _get_app(ctx)
    try:
        results = await asyncio.wait_for(
            _scan_dependencies_bulk(pkg_list, app.client, app.cache),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        audit_record("scan_container_packages", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 60 seconds."
    except Exception as exc:
        audit_record("scan_container_packages", params, "error", (time.monotonic() - start) * 1000)
        return f"Container scan error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("scan_container_packages", params, "ok", duration)

    if not results:
        return (
            f"No known vulnerabilities found in {len(pkg_list)} scanned container packages. "
            f"(via OSV.dev)"
        )

    lines = [
        f"Container Package Scan  ({len(results)} vulnerable out of {len(pkg_list)} packages)\n"
    ]
    for pkg in results:
        eco = pkg.get("ecosystem", "")
        name = pkg.get("package", "")
        ver = pkg.get("version", "")
        count = pkg.get("vuln_count", 0)
        ver_str = f":{ver}" if ver else ""
        lines.append(f"  {name}{ver_str}  [{eco}]  →  {count} vulnerability/vulnerabilities")
        for v in pkg.get("vulns", []):
            sev = v.get("severity", "UNKNOWN")
            vid = v.get("id", "")
            aliases = v.get("aliases", [])
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), "")
            alias_str = f"  ({cve_alias})" if cve_alias else ""
            summary = v.get("summary", "")[:100]
            lines.append(f"    [{sev}] {vid}{alias_str}: {summary}")
        lines.append("")
    return "\n".join(lines)


# ── Tool 23: scan_repo_secrets ────────────────────────────────────────────────


@mcp.tool()
async def scan_repo_secrets(search_term: str, ctx: Context = None) -> str:
    """Search GitHub public repositories for potential exposed credentials or secrets
    related to a search term (CVE ID, tool name, or keyword).
    Requires GITHUB_TOKEN for best results. For security research only.

    Args:
        search_term: CVE ID, tool name, or keyword to search for in public repo files
                     (e.g. CVE-2024-1234, AWS_SECRET_ACCESS_KEY, log4j)
    """
    start = time.monotonic()
    params = {"search_term": search_term}

    term = search_term.strip()
    if not term or len(term) > 200:
        audit_record("scan_repo_secrets", params, "invalid_input", 0)
        return "Invalid search term. Provide a CVE ID, tool name, or keyword (max 200 chars)."

    app = _get_app(ctx)
    try:
        result = await asyncio.wait_for(
            _scan_repo_secrets(term, app.client, app.cache),
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        audit_record("scan_repo_secrets", params, "error", (time.monotonic() - start) * 1000)
        return "Request timed out after 20 seconds."
    except Exception as exc:
        audit_record("scan_repo_secrets", params, "error", (time.monotonic() - start) * 1000)
        return f"Secret scan error: {exc}"

    duration = (time.monotonic() - start) * 1000
    audit_record("scan_repo_secrets", params, "ok", duration)

    if "error" in result:
        return result["error"]

    if not result.get("searched"):
        return "Search could not be completed."

    total = result.get("total_count", 0)
    matches = result.get("matches", [])

    if not matches:
        return f"No public GitHub files found matching '{term}'."

    lines = [
        f"GitHub Public Secret/Exposure Search: '{term}'\n",
        f"  Approximate total matches: {total:,}",
        f"  Showing top {len(matches)}:\n",
    ]
    for m in matches:
        lines.append(f"  {m.get('repo', '')} — {m.get('file_path', '')}")
        lines.append(f"    {m.get('file_url', '')}")

    lines.append("\n  Note: This shows publicly visible files only. For authorized research use.")
    return "\n".join(lines)


# ── Phase 3: PoC Intelligence ──────────────────────────────────────────────


@mcp.tool()
async def check_poc_exists(
    cve_id: str,
    include_github: bool = True,
    include_exploitdb: bool = True,
    ctx: Context = None,
) -> str:
    """Search for proof-of-concept exploits across GitHub, Exploit-DB, and Nuclei templates."""
    start = time.monotonic()
    from cve_mcp.api.poc_checker import search_poc_existence

    app = _get_app(ctx)
    client = app.client
    cache = app.cache
    result = await search_poc_existence(cve_id, client, cache, include_github, include_exploitdb)

    lines = [
        f"PoC Intelligence: {cve_id}",
        f"Confidence: {result['confidence']} — {result['confidence_label']}",
        "",
    ]
    if result["github_results"]:
        lines.append(f"GitHub Repositories ({len(result['github_results'])}):")
        for r in result["github_results"][:5]:
            lines.append(f"  • {r['full_name']} ⭐{r['stars']} — {r['html_url']}")
    if result["exploitdb_results"]:
        lines.append(f"\nExploit-DB Entries ({len(result['exploitdb_results'])}):")
        for e in result["exploitdb_results"][:5]:
            lines.append(f"  • [{e['id']}] {e['description']} ({e['type']})")
    if result["nuclei_templates"]:
        lines.append(f"\nNuclei Templates ({len(result['nuclei_templates'])}):")
        for t in result["nuclei_templates"][:3]:
            lines.append(f"  • {t['name']} — {t['html_url']}")
    if result["total_sources_found"] == 0:
        lines.append("No public PoC or exploit found.")
    duration = (time.monotonic() - start) * 1000
    audit_record("check_poc_exists", {"cve_id": cve_id}, "ok", duration)
    return "\n".join(lines)


# ── Phase 3: Risk Scoring ──────────────────────────────────────────────────


@mcp.tool()
async def calculate_risk_score(cve_id: str, ctx: Context = None) -> str:
    """Calculate a composite 0-100 risk score using CVSS, EPSS, KEV, and PoC data."""
    start = time.monotonic()
    from cve_mcp.api.poc_checker import search_poc_existence
    from cve_mcp.utils.risk_scorer import score_cve

    app = _get_app(ctx)

    nvd_data, epss_scores, poc_result = await asyncio.gather(
        fetch_cve(cve_id, app.client, app.limiter, app.cache),
        get_epss([cve_id], app.client, app.cache),
        search_poc_existence(cve_id, app.client, app.cache),
        return_exceptions=True,
    )
    kev_entry = lookup_kev(app.kev_catalog, cve_id)

    for name, val in [("nvd", nvd_data), ("epss", epss_scores), ("poc", poc_result)]:
        if isinstance(val, Exception):
            logger.warning("Error fetching %s for %s: %s", name, cve_id, val)

    epss_data = None
    if not isinstance(epss_scores, Exception) and epss_scores:
        epss_data = {"probability": epss_scores[0].epss}

    result = score_cve(
        cve_id,
        nvd_data if not isinstance(nvd_data, Exception) else None,
        epss_data,
        kev_entry,
        poc_result if not isinstance(poc_result, Exception) else None,
    )

    duration = (time.monotonic() - start) * 1000
    audit_record("calculate_risk_score", {"cve_id": cve_id}, "ok", duration)

    c = result["components"]
    lines = [
        f"Risk Score: {result['cve_id']}",
        f"Score: {result['risk_score']}/100 ({result['risk_label']})",
        f"Urgency: {result['urgency']}",
        f"Recommendation: {result['recommendation']}",
        "",
        "Component Breakdown:",
        f"  CVSS {c['cvss_score']:.1f}  → {c['cvss_contribution']:.1f}/20 pts",
        f"  EPSS {c['epss_probability'] * 100:.1f}% → {c['epss_contribution']:.1f}/35 pts",
        f"  KEV  {'Yes' if c['in_kev'] else 'No'}   → {c['kev_contribution']:.0f}/30 pts",
        f"  PoC  {c['poc_confidence']}  → {c['poc_contribution']:.0f}/15 pts",
    ]
    if result["boosters_applied"]:
        lines.append(f"\nBoosters: {', '.join(result['boosters_applied'])}")
    if result["days_since_published"] is not None:
        lines.append(f"Age: {result['days_since_published']} days since published")
    return "\n".join(lines)


# ── Phase 3: Vulnerability Reports ─────────────────────────────────────────


@mcp.tool()
async def generate_vuln_report(
    cve_id: str,
    format: str = "technical",
    include_remediation: bool = True,
    ctx: Context = None,
) -> str:
    """Generate a vulnerability report in executive, technical, or full format."""
    start = time.monotonic()
    from cve_mcp.api.report_generator import build_vuln_report

    if format not in {"executive", "technical", "full"}:
        return f"Invalid format '{format}'. Use: executive, technical, or full."
    app = _get_app(ctx)
    client = app.client
    cache = app.cache
    result = await build_vuln_report(
        cve_id, format, include_remediation, client, cache, limiter=app.limiter
    )
    duration = (time.monotonic() - start) * 1000
    audit_record("generate_vuln_report", {"cve_id": cve_id, "format": format}, "ok", duration)
    return result["report_text"]


@mcp.tool()
async def compare_cves(cve_ids: list[str], ctx: Context = None) -> str:
    """Compare multiple CVEs by risk score and generate a patch priority ranking."""
    start = time.monotonic()
    from cve_mcp.api.report_generator import build_cve_comparison

    if not (2 <= len(cve_ids) <= 10):
        return "Provide between 2 and 10 CVE IDs to compare."
    app = _get_app(ctx)
    client = app.client
    cache = app.cache
    result = await build_cve_comparison(cve_ids, client, cache, limiter=app.limiter)

    lines = ["CVE Comparison — Patch Priority Ranking", "=" * 60]
    lines.append(
        f"{'Rank':<5} {'CVE ID':<20} {'Score':<8} {'Label':<10} {'KEV':<5} {'EPSS%':<8} {'Urgency'}"
    )
    lines.append("-" * 80)
    for row in result["comparison_matrix"]:
        lines.append(
            f"{row['patch_priority_rank']:<5} {row['cve_id']:<20} "
            f"{row['risk_score']:<8.1f} {row['risk_label']:<10} "
            f"{'Yes' if row['in_kev'] else 'No':<5} "
            f"{row['epss_probability'] * 100:<8.1f} {row['urgency']}"
        )
    lines.append("")
    lines.append(result["summary"])
    duration = (time.monotonic() - start) * 1000
    audit_record("compare_cves", {"cve_ids": cve_ids}, "ok", duration)
    return "\n".join(lines)


# ── v0.2.0 Orchestrator: triage_cve ─────────────────────────────────────────


def _epss_to_dict(epss) -> dict | None:
    """Adapt an EPSSScore (or None) into the {"probability": float} shape that
    risk_scorer.score_cve and ssvc.ssvc_decision consume."""
    if epss is None:
        return None
    prob = getattr(epss, "epss", None)
    if prob is None and isinstance(epss, dict):
        prob = epss.get("epss", epss.get("probability"))
    if prob is None:
        return None
    try:
        return {"probability": float(prob)}
    except (TypeError, ValueError):
        return None


@mcp.tool()
async def triage_cve(cve_id: str, depth: str = "standard", ctx: Context = None) -> str:
    """One-call CVE triage orchestrator (v0.2.0).

    Fans out the relevant upstream sources concurrently — NVD (with a transparent
    VulnCheck NVD++ fallback when NVD fails), EPSS, the CISA KEV catalog, and
    (for depth != "quick") public PoC/exploit discovery — then computes the
    composite risk score (KEV hard-override applies: a KEV-listed CVE is always
    CRITICAL with score >= 76). For depth == "deep" it additionally emits an
    SSVC v2 gated decision (Act / Attend / Track* / Track).

    Args:
        cve_id: CVE identifier (e.g. CVE-2021-44228).
        depth: "quick"    — NVD + EPSS + KEV (no PoC search; fastest),
               "standard" — adds PoC/exploit discovery (default),
               "deep"     — adds an SSVC v2 qualitative decision.
    """
    start = time.monotonic()
    params = {"cve_id": cve_id, "depth": depth}

    clean = normalize_cve(cve_id)
    if not clean:
        audit_record("triage_cve", params, "invalid_input", 0)
        return "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)"

    depth_norm = (depth or "standard").strip().lower()
    if depth_norm not in {"quick", "standard", "deep"}:
        audit_record("triage_cve", params, "invalid_input", 0)
        return "Invalid depth. Use one of: quick, standard, deep."

    app = _get_app(ctx)
    want_poc = depth_norm != "quick"

    # Fan out NVD + EPSS (+ PoC) concurrently; KEV is in-memory (no I/O).
    coros = [
        fetch_cve(clean, app.client, app.limiter, app.cache),
        get_epss([clean], app.client, app.cache),
    ]
    if want_poc:
        coros.append(search_poc_existence(clean, app.client, app.cache))

    results = await fan_out(*coros, timeout=45.0)
    nvd_record = results[0]
    epss_list = results[1] or []
    poc_result = results[2] if want_poc and len(results) > 2 else None

    # Transparent NVD fallback via VulnCheck NVD++ when the primary source failed.
    fallback_used = False
    if nvd_record is None:
        vc_data = await fetch_cve_vulncheck(clean, app.client, app.cache)
        if vc_data is not None:
            try:
                nvd_record = CVERecord.model_validate(vc_data)
                fallback_used = True
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("VulnCheck fallback record invalid for %s: %s", clean, exc)
                nvd_record = None

    epss_obj = epss_list[0] if epss_list else None
    epss_dict = _epss_to_dict(epss_obj)
    kev_entry = lookup_kev(app.kev_catalog, clean)

    scored = score_cve(clean, nvd_record, epss_dict, kev_entry, poc_result)

    duration = (time.monotonic() - start) * 1000
    audit_record("triage_cve", params, "ok", duration)

    # ── Build the report ─────────────────────────────────────────────────
    c = scored["components"]
    lines = [
        f"=== CVE Triage: {clean} ===",
        f"Depth: {depth_norm}   Scoring version: {scored.get('scoring_version', SCORING_VERSION)}",
        "",
        f"RISK SCORE: {scored['risk_score']}/100  ({scored['risk_label']})",
        f"Urgency:    {scored['urgency']}",
        f"Action:     {scored['recommendation']}",
        "",
        "SIGNALS:",
    ]

    if nvd_record is not None:
        vector_str, score, severity = _get_vector(nvd_record.metrics)
        sev_line = (
            f"  CVSS:   {score} {severity}".rstrip()
            if score
            else "  CVSS:   (no CVSS in NVD record)"
        )
        lines.append(sev_line)
        if vector_str:
            lines.append(f"  Vector: {vector_str}")
        src = "VulnCheck NVD++ (NVD fallback)" if fallback_used else "NVD"
        lines.append(f"  Source: {src}")
    else:
        lines.append("  CVSS:   (NVD/VulnCheck data unavailable)")

    if epss_obj is not None:
        lines.append(
            f"  EPSS:   {float(epss_obj.epss) * 100:.2f}% "
            f"(percentile {float(epss_obj.percentile) * 100:.1f}th, as of {epss_obj.date})"
        )
    else:
        lines.append("  EPSS:   (unavailable)")

    if kev_entry is not None:
        ransom = kev_entry.knownRansomwareCampaignUse or "Unknown"
        lines.append(
            f"  KEV:    YES — added {kev_entry.dateAdded}, due {kev_entry.dueDate}, "
            f"ransomware: {ransom}  (HARD OVERRIDE → CRITICAL)"
        )
    else:
        lines.append("  KEV:    NO")

    if want_poc:
        if poc_result:
            lines.append(
                f"  PoC:    {poc_result.get('confidence', 'NONE')} "
                f"({poc_result.get('confidence_label', '')}) — "
                f"{poc_result.get('total_sources_found', 0)} public source(s)"
            )
        else:
            lines.append("  PoC:    (search unavailable)")

    lines.append("")
    lines.append("SCORE BREAKDOWN:")
    lines.append(f"  CVSS {c['cvss_score']:.1f}  → {c['cvss_contribution']:.1f}/20 pts")
    lines.append(f"  EPSS {c['epss_probability'] * 100:.1f}% → {c['epss_contribution']:.1f}/35 pts")
    lines.append(f"  KEV  {'Yes' if c['in_kev'] else 'No'}   → {c['kev_contribution']:.0f}/30 pts")
    lines.append(f"  PoC  {c['poc_confidence']}  → {c['poc_contribution']:.0f}/15 pts")
    if scored["boosters_applied"]:
        lines.append(f"  Boosters: {', '.join(scored['boosters_applied'])}")
    if scored["days_since_published"] is not None:
        lines.append(f"  Age: {scored['days_since_published']} days since published")

    # ── Deep mode: SSVC v2 gated decision ────────────────────────────────
    if depth_norm == "deep":
        ssvc = ssvc_decision(
            in_kev=bool(kev_entry),
            epss_probability=(epss_dict or {}).get("probability", 0.0),
            poc_confidence=c["poc_confidence"],
            cvss_score=c["cvss_score"],
            exposure="open",
        )
        d = ssvc["decision"]
        lines.append("")
        lines.append(f"SSVC DECISION (v{ssvc['scoring_version']}, CISA Deployer model):")
        lines.append(f"  Action: {ssvc['action']}")
        lines.append(
            f"  Path:   Exploitation={d['exploitation']}, Automatable={d['automatable']}, "
            f"TechnicalImpact={d['technical_impact']}, Mission&Wellbeing={d['mission_wellbeing']}, "
            f"Exposure={d['exposure']}"
        )
        lines.append(f"  {ssvc['rationale']}")

    return "\n".join(lines)


# ── v0.2.0 Resources ────────────────────────────────────────────────────────


@mcp.resource(
    "kev://catalog",
    description=(
        "Summary of the pre-warmed CISA Known Exploited Vulnerabilities (KEV) "
        "catalog held in server memory: total entry count, ransomware-linked "
        "count, and the most recently added entries."
    ),
    mime_type="text/plain",
)
async def kev_catalog_resource() -> str:
    """Return a human-readable summary of the in-memory KEV catalog."""
    catalog = list(_kev_catalog_snapshot)
    total = len(catalog)
    if total == 0:
        return "CISA KEV catalog is empty (load failed or not yet fetched)."

    ransomware = sum(
        1 for e in catalog if (e.knownRansomwareCampaignUse or "").strip().lower() == "known"
    )

    def _added(e: KEVEntry) -> str:
        return e.dateAdded or ""

    recent = sorted(catalog, key=_added, reverse=True)[:10]
    lines = [
        "CISA KEV Catalog (pre-warmed, in-memory)",
        f"  Total entries:           {total}",
        f"  Ransomware-linked:       {ransomware}",
        "",
        "  Most recently added:",
    ]
    for e in recent:
        lines.append(
            f"    {e.cveID}  {e.dateAdded}  {e.vendorProject} — {e.product}: {e.vulnerabilityName}"
        )
    return "\n".join(lines)


@mcp.resource(
    "epss://scores/{cve_id}",
    description=(
        "EPSS (Exploit Prediction Scoring System) score for a single CVE: the "
        "30-day exploitation probability and its percentile, fetched from FIRST.org "
        "(cached). URI template: epss://scores/CVE-YYYY-NNNNN."
    ),
    mime_type="text/plain",
)
async def epss_score_resource(cve_id: str) -> str:
    """Return the EPSS score for ``cve_id`` as a short plain-text record."""
    clean = normalize_cve(cve_id)
    if not clean:
        return f"Invalid CVE ID '{cve_id}'. Expected CVE-YYYY-NNNNN."

    app = _resource_app()
    if app is None:
        return "EPSS resource unavailable: server context not initialized."

    try:
        scores = await asyncio.wait_for(get_epss([clean], app.client, app.cache), timeout=15.0)
    except asyncio.TimeoutError:
        return f"EPSS lookup for {clean} timed out."
    except Exception as exc:
        return f"EPSS lookup error for {clean}: {exc}"

    if not scores:
        return f"No EPSS data found for {clean}."
    s = scores[0]
    return (
        f"EPSS for {s.cve}\n"
        f"  Probability: {float(s.epss) * 100:.2f}%  (30-day exploitation likelihood)\n"
        f"  Percentile:  {float(s.percentile) * 100:.1f}th\n"
        f"  As of:       {s.date}"
    )


@mcp.resource(
    "manifest://tool-hash",
    description=(
        "Stable SHA-256 over the canonical JSON of every registered tool's "
        "{name, description, inputSchema}, sorted by name. Lets a client pin and "
        "verify the server's tool surface (detects added/removed/renamed tools "
        "or changed argument schemas)."
    ),
    mime_type="text/plain",
)
async def tool_manifest_resource() -> str:
    """Return the tool-manifest SHA-256 plus the count of registered tools."""
    tools = await mcp.list_tools()
    digest = await _compute_tool_manifest_hash()
    return (
        "Tool Manifest Hash (SHA-256 over sorted {name, description, inputSchema})\n"
        f"  Registered tools: {len(tools)}\n"
        f"  Server version:   {SERVER_VERSION}\n"
        f"  sha256: {digest}"
    )


# ── v0.2.0 Prompts ──────────────────────────────────────────────────────────


@mcp.prompt(
    title="Patch decision",
    description="Decide whether to patch a CVE now, using the triage_cve orchestrator.",
)
def patch_decision(cve_id: str, asset_context: str = "internet-facing") -> str:
    """Guide the model to make an evidence-based patch decision for one CVE."""
    return (
        f"You are a vulnerability-management analyst. Decide whether {cve_id} must "
        f"be patched now for an asset that is {asset_context}.\n\n"
        f'Step 1: Call the `triage_cve` tool with cve_id="{cve_id}" and '
        f'depth="deep" (deep mode adds the SSVC gated decision, which is ideal '
        f"for a go/no-go patch call).\n"
        f"Step 2: From the tool output, weigh the risk score & label, the CISA KEV "
        f"status (KEV is a hard override → treat as CRITICAL / patch immediately), "
        f"the EPSS probability, public PoC availability, and the SSVC action band "
        f"(Act / Attend / Track* / Track).\n"
        f"Step 3: Give a clear PATCH NOW vs. SCHEDULE recommendation with a "
        f"concrete timeframe, explicitly tied to the {asset_context} exposure, and "
        f"cite the specific signals (score, KEV, EPSS, PoC, SSVC) that drove it."
    )


@mcp.prompt(
    title="Compare and prioritize CVEs",
    description="Rank several CVEs for patch priority using triage_cve / compare_cves.",
)
def compare_and_prioritize(cve_ids: str) -> str:
    """Guide the model to triage and rank a comma-separated list of CVEs."""
    return (
        "You are triaging a batch of vulnerabilities for patch prioritization.\n\n"
        f"CVEs to rank (comma-separated): {cve_ids}\n\n"
        'Step 1: For EACH CVE, call the `triage_cve` tool (depth="standard") to '
        "obtain its composite risk score, KEV status, EPSS probability, and PoC "
        "availability. (For a quick side-by-side table you may also use the "
        "`compare_cves` tool with the same list.)\n"
        "Step 2: Rank the CVEs from most to least urgent. KEV-listed CVEs are a "
        "hard override and must sort to the top (always CRITICAL). Break ties with "
        "EPSS probability, then CVSS severity, then PoC availability.\n"
        "Step 3: Present a prioritized table (rank, CVE, score, label, KEV, EPSS%, "
        "urgency) followed by a one-line patch-order recommendation."
    )


@mcp.prompt(
    title="Dependency triage",
    description="Triage CVEs surfaced by a dependency/container scan via triage_cve.",
)
def dependency_triage(dependency_or_cves: str, ecosystem: str = "PyPI") -> str:
    """Guide the model to scan dependencies, then triage the resulting CVEs."""
    return (
        "You are triaging vulnerabilities found in application dependencies.\n\n"
        f"Input ({ecosystem}): {dependency_or_cves}\n\n"
        "Step 1: If the input is raw dependency content (requirements.txt, "
        "package.json, pom.xml, or name:ecosystem:version lines), call "
        "`scan_dependencies` to discover vulnerable packages and their CVE IDs. "
        "If the input is already a list of CVE IDs, skip to Step 2.\n"
        "Step 2: For each discovered CVE, call the `triage_cve` tool "
        '(depth="standard") to get the composite risk score, KEV status, EPSS, '
        "and PoC availability.\n"
        "Step 3: Produce a remediation plan: which packages to upgrade first "
        "(KEV-listed and high-EPSS CVEs first), the fixed version to move to where "
        "known, and the urgency for each, so the team can patch in priority order."
    )


# ── Watchtower (additive package: cve_mcp.watchtower) ───────────────────────
# Estate inventory + exposure snapshots + change diffs. All logic lives in
# the watchtower package; this block only registers its four tools onto the
# shared FastMCP instance, reusing the lifespan AppContext (HTTP client,
# cache, pre-warmed KEV catalog) via _get_app.
from cve_mcp.watchtower.tools import register_watchtower as _register_watchtower

_register_watchtower(mcp, _get_app)


def main():
    # Transport selection (plan 5.1). MCP_TRANSPORT=http serves streamable-http
    # on HOST:PORT (stateless, container-friendly); anything else uses stdio.
    #
    # Per the verified MCP 1.28 API notes: FastMCP.run() ONLY accepts
    # (transport, mount_path). host/port/stateless_http are NOT run() kwargs —
    # they live on the FastMCP instance settings. We therefore set them on
    # mcp.settings before calling run("streamable-http").
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport in {"http", "streamable-http", "streamable_http"}:
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.settings.stateless_http = True
        logger.info("Starting cve-mcp on streamable-http at %s:%d (stateless)", host, port)
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
