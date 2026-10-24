"""MCP tool registrations for Watchtower.

Registered onto the base server's FastMCP instance by ``register_watchtower``
(called from a delimited block at the end of ``cve_mcp/server.py``). The
tools follow the base server's idiom exactly: validate input, call
``audit_record`` on every exit path, bound network work with
``asyncio.wait_for``, and return plain-text reports.

The estate store is a lazily-initialized module-level singleton: the estate
is server-lifetime state (that is the point of Watchtower), and its path
follows the base config idiom ($WATCHTOWER_DB_PATH or ~/.cve-mcp/estate.db).
"""

from __future__ import annotations

import asyncio
import logging
import time

from cve_mcp.api.epss_client import get_epss
from cve_mcp.api.kev_client import lookup_kev
from cve_mcp.api.osv_client import query_package
from cve_mcp.audit import record as audit_record
from cve_mcp.watchtower.brief import (
    render_brief,
    render_current_state_brief,
    render_diff,
    render_snapshot_summary,
)
from cve_mcp.watchtower.engine import DEFAULT_EPSS_THRESHOLD, diff_snapshots, take_snapshot
from cve_mcp.watchtower.parsers import parse_estate_text
from cve_mcp.watchtower.store import EstateStore, default_db_path

logger = logging.getLogger(__name__)

_store: EstateStore | None = None
_store_lock = asyncio.Lock()


async def get_store() -> EstateStore:
    """Return the shared estate store, initializing it on first use."""
    global _store
    if _store is None:
        async with _store_lock:
            if _store is None:
                store = EstateStore(default_db_path())
                await store.initialize()
                _store = store
    return _store


def set_store(store: EstateStore | None) -> None:
    """Swap the shared store (tests and embedding); None resets to lazy."""
    global _store
    _store = store


def _bind_live_intel(app):
    """Bind the base project's intel clients to the engine's callables."""

    async def osv_query(name: str, ecosystem: str, version: str) -> list[dict]:
        return await query_package(name, ecosystem, version, app.client, app.cache)

    def kev_lookup(cve_id: str):
        return lookup_kev(app.kev_catalog, cve_id)

    async def epss_query(cve_ids: list[str]):
        return await get_epss(cve_ids, app.client, app.cache)

    return osv_query, kev_lookup, epss_query


def register_watchtower(mcp, get_app) -> None:
    """Register the four Watchtower tools on the server's FastMCP instance.

    ``get_app`` is the base server's AppContext accessor (ctx -> AppContext)
    so Watchtower reuses the lifespan-managed HTTP client, cache, and the
    pre-warmed KEV catalog instead of opening its own.
    """

    @mcp.tool()
    async def estate_add(source_text: str, source_name: str = "", ctx=None) -> str:
        """Add packages to your Watchtower estate from an SBOM or lockfile.

        Paste the file contents: CycloneDX JSON, SPDX JSON, requirements.txt,
        package-lock.json, or go.mod. Packages are remembered persistently
        (ecosystem, name, version, first-seen date) so later scans can diff
        your exposure over time.

        Args:
            source_text: The SBOM/lockfile file contents.
            source_name: Optional original filename (helps format detection).
        """
        start = time.monotonic()
        params = {"source_name": source_name, "chars": len(source_text or "")}
        try:
            packages = parse_estate_text(source_text or "", source_name or "")
        except ValueError as exc:
            audit_record("estate_add", params, "invalid_input", 0)
            return f"Could not parse the input: {exc}"

        try:
            store = await get_store()
            added, total = await store.add_packages(packages)
        except Exception as exc:
            audit_record("estate_add", params, "error", (time.monotonic() - start) * 1000)
            return f"Estate store error: {exc}"

        audit_record("estate_add", params, "ok", (time.monotonic() - start) * 1000)
        by_ecosystem: dict[str, int] = {}
        for pkg in packages:
            by_ecosystem[pkg.ecosystem] = by_ecosystem.get(pkg.ecosystem, 0) + 1
        eco_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_ecosystem.items()))
        return (
            f"Estate updated: {added} new package(s) added, {total} total in the estate.\n"
            f"Parsed {len(packages)} package(s) from this input ({eco_str}).\n"
            "Run estate_scan to snapshot the estate's current exposure."
        )

    @mcp.tool()
    async def estate_scan(label: str = "", ctx=None) -> str:
        """Snapshot your estate's current vulnerability exposure.

        Queries OSV for every installed package, joins the CISA KEV catalog
        and current EPSS scores, and persists the result as a snapshot that
        watch_diff / watch_brief can compare against earlier snapshots.

        Args:
            label: Optional label for this snapshot (e.g. "monday", "pre-release").
        """
        start = time.monotonic()
        params = {"label": label}
        app = get_app(ctx)
        store = await get_store()
        if await store.package_count() == 0:
            audit_record("estate_scan", params, "invalid_input", 0)
            return (
                "The estate is empty. Add packages first with estate_add "
                "(paste an SBOM or lockfile)."
            )
        osv_query, kev_lookup, epss_query = _bind_live_intel(app)
        try:
            snapshot = await asyncio.wait_for(
                take_snapshot(
                    store,
                    osv_query=osv_query,
                    kev_lookup=kev_lookup,
                    epss_query=epss_query,
                    label=label,
                ),
                timeout=300.0,
            )
        except asyncio.TimeoutError:
            audit_record("estate_scan", params, "error", (time.monotonic() - start) * 1000)
            return "Estate scan timed out after 300 seconds. OSV may be under load."
        except Exception as exc:
            audit_record("estate_scan", params, "error", (time.monotonic() - start) * 1000)
            return f"Estate scan error: {exc}"

        audit_record("estate_scan", params, "ok", (time.monotonic() - start) * 1000)
        return render_snapshot_summary(snapshot)

    @mcp.tool()
    async def watch_diff(epss_threshold: float = DEFAULT_EPSS_THRESHOLD, ctx=None) -> str:
        """Show what changed between the two most recent estate snapshots.

        Reports new CISA KEV additions hitting your installed packages, EPSS
        spikes past the threshold, newly disclosed CVEs against installed
        versions, resolved findings, and estate membership changes.

        Args:
            epss_threshold: Minimum EPSS rise (0.0-1.0) counted as a spike.
                            Default 0.10 (10 points).
        """
        start = time.monotonic()
        params = {"epss_threshold": epss_threshold}
        if not (0.0 <= epss_threshold <= 1.0):
            audit_record("watch_diff", params, "invalid_input", 0)
            return "Invalid epss_threshold. Provide a value between 0.0 and 1.0."
        store = await get_store()
        snapshots = await store.latest_snapshots(2)
        if not snapshots:
            audit_record("watch_diff", params, "not_found", (time.monotonic() - start) * 1000)
            return "No snapshots yet. Run estate_scan to take the first one."
        new = snapshots[0]
        old = snapshots[1] if len(snapshots) > 1 else None
        report = diff_snapshots(old, new, epss_threshold=epss_threshold)
        audit_record("watch_diff", params, "ok", (time.monotonic() - start) * 1000)
        return render_diff(report)

    @mcp.tool()
    async def watch_brief(epss_threshold: float = DEFAULT_EPSS_THRESHOLD, ctx=None) -> str:
        """Prioritized patch brief for your estate, from the latest snapshots.

        KEV-listed changes first, EPSS spikes second, new exposure third —
        the patch order a SOC/GRC review actually works in. With only one
        snapshot on record, returns a current-state brief instead.

        Args:
            epss_threshold: Minimum EPSS rise (0.0-1.0) counted as a spike.
                            Default 0.10 (10 points).
        """
        start = time.monotonic()
        params = {"epss_threshold": epss_threshold}
        if not (0.0 <= epss_threshold <= 1.0):
            audit_record("watch_brief", params, "invalid_input", 0)
            return "Invalid epss_threshold. Provide a value between 0.0 and 1.0."
        store = await get_store()
        snapshots = await store.latest_snapshots(2)
        if not snapshots:
            audit_record("watch_brief", params, "not_found", (time.monotonic() - start) * 1000)
            return "No snapshots yet. Run estate_scan to take the first one."
        new = snapshots[0]
        if len(snapshots) == 1:
            audit_record("watch_brief", params, "ok", (time.monotonic() - start) * 1000)
            return render_current_state_brief(new)
        report = diff_snapshots(snapshots[1], new, epss_threshold=epss_threshold)
        audit_record("watch_brief", params, "ok", (time.monotonic() - start) * 1000)
        return render_brief(report)
