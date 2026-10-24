"""Watchtower CLI watch mode — the ``cve-watch`` command.

Same operations as the MCP tools, for cron jobs, CI, and terminals:

    cve-watch add estate.cdx.json
    cve-watch list
    cve-watch scan --label monday
    cve-watch diff
    cve-watch brief

Live mode reuses the base project's intel clients (NVD-independent: OSV +
CISA KEV + FIRST EPSS, none of which need API keys). ``--fixture
intel.json`` runs fully offline against a fixture file (see
``cve_mcp.watchtower.fixtures`` for the format) — used by demos and tests.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from cve_mcp.watchtower.brief import (
    render_brief,
    render_current_state_brief,
    render_diff,
    render_snapshot_summary,
)
from cve_mcp.watchtower.engine import DEFAULT_EPSS_THRESHOLD, diff_snapshots, take_snapshot
from cve_mcp.watchtower.parsers import parse_estate_text
from cve_mcp.watchtower.store import EstateStore, default_db_path


async def _live_intel():
    """Bind live intel clients; returns (osv_query, kev_lookup, epss_query, cleanup)."""
    import httpx

    from cve_mcp.api.epss_client import get_epss
    from cve_mcp.api.kev_client import fetch_kev_catalog, lookup_kev
    from cve_mcp.api.osv_client import query_package
    from cve_mcp.cache.sqlite_cache import VulnCache
    from cve_mcp.config import CACHE_DB_PATH, REQUEST_TIMEOUT

    cache_path = Path(CACHE_DB_PATH).expanduser()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache = VulnCache(str(cache_path))
    await cache.initialize()
    client = httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT, verify=True, follow_redirects=True, max_redirects=3
    )
    catalog = await fetch_kev_catalog(client, cache)

    async def osv_query(name: str, ecosystem: str, version: str) -> list[dict]:
        return await query_package(name, ecosystem, version, client, cache)

    def kev_lookup(cve_id: str):
        return lookup_kev(catalog, cve_id)

    async def epss_query(cve_ids: list[str]):
        return await get_epss(cve_ids, client, cache)

    async def cleanup() -> None:
        await client.aclose()
        await cache.close()

    return osv_query, kev_lookup, epss_query, cleanup


async def _run(args: argparse.Namespace) -> int:
    store = EstateStore(args.db)
    await store.initialize()
    try:
        if args.command == "add":
            text = Path(args.file).read_text(encoding="utf-8")
            try:
                packages = parse_estate_text(text, args.file)
            except ValueError as exc:
                print(f"Could not parse {args.file}: {exc}", file=sys.stderr)
                return 2
            added, total = await store.add_packages(packages)
            print(
                f"Estate updated: {added} new package(s) added, {total} total "
                f"(parsed {len(packages)} from {args.file})."
            )
            return 0

        if args.command == "list":
            packages = await store.list_packages()
            if not packages:
                print("The estate is empty. Add packages with: cve-watch add <sbom-or-lockfile>")
                return 0
            print(f"Estate: {len(packages)} packages")
            for pkg in packages:
                seen = f"  (first seen {pkg.first_seen})" if pkg.first_seen else ""
                print(f"  {pkg.label}{seen}")
            return 0

        if args.command == "scan":
            if await store.package_count() == 0:
                print(
                    "The estate is empty. Add packages first: cve-watch add <sbom-or-lockfile>",
                    file=sys.stderr,
                )
                return 2
            cleanup = None
            if args.fixture:
                from cve_mcp.watchtower.fixtures import FixtureIntel

                intel = FixtureIntel.from_file(args.fixture)
                osv_query, kev_lookup, epss_query = (
                    intel.osv_query,
                    intel.kev_lookup,
                    intel.epss_query,
                )
            else:
                osv_query, kev_lookup, epss_query, cleanup = await _live_intel()
            try:
                snapshot = await take_snapshot(
                    store,
                    osv_query=osv_query,
                    kev_lookup=kev_lookup,
                    epss_query=epss_query,
                    label=args.label,
                )
            finally:
                if cleanup is not None:
                    await cleanup()
            print(render_snapshot_summary(snapshot))
            return 0

        if args.command in ("diff", "brief"):
            snapshots = await store.latest_snapshots(2)
            if not snapshots:
                print("No snapshots yet. Run: cve-watch scan", file=sys.stderr)
                return 2
            new = snapshots[0]
            if args.command == "diff":
                old = snapshots[1] if len(snapshots) > 1 else None
                print(render_diff(diff_snapshots(old, new, epss_threshold=args.epss_threshold)))
            else:
                if len(snapshots) == 1:
                    print(render_current_state_brief(new))
                else:
                    print(
                        render_brief(
                            diff_snapshots(snapshots[1], new, epss_threshold=args.epss_threshold)
                        )
                    )
            return 0

        return 2
    finally:
        await store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve-watch",
        description="Watchtower: track your estate's vulnerability exposure over time.",
    )
    parser.add_argument(
        "--db",
        default=default_db_path(),
        help="Estate database path (default: $WATCHTOWER_DB_PATH or ~/.cve-mcp/estate.db)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Ingest an SBOM or lockfile into the estate")
    p_add.add_argument(
        "file", help="CycloneDX/SPDX JSON, requirements.txt, package-lock.json, go.mod"
    )

    sub.add_parser("list", help="List the estate's packages")

    p_scan = sub.add_parser("scan", help="Snapshot the estate's current exposure")
    p_scan.add_argument("--label", default="", help="Label for this snapshot")
    p_scan.add_argument(
        "--fixture",
        default="",
        help="Offline intel fixture JSON instead of live APIs (demos/tests)",
    )

    for name in ("diff", "brief"):
        p = sub.add_parser(name, help=f"Show the {name} between the two latest snapshots")
        p.add_argument(
            "--epss-threshold",
            type=float,
            default=DEFAULT_EPSS_THRESHOLD,
            help="Minimum EPSS rise counted as a spike (default 0.10)",
        )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
