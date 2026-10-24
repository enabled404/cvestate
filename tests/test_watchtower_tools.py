"""Watchtower MCP tool tests — registration and the offline tool flow.

Uses a throwaway FastMCP instance and a tmp_path estate store; intel comes
from FixtureIntel injected straight into the engine (the same path the MCP
estate_scan tool binds to live clients), so no network is touched.
"""

from __future__ import annotations

import json

import pytest
from mcp.server.fastmcp import FastMCP

from cve_mcp.watchtower import tools as watchtower_tools
from cve_mcp.watchtower.engine import take_snapshot
from cve_mcp.watchtower.fixtures import FixtureIntel
from cve_mcp.watchtower.store import EstateStore

SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            }
        ],
    }
)

INTEL_V1 = {
    "osv": {
        "Maven:org.apache.logging.log4j:log4j-core@2.14.1": [
            {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell"}
        ]
    },
    "kev": [],
    "epss": {"CVE-2021-44228": {"epss": 0.31, "percentile": 0.91}},
}

INTEL_V2 = {
    "osv": INTEL_V1["osv"],
    "kev": [{"cveID": "CVE-2021-44228", "dateAdded": "2026-10-24", "dueDate": "2026-11-07"}],
    "epss": {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.999}},
}


def _text_of(result) -> str:
    content = result[0] if isinstance(result, tuple) else result
    return "".join(getattr(block, "text", "") for block in content)


@pytest.fixture
async def wired(tmp_path):
    mcp = FastMCP("watchtower-test")
    watchtower_tools.register_watchtower(mcp, lambda ctx: None)
    store = EstateStore(str(tmp_path / "estate.db"))
    await store.initialize()
    watchtower_tools.set_store(store)
    yield mcp, store
    watchtower_tools.set_store(None)
    await store.close()


async def test_four_watchtower_tools_registered(wired):
    mcp, _store = wired
    names = {t.name for t in await mcp.list_tools()}
    assert {"estate_add", "estate_scan", "watch_diff", "watch_brief"}.issubset(names)


async def test_base_server_has_32_tools():
    from cve_mcp.server import mcp as base_mcp

    names = {t.name for t in await base_mcp.list_tools()}
    assert len(names) == 32
    assert {"estate_add", "estate_scan", "watch_diff", "watch_brief"}.issubset(names)


async def test_estate_add_tool_ingests_sbom(wired):
    mcp, store = wired
    out = _text_of(
        await mcp.call_tool("estate_add", {"source_text": SBOM, "source_name": "x.cdx.json"})
    )
    assert "1 new package(s) added" in out
    assert await store.package_count() == 1


async def test_full_flow_add_scan_diff_brief(wired):
    mcp, store = wired
    await mcp.call_tool("estate_add", {"source_text": SBOM, "source_name": "x.cdx.json"})

    intel1 = FixtureIntel(INTEL_V1)
    await take_snapshot(
        store,
        osv_query=intel1.osv_query,
        kev_lookup=intel1.kev_lookup,
        epss_query=intel1.epss_query,
    )
    intel2 = FixtureIntel(INTEL_V2)
    await take_snapshot(
        store,
        osv_query=intel2.osv_query,
        kev_lookup=intel2.kev_lookup,
        epss_query=intel2.epss_query,
    )

    diff_out = _text_of(await mcp.call_tool("watch_diff", {}))
    assert "Newly KEV-listed (1)" in diff_out
    assert "CVE-2021-44228" in diff_out

    brief_out = _text_of(await mcp.call_tool("watch_brief", {}))
    assert "PATCH NOW" in brief_out
    assert "CVE-2021-44228" in brief_out


async def test_watch_brief_without_snapshots_guides_user(wired):
    mcp, _store = wired
    out = _text_of(await mcp.call_tool("watch_brief", {}))
    assert "No snapshots yet" in out


async def test_watch_diff_rejects_bad_threshold(wired):
    mcp, _store = wired
    out = _text_of(await mcp.call_tool("watch_diff", {"epss_threshold": 2.5}))
    assert "Invalid epss_threshold" in out
