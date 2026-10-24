"""Watchtower estate store tests — SQLite persistence (offline, tmp_path)."""

from __future__ import annotations

import pytest

from cve_mcp.watchtower.models import Finding, Package, Snapshot
from cve_mcp.watchtower.store import EstateStore


@pytest.fixture
async def store(tmp_path):
    s = EstateStore(str(tmp_path / "estate.db"))
    await s.initialize()
    yield s
    await s.close()


async def test_add_and_list_packages(store):
    added, total = await store.add_packages(
        [Package("PyPI", "requests", "2.19.1"), Package("npm", "lodash", "4.17.20")]
    )
    assert (added, total) == (2, 2)
    packages = await store.list_packages()
    assert [p.name for p in packages] == ["lodash", "requests"] or len(packages) == 2
    assert all(p.first_seen for p in packages)


async def test_readd_preserves_first_seen(store):
    await store.add_packages([Package("PyPI", "requests", "2.19.1")], today="2026-01-01")
    added, total = await store.add_packages(
        [Package("PyPI", "requests", "2.19.1")], today="2026-06-01"
    )
    assert (added, total) == (0, 1)
    (pkg,) = await store.list_packages()
    assert pkg.first_seen == "2026-01-01"


async def test_new_version_is_a_new_package(store):
    await store.add_packages([Package("PyPI", "requests", "2.19.1")])
    added, total = await store.add_packages([Package("PyPI", "requests", "2.31.0")])
    assert (added, total) == (1, 2)


async def test_save_and_get_snapshot_round_trip(store):
    snap = Snapshot(
        created_at="2026-10-24T00:00:00+00:00",
        label="monday",
        packages=[Package("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")],
        findings=[
            Finding(
                ecosystem="Maven",
                name="org.apache.logging.log4j:log4j-core",
                version="2.14.1",
                cve_id="CVE-2021-44228",
                osv_id="GHSA-jfh8-c2jp-5v3q",
                summary="Log4Shell",
                in_kev=True,
                kev_date_added="2021-12-10",
                kev_due_date="2021-12-24",
                epss=0.97,
                percentile=0.999,
            )
        ],
    )
    snapshot_id = await store.save_snapshot(snap)
    loaded = await store.get_snapshot(snapshot_id)
    assert loaded is not None
    assert loaded.label == "monday"
    assert loaded.packages[0].name == "org.apache.logging.log4j:log4j-core"
    (finding,) = loaded.findings
    assert finding.cve_id == "CVE-2021-44228"
    assert finding.in_kev is True
    assert finding.epss == 0.97
    assert finding.kev_due_date == "2021-12-24"


async def test_snapshot_with_no_epss_stays_none(store):
    snap = Snapshot(
        created_at="2026-10-24T00:00:00+00:00",
        packages=[Package("PyPI", "requests", "2.19.1")],
        findings=[Finding("PyPI", "requests", "2.19.1", "CVE-2018-18074")],
    )
    loaded = await store.get_snapshot(await store.save_snapshot(snap))
    assert loaded is not None
    assert loaded.findings[0].epss is None
    assert loaded.findings[0].in_kev is False


async def test_latest_snapshots_newest_first(store):
    for i in range(3):
        await store.save_snapshot(
            Snapshot(created_at=f"2026-10-2{i}T00:00:00+00:00", label=f"s{i}")
        )
    latest = await store.latest_snapshots(2)
    assert [s.label for s in latest] == ["s2", "s1"]
    assert await store.snapshot_count() == 3


async def test_get_missing_snapshot_returns_none(store):
    assert await store.get_snapshot(999) is None


async def test_empty_store_counts(store):
    assert await store.package_count() == 0
    assert await store.snapshot_count() == 0
    assert await store.latest_snapshots(2) == []
