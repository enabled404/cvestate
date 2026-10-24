"""Watchtower snapshot + diff engine tests — fake intel, no network."""

from __future__ import annotations

import pytest

from cve_mcp.watchtower.engine import diff_snapshots, extract_cve_id, take_snapshot
from cve_mcp.watchtower.fixtures import FixtureIntel
from cve_mcp.watchtower.models import (
    KIND_EPSS_SPIKE,
    KIND_NEW_EXPOSURE,
    KIND_NEW_KEV,
    KIND_PACKAGE_ADDED,
    KIND_PACKAGE_REMOVED,
    KIND_RESOLVED,
    Finding,
    Package,
    Snapshot,
)
from cve_mcp.watchtower.store import EstateStore

LOG4J = ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")

INTEL_V1 = {
    "osv": {
        "Maven:org.apache.logging.log4j:log4j-core@2.14.1": [
            {
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": ["CVE-2021-44228"],
                "summary": "Log4Shell RCE",
            }
        ]
    },
    "kev": [],
    "epss": {"CVE-2021-44228": {"epss": 0.31, "percentile": 0.91, "date": "2026-10-20"}},
}

INTEL_V2 = {
    "osv": INTEL_V1["osv"],
    "kev": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2026-10-24",
            "dueDate": "2026-11-07",
            "vendorProject": "Apache",
            "product": "Log4j2",
        }
    ],
    "epss": {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.999, "date": "2026-10-24"}},
}


@pytest.fixture
async def store(tmp_path):
    s = EstateStore(str(tmp_path / "estate.db"))
    await s.initialize()
    await s.add_packages([Package(*LOG4J)])
    yield s
    await s.close()


async def _snap(store, intel_data, label=""):
    intel = FixtureIntel(intel_data)
    return await take_snapshot(
        store,
        osv_query=intel.osv_query,
        kev_lookup=intel.kev_lookup,
        epss_query=intel.epss_query,
        label=label,
    )


async def test_snapshot_builds_findings_and_joins_intel(store):
    snap = await _snap(store, INTEL_V1)
    (finding,) = snap.findings
    assert finding.cve_id == "CVE-2021-44228"
    assert finding.osv_id == "GHSA-jfh8-c2jp-5v3q"
    assert finding.in_kev is False
    assert finding.epss == 0.31
    assert snap.id > 0  # persisted


async def test_snapshot_records_kev_state(store):
    snap = await _snap(store, INTEL_V2)
    (finding,) = snap.findings
    assert finding.in_kev is True
    assert finding.kev_date_added == "2026-10-24"
    assert finding.kev_due_date == "2026-11-07"


async def test_snapshot_skips_unqueryable_ecosystem_but_keeps_package(store):
    await store.add_packages([Package("unknown", "internal-tool", "1.0")])
    snap = await _snap(store, INTEL_V1)
    assert len(snap.packages) == 2
    assert all(f.name != "internal-tool" for f in snap.findings)


async def test_snapshot_tolerates_osv_failure(store):
    async def boom(name, ecosystem, version):
        raise RuntimeError("OSV down")

    intel = FixtureIntel(INTEL_V1)
    snap = await take_snapshot(
        store, osv_query=boom, kev_lookup=intel.kev_lookup, epss_query=intel.epss_query
    )
    assert snap.findings == []
    assert len(snap.packages) == 1


def test_extract_cve_id_prefers_cve_alias():
    cve, osv_id = extract_cve_id({"id": "GHSA-1", "aliases": ["CVE-2024-0001", "GHSA-1"]})
    assert (cve, osv_id) == ("CVE-2024-0001", "GHSA-1")


def test_extract_cve_id_keeps_osv_id_without_alias():
    assert extract_cve_id({"id": "GHSA-only", "aliases": []}) == ("GHSA-only", "GHSA-only")
    assert extract_cve_id({"id": "CVE-2023-1234"}) == ("CVE-2023-1234", "CVE-2023-1234")


def _finding(**kw):
    base = dict(ecosystem="Maven", name=LOG4J[1], version="2.14.1", cve_id="CVE-2021-44228")
    base.update(kw)
    return Finding(**base)


def _snapshot(findings, packages=None, snap_id=1):
    return Snapshot(
        id=snap_id,
        created_at="2026-10-24T00:00:00+00:00",
        packages=packages if packages is not None else [Package(*LOG4J)],
        findings=findings,
    )


def test_diff_detects_new_kev_on_existing_finding():
    old = _snapshot([_finding(in_kev=False, epss=0.31)], snap_id=1)
    new = _snapshot([_finding(in_kev=True, epss=0.97)], snap_id=2)
    report = diff_snapshots(old, new)
    kev_events = report.of_kind(KIND_NEW_KEV)
    assert len(kev_events) == 1
    assert kev_events[0].finding.cve_id == "CVE-2021-44228"
    # KEV classification wins over the EPSS spike for the same finding.
    assert report.of_kind(KIND_EPSS_SPIKE) == []


def test_diff_detects_epss_spike_over_threshold():
    old = _snapshot([_finding(epss=0.20)], snap_id=1)
    new = _snapshot([_finding(epss=0.45)], snap_id=2)
    report = diff_snapshots(old, new, epss_threshold=0.10)
    spikes = report.of_kind(KIND_EPSS_SPIKE)
    assert len(spikes) == 1
    assert "+25.0 pts" in spikes[0].detail


def test_diff_ignores_epss_rise_under_threshold():
    old = _snapshot([_finding(epss=0.20)], snap_id=1)
    new = _snapshot([_finding(epss=0.25)], snap_id=2)
    report = diff_snapshots(old, new, epss_threshold=0.10)
    assert report.of_kind(KIND_EPSS_SPIKE) == []
    assert not report.has_changes


def test_diff_threshold_is_configurable():
    old = _snapshot([_finding(epss=0.20)], snap_id=1)
    new = _snapshot([_finding(epss=0.25)], snap_id=2)
    report = diff_snapshots(old, new, epss_threshold=0.01)
    assert len(report.of_kind(KIND_EPSS_SPIKE)) == 1


def test_diff_detects_new_exposure():
    old = _snapshot([], snap_id=1)
    new = _snapshot([_finding(cve_id="CVE-2026-9999", epss=0.05)], snap_id=2)
    report = diff_snapshots(old, new)
    assert len(report.of_kind(KIND_NEW_EXPOSURE)) == 1


def test_diff_new_kev_finding_classified_as_kev_not_exposure():
    old = _snapshot([], snap_id=1)
    new = _snapshot([_finding(in_kev=True)], snap_id=2)
    report = diff_snapshots(old, new)
    assert len(report.of_kind(KIND_NEW_KEV)) == 1
    assert report.of_kind(KIND_NEW_EXPOSURE) == []


def test_diff_detects_resolved():
    old = _snapshot([_finding()], snap_id=1)
    new = _snapshot([], snap_id=2)
    report = diff_snapshots(old, new)
    resolved = report.of_kind(KIND_RESOLVED)
    assert len(resolved) == 1
    assert resolved[0].previous.cve_id == "CVE-2021-44228"


def test_diff_detects_package_membership_changes():
    old = _snapshot([], packages=[Package(*LOG4J)], snap_id=1)
    new = _snapshot([], packages=[Package("PyPI", "requests", "2.19.1")], snap_id=2)
    report = diff_snapshots(old, new)
    assert len(report.of_kind(KIND_PACKAGE_ADDED)) == 1
    assert len(report.of_kind(KIND_PACKAGE_REMOVED)) == 1


def test_diff_with_no_old_snapshot_has_no_events():
    report = diff_snapshots(None, _snapshot([_finding(in_kev=True)]))
    assert report.events == []
    assert report.old is None
