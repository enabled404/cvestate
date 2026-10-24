"""Watchtower brief rendering tests — priority order and edge cases."""

from __future__ import annotations

from cve_mcp.watchtower.brief import (
    render_brief,
    render_current_state_brief,
    render_diff,
    render_snapshot_summary,
)
from cve_mcp.watchtower.engine import diff_snapshots
from cve_mcp.watchtower.models import Finding, Package, Snapshot

LOG4J_PKG = Package("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")


def _f(cve, **kw):
    base = dict(
        ecosystem="Maven",
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1",
        cve_id=cve,
    )
    base.update(kw)
    return Finding(**base)


def _snap(findings, snap_id=1, packages=None):
    return Snapshot(
        id=snap_id,
        created_at="2026-10-24T00:00:00+00:00",
        packages=packages if packages is not None else [LOG4J_PKG],
        findings=findings,
    )


def test_brief_orders_kev_then_spike_then_new_exposure():
    old = _snap(
        [
            _f("CVE-2021-44228", in_kev=False, epss=0.31),
            _f("CVE-2022-0001", epss=0.10),
        ],
        snap_id=1,
    )
    new = _snap(
        [
            _f("CVE-2021-44228", in_kev=True, epss=0.97, kev_due_date="2026-11-07"),
            _f("CVE-2022-0001", epss=0.55),
            _f("CVE-2026-5555", epss=0.02),
        ],
        snap_id=2,
    )
    brief = render_brief(diff_snapshots(old, new))
    assert brief.index("PATCH NOW") < brief.index("PATCH NEXT") < brief.index("NEW EXPOSURE")
    assert "CVE-2021-44228" in brief
    assert "Action: patch the KEV items above first." in brief


def test_brief_no_changes():
    snap = _snap([_f("CVE-2021-44228", epss=0.31)], snap_id=1)
    brief = render_brief(diff_snapshots(snap, snap))
    assert "No changes" in brief


def test_brief_current_state_leads_with_kev():
    snap = _snap(
        [
            _f("CVE-2021-44228", in_kev=True, kev_due_date="2026-11-07", epss=0.97),
            _f("CVE-2022-0001", epss=0.40),
        ]
    )
    brief = render_current_state_brief(snap)
    assert "PATCH FIRST" in brief
    assert brief.index("CVE-2021-44228") < brief.index("CVE-2022-0001")


def test_render_diff_single_snapshot_message():
    snap = _snap([_f("CVE-2021-44228")])
    text = render_diff(diff_snapshots(None, snap))
    assert "Only one snapshot" in text


def test_snapshot_summary_counts():
    snap = _snap(
        [
            _f("CVE-2021-44228", in_kev=True, kev_due_date="2026-11-07", epss=0.97),
            _f("CVE-2022-0001", epss=0.40),
        ]
    )
    summary = render_snapshot_summary(snap)
    assert "1 packages" in summary
    assert "2 findings, 1 in CISA KEV" in summary
    assert "KEV-LISTED" in summary
