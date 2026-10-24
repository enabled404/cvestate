"""Text rendering for Watchtower: snapshot summaries and the delta brief.

The format deliberately matches the base project's ``triage_cve`` report
style — ``=== Title ===`` header, ALL-CAPS section labels, two-space
indent, aligned fields — so Watchtower output reads as part of the same
server.
"""

from __future__ import annotations

from cve_mcp.watchtower.models import (
    KIND_EPSS_SPIKE,
    KIND_NEW_EXPOSURE,
    KIND_NEW_KEV,
    KIND_PACKAGE_ADDED,
    KIND_PACKAGE_REMOVED,
    KIND_RESOLVED,
    DiffEvent,
    DiffReport,
    Finding,
    Snapshot,
)


def _epss_str(f: Finding) -> str:
    if f.epss is None:
        return "EPSS n/a"
    pct = f" (percentile {f.percentile * 100:.1f}th)" if f.percentile is not None else ""
    return f"EPSS {f.epss * 100:.1f}%{pct}"


def _finding_line(f: Finding) -> str:
    kev = ""
    if f.in_kev:
        kev = (
            f"  [KEV added {f.kev_date_added}, due {f.kev_due_date}]"
            if f.kev_due_date
            else "  [KEV]"
        )
    return f"  {f.cve_id:<18} {f.package_label:<38} {_epss_str(f)}{kev}"


def render_snapshot_summary(snapshot: Snapshot) -> str:
    """One-screen summary of a single snapshot (used by estate_scan)."""
    kev = snapshot.kev_findings
    lines = [
        "=== Estate Snapshot ===",
        f"Snapshot:  #{snapshot.id}  {snapshot.created_at}"
        + (f"  ({snapshot.label})" if snapshot.label else ""),
        f"Estate:    {len(snapshot.packages)} packages",
        f"Exposure:  {len(snapshot.findings)} findings, {len(kev)} in CISA KEV",
        "",
    ]
    if kev:
        lines.append("KEV-LISTED (patch first):")
        for f in sorted(kev, key=lambda x: x.kev_due_date or "9999"):
            lines.append(_finding_line(f))
        lines.append("")
    top = sorted(
        (f for f in snapshot.findings if f.epss is not None),
        key=lambda x: x.epss or 0.0,
        reverse=True,
    )[:5]
    if top:
        lines.append("TOP EPSS:")
        for f in top:
            lines.append(_finding_line(f))
        lines.append("")
    if not snapshot.findings:
        lines.append("No known vulnerabilities found against the installed versions.")
    return "\n".join(lines).rstrip()


def render_current_state_brief(snapshot: Snapshot) -> str:
    """Prioritized brief from a single snapshot (no diff available yet)."""
    kev = sorted(snapshot.kev_findings, key=lambda x: x.kev_due_date or "9999")
    by_epss = sorted(
        (f for f in snapshot.findings if not f.in_kev),
        key=lambda x: x.epss if x.epss is not None else -1.0,
        reverse=True,
    )
    lines = [
        "=== Watchtower Brief — current estate exposure ===",
        f"Snapshot:  #{snapshot.id}  {snapshot.created_at}"
        + (f"  ({snapshot.label})" if snapshot.label else ""),
        f"Estate:    {len(snapshot.packages)} packages, "
        f"{len(snapshot.findings)} findings, {len(kev)} in CISA KEV",
        "",
    ]
    if kev:
        lines.append("PATCH FIRST — CISA KEV (known exploited):")
        for f in kev:
            lines.append(_finding_line(f))
        lines.append("")
    if by_epss:
        lines.append("WATCH — highest EPSS:")
        for f in by_epss[:10]:
            lines.append(_finding_line(f))
        lines.append("")
    if not snapshot.findings:
        lines.append("No known vulnerabilities found against the installed versions.")
    lines.append("Run another estate_scan later and watch_diff will show what changed.")
    return "\n".join(lines).rstrip()


def render_diff(report: DiffReport) -> str:
    """Compact change list between the two latest snapshots (watch_diff)."""
    new, old = report.new, report.old
    lines = [
        "=== Watchtower Diff ===",
        f"Snapshots: #{old.id if old else '?'} ({old.created_at if old else 'none'})"
        f"  ->  #{new.id} ({new.created_at})",
        "",
    ]
    if old is None:
        lines.append("Only one snapshot exists — nothing to diff against yet.")
        lines.append("Run estate_scan again after time passes (or intel changes).")
        return "\n".join(lines)
    if not report.has_changes:
        lines.append("No changes. Exposure is identical to the previous snapshot.")
        return "\n".join(lines)

    labels = [
        (KIND_NEW_KEV, "Newly KEV-listed"),
        (KIND_EPSS_SPIKE, "EPSS spikes"),
        (KIND_NEW_EXPOSURE, "New exposure"),
        (KIND_RESOLVED, "Resolved"),
        (KIND_PACKAGE_ADDED, "Packages added"),
        (KIND_PACKAGE_REMOVED, "Packages removed"),
    ]
    for kind, label in labels:
        events = report.of_kind(kind)
        if not events:
            continue
        lines.append(f"{label} ({len(events)}):")
        for e in events:
            if e.package is not None:
                lines.append(f"  {e.package.label}")
            elif e.finding is not None:
                lines.append(_finding_line(e.finding))
                if e.detail:
                    lines.append(f"      {e.detail}")
            elif e.previous is not None:
                lines.append(_finding_line(e.previous))
        lines.append("")
    return "\n".join(lines).rstrip()


def _event_finding_line(event: DiffEvent) -> str:
    f = event.finding or event.previous
    if f is None:
        return f"  {event.detail}"
    return _finding_line(f)


def render_brief(report: DiffReport) -> str:
    """The delta brief: what changed, in patch-priority order.

    Sections: KEV first, EPSS spikes second (largest delta first), new
    exposure third, then resolved and estate membership changes.
    """
    new = report.new
    old = report.old
    lines = [
        "=== Watchtower Brief — what changed against your stack ===",
        f"Snapshots: #{old.id if old else '?'} ({old.created_at if old else 'none'})"
        f"  ->  #{new.id} ({new.created_at})",
        f"Estate:    {len(new.packages)} packages, {len(new.findings)} findings, "
        f"{len(new.kev_findings)} in CISA KEV",
        "",
    ]

    if old is None:
        return render_current_state_brief(new)

    kev_events = report.of_kind(KIND_NEW_KEV)
    spike_events = sorted(
        report.of_kind(KIND_EPSS_SPIKE),
        key=lambda e: (
            (e.finding.epss or 0.0) - (e.previous.epss or 0.0) if e.finding and e.previous else 0.0
        ),
        reverse=True,
    )
    exposure_events = report.of_kind(KIND_NEW_EXPOSURE)
    resolved_events = report.of_kind(KIND_RESOLVED)
    added_events = report.of_kind(KIND_PACKAGE_ADDED)
    removed_events = report.of_kind(KIND_PACKAGE_REMOVED)

    if not report.has_changes:
        lines.append("No changes since the previous snapshot. Exposure is unchanged.")
        return "\n".join(lines).rstrip()

    if kev_events:
        lines.append("PATCH NOW — newly KEV-listed against your stack:")
        for e in kev_events:
            lines.append(_event_finding_line(e))
        lines.append("")
    if spike_events:
        lines.append(f"PATCH NEXT — EPSS spikes (>= +{report.epss_threshold * 100:.0f} pts):")
        for e in spike_events:
            lines.append(_event_finding_line(e))
            if e.detail:
                lines.append(f"      {e.detail}")
        lines.append("")
    if exposure_events:
        lines.append("NEW EXPOSURE — newly disclosed against installed versions:")
        for e in exposure_events:
            lines.append(_event_finding_line(e))
        lines.append("")
    if resolved_events:
        lines.append("RESOLVED — no longer reported:")
        for e in resolved_events:
            lines.append(_event_finding_line(e))
        lines.append("")
    if added_events or removed_events:
        lines.append("ESTATE CHANGES:")
        for e in added_events:
            if e.package:
                lines.append(f"  + {e.package.label} joined the estate")
        for e in removed_events:
            if e.package:
                lines.append(f"  - {e.package.label} left the estate")
        lines.append("")

    action = "patch the KEV items above first"
    if not kev_events and spike_events:
        action = "work the EPSS spikes above first"
    elif not kev_events and not spike_events and exposure_events:
        action = "review the new exposure above"
    elif not (kev_events or spike_events or exposure_events):
        action = "no urgent patching from this diff"
    lines.append(f"Action: {action}.")
    return "\n".join(lines).rstrip()
