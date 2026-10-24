"""Watchtower snapshot engine and diff engine.

The snapshot engine walks the estate, queries the base project's existing
intel clients (OSV for package vulnerabilities, the CISA KEV catalog for
known-exploited status, EPSS for exploitation probability) and persists the
result as one snapshot.

Intel access is injected as callables so tests and offline runs can supply
fixtures instead of the network:

  * ``osv_query(name, ecosystem, version) -> list[dict]`` — raw OSV vulns,
    same shape as ``cve_mcp.api.osv_client.query_package`` returns.
  * ``kev_lookup(cve_id) -> KEVEntry-like | None`` — anything with
    ``dateAdded`` / ``dueDate`` attributes (or a dict with those keys).
  * ``epss_query(cve_ids) -> iterable`` — EPSSScore-like objects (or dicts)
    with ``cve`` / ``epss`` / ``percentile``.

The diff engine is a pure function over two Snapshot objects.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timezone

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
from cve_mcp.watchtower.parsers import QUERYABLE_ECOSYSTEMS, UNKNOWN_ECOSYSTEM
from cve_mcp.watchtower.store import EstateStore

logger = logging.getLogger(__name__)

OsvQuery = Callable[[str, str, str], Awaitable[list[dict]]]
KevLookup = Callable[[str], object | None]
EpssQuery = Callable[[list[str]], Awaitable[Iterable[object]]]

DEFAULT_EPSS_THRESHOLD = 0.10


def extract_cve_id(vuln: dict) -> tuple[str, str]:
    """Return (finding_key, osv_id) for one OSV vulnerability record.

    The finding key is the first CVE alias when one exists, else the OSV id
    itself (CVE ids, GHSA ids, etc. all work as stable keys).
    """
    osv_id = vuln.get("id") or ""
    aliases = vuln.get("aliases") or []
    for alias in aliases:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias.upper(), osv_id
    return osv_id, osv_id


def _kev_field(entry: object | None, field: str) -> str:
    if entry is None:
        return ""
    if isinstance(entry, dict):
        return str(entry.get(field) or "")
    return str(getattr(entry, field, "") or "")


def _epss_fields(score: object) -> tuple[str, float | None, float | None]:
    if isinstance(score, dict):
        cve = str(score.get("cve") or "")
        epss = score.get("epss", score.get("probability"))
        percentile = score.get("percentile")
    else:
        cve = str(getattr(score, "cve", "") or "")
        epss = getattr(score, "epss", None)
        percentile = getattr(score, "percentile", None)
    try:
        epss_val = float(epss) if epss is not None else None
    except (TypeError, ValueError):
        epss_val = None
    try:
        pct_val = float(percentile) if percentile is not None else None
    except (TypeError, ValueError):
        pct_val = None
    return cve, epss_val, pct_val


async def take_snapshot(
    store: EstateStore,
    *,
    osv_query: OsvQuery,
    kev_lookup: KevLookup,
    epss_query: EpssQuery,
    label: str = "",
    now: str | None = None,
) -> Snapshot:
    """Snapshot the estate's current exposure and persist it.

    Packages whose ecosystem OSV cannot query (or that OSV errors on) are
    skipped for findings but still recorded in the snapshot's package set,
    so package add/remove diffs stay accurate.
    """
    packages = await store.list_packages()
    findings: list[Finding] = []

    for pkg in packages:
        if pkg.ecosystem in ("", UNKNOWN_ECOSYSTEM) or pkg.ecosystem not in QUERYABLE_ECOSYSTEMS:
            continue
        try:
            vulns = await osv_query(pkg.name, pkg.ecosystem, pkg.version)
        except Exception as exc:
            logger.warning("OSV query failed for %s: %s", pkg.label, exc)
            continue
        for vuln in vulns or []:
            if not isinstance(vuln, dict):
                continue
            cve_id, osv_id = extract_cve_id(vuln)
            if not cve_id:
                continue
            kev_entry = kev_lookup(cve_id)
            findings.append(
                Finding(
                    ecosystem=pkg.ecosystem,
                    name=pkg.name,
                    version=pkg.version,
                    cve_id=cve_id,
                    osv_id=osv_id,
                    summary=(vuln.get("summary") or "")[:300],
                    in_kev=kev_entry is not None,
                    kev_date_added=_kev_field(kev_entry, "dateAdded"),
                    kev_due_date=_kev_field(kev_entry, "dueDate"),
                )
            )

    # One batched EPSS pass over every distinct CVE found.
    cve_ids = sorted({f.cve_id for f in findings if f.cve_id.upper().startswith("CVE-")})
    epss_by_cve: dict[str, tuple[float | None, float | None]] = {}
    if cve_ids:
        try:
            for score in await epss_query(cve_ids):
                cve, epss_val, pct_val = _epss_fields(score)
                if cve:
                    epss_by_cve[cve.upper()] = (epss_val, pct_val)
        except Exception as exc:
            logger.warning("EPSS batch query failed: %s", exc)

    if epss_by_cve:
        enriched: list[Finding] = []
        for f in findings:
            epss_val, pct_val = epss_by_cve.get(f.cve_id.upper(), (None, None))
            if epss_val is None and pct_val is None:
                enriched.append(f)
            else:
                enriched.append(
                    Finding(
                        ecosystem=f.ecosystem,
                        name=f.name,
                        version=f.version,
                        cve_id=f.cve_id,
                        osv_id=f.osv_id,
                        summary=f.summary,
                        in_kev=f.in_kev,
                        kev_date_added=f.kev_date_added,
                        kev_due_date=f.kev_due_date,
                        epss=epss_val,
                        percentile=pct_val,
                    )
                )
        findings = enriched

    snapshot = Snapshot(
        created_at=now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        label=label,
        packages=packages,
        findings=findings,
    )
    snapshot.id = await store.save_snapshot(snapshot)
    return snapshot


# ── Diff engine ─────────────────────────────────────────────────────────────


def diff_snapshots(
    old: Snapshot | None,
    new: Snapshot,
    *,
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD,
) -> DiffReport:
    """Compare two snapshots and report what changed against the estate.

    Event priority (also the brief's section order): NEW_KEV, EPSS_SPIKE,
    NEW_EXPOSURE, RESOLVED, then package membership changes.
    """
    report = DiffReport(old=old, new=new, epss_threshold=epss_threshold)
    if old is None:
        return report

    old_findings = {f.key: f for f in old.findings}
    new_findings = {f.key: f for f in new.findings}

    for key, new_f in new_findings.items():
        old_f = old_findings.get(key)
        if old_f is None:
            if new_f.in_kev:
                report.events.append(
                    DiffEvent(
                        kind=KIND_NEW_KEV,
                        finding=new_f,
                        detail="Newly disclosed CVE is already in CISA KEV",
                    )
                )
            else:
                report.events.append(
                    DiffEvent(
                        kind=KIND_NEW_EXPOSURE,
                        finding=new_f,
                        detail="New vulnerability against an installed package",
                    )
                )
            continue
        if new_f.in_kev and not old_f.in_kev:
            report.events.append(
                DiffEvent(
                    kind=KIND_NEW_KEV,
                    finding=new_f,
                    previous=old_f,
                    detail="CVE added to CISA KEV since the previous snapshot",
                )
            )
            continue
        if (
            new_f.epss is not None
            and old_f.epss is not None
            and (new_f.epss - old_f.epss) >= epss_threshold
        ):
            report.events.append(
                DiffEvent(
                    kind=KIND_EPSS_SPIKE,
                    finding=new_f,
                    previous=old_f,
                    detail=(
                        f"EPSS rose {old_f.epss * 100:.1f}% -> {new_f.epss * 100:.1f}% "
                        f"(+{(new_f.epss - old_f.epss) * 100:.1f} pts)"
                    ),
                )
            )

    for key, old_f in old_findings.items():
        if key not in new_findings:
            report.events.append(
                DiffEvent(
                    kind=KIND_RESOLVED,
                    finding=None,
                    previous=old_f,
                    detail="No longer reported against the installed version",
                )
            )

    old_pkgs = {p.key: p for p in old.packages}
    new_pkgs = {p.key: p for p in new.packages}
    for key, pkg in new_pkgs.items():
        if key not in old_pkgs:
            report.events.append(
                DiffEvent(kind=KIND_PACKAGE_ADDED, package=pkg, detail="Package joined the estate")
            )
    for key, pkg in old_pkgs.items():
        if key not in new_pkgs:
            report.events.append(
                DiffEvent(kind=KIND_PACKAGE_REMOVED, package=pkg, detail="Package left the estate")
            )

    report.events.sort(key=lambda e: e.priority)
    return report
