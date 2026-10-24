"""Dataclasses for the Watchtower estate / snapshot / diff model.

Plain dataclasses (not pydantic) — Watchtower state is internal, persisted
to SQLite, and never crosses a trust boundary as untrusted input, so the
heavier pydantic models in ``cve_mcp.models`` are unnecessary here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Diff event kinds, in brief priority order.
KIND_NEW_KEV = "NEW_KEV"
KIND_EPSS_SPIKE = "EPSS_SPIKE"
KIND_NEW_EXPOSURE = "NEW_EXPOSURE"
KIND_RESOLVED = "RESOLVED"
KIND_PACKAGE_ADDED = "PACKAGE_ADDED"
KIND_PACKAGE_REMOVED = "PACKAGE_REMOVED"

KIND_PRIORITY = {
    KIND_NEW_KEV: 0,
    KIND_EPSS_SPIKE: 1,
    KIND_NEW_EXPOSURE: 2,
    KIND_RESOLVED: 3,
    KIND_PACKAGE_ADDED: 4,
    KIND_PACKAGE_REMOVED: 5,
}


@dataclass(frozen=True)
class Package:
    """One installed package in the estate."""

    ecosystem: str  # OSV ecosystem string: PyPI, npm, Go, Maven, ...
    name: str
    version: str = ""
    first_seen: str = ""  # ISO date, set by the store on insert
    source: str = ""  # file/format the package was ingested from

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    @property
    def label(self) -> str:
        ver = f" {self.version}" if self.version else ""
        return f"{self.ecosystem}/{self.name}{ver}"


@dataclass(frozen=True)
class Finding:
    """One (package, CVE) exposure observation inside a snapshot."""

    ecosystem: str
    name: str
    version: str
    cve_id: str  # CVE id when known, otherwise the OSV/GHSA id
    osv_id: str = ""
    summary: str = ""
    in_kev: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""
    epss: float | None = None
    percentile: float | None = None

    @property
    def package_key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.ecosystem, self.name, self.version, self.cve_id)

    @property
    def package_label(self) -> str:
        ver = f" {self.version}" if self.version else ""
        return f"{self.ecosystem}/{self.name}{ver}"


@dataclass
class Snapshot:
    """The estate's full exposure state at one point in time."""

    id: int = 0
    created_at: str = ""
    label: str = ""
    packages: list[Package] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def kev_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.in_kev]


@dataclass(frozen=True)
class DiffEvent:
    """One thing that changed between two snapshots."""

    kind: str  # one of the KIND_* constants
    finding: Finding | None = None  # the finding in the NEW snapshot
    previous: Finding | None = None  # the finding in the OLD snapshot
    package: Package | None = None  # for package membership events
    detail: str = ""

    @property
    def priority(self) -> int:
        return KIND_PRIORITY.get(self.kind, 99)


@dataclass
class DiffReport:
    """The full diff between two snapshots."""

    old: Snapshot | None
    new: Snapshot
    epss_threshold: float = 0.10
    events: list[DiffEvent] = field(default_factory=list)

    def of_kind(self, kind: str) -> list[DiffEvent]:
        return [e for e in self.events if e.kind == kind]

    @property
    def has_changes(self) -> bool:
        return bool(self.events)
