"""Watchtower — estate memory for the CVE MCP server.

The base server is stateless: every tool answers one lookup and forgets it.
Watchtower adds the missing half:

  * an estate store (SQLite) that ingests SBOMs and lockfiles once and
    remembers what you actually run,
  * a snapshot engine that records your exposure state using the base
    project's own NVD/EPSS/KEV/OSV intel clients,
  * a diff engine that answers the question a lookup tool never can:
    what changed against YOUR stack since the last run,
  * a prioritized patch brief (KEV first, EPSS spikes second, new
    exposure third) exposed as MCP tools and a CLI watch mode.
"""

from __future__ import annotations

__version__ = "0.1.0"

from cve_mcp.watchtower.models import (
    DiffEvent,
    DiffReport,
    Finding,
    Package,
    Snapshot,
)

__all__ = [
    "DiffEvent",
    "DiffReport",
    "Finding",
    "Package",
    "Snapshot",
    "__version__",
]
