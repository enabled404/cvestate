"""Offline intel fixtures for Watchtower.

A fixture is one JSON object describing what the intel sources would have
returned, so snapshots, demos, and tests can run with no network and no
API keys:

    {
      "osv": {
        "PyPI:requests@2.19.1": [
          {"id": "GHSA-xxxx", "aliases": ["CVE-2018-18074"], "summary": "..."}
        ]
      },
      "kev": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
         "dueDate": "2021-12-24", "vendorProject": "Apache", "product": "Log4j2"}
      ],
      "epss": {
        "CVE-2021-44228": {"epss": 0.97, "percentile": 0.999, "date": "2026-10-24"}
      }
    }

OSV keys are "<ecosystem>:<name>@<version>"; a bare "<ecosystem>:<name>"
key matches any version of that package.
"""

from __future__ import annotations

import json
from pathlib import Path


class FixtureIntel:
    """Intel callables backed by a fixture dict (see module docstring)."""

    def __init__(self, data: dict) -> None:
        self._osv: dict[str, list[dict]] = data.get("osv") or {}
        self._epss: dict[str, dict] = data.get("epss") or {}
        self._kev: dict[str, dict] = {}
        for entry in data.get("kev") or []:
            cve_id = entry.get("cveID") or entry.get("cve_id") or ""
            if cve_id:
                self._kev[cve_id.upper()] = entry

    @classmethod
    def from_file(cls, path: str | Path) -> FixtureIntel:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    async def osv_query(self, name: str, ecosystem: str, version: str) -> list[dict]:
        exact = f"{ecosystem}:{name}@{version}"
        if exact in self._osv:
            return list(self._osv[exact])
        bare = f"{ecosystem}:{name}"
        return list(self._osv.get(bare) or [])

    def kev_lookup(self, cve_id: str) -> dict | None:
        return self._kev.get(cve_id.upper())

    async def epss_query(self, cve_ids: list[str]) -> list[dict]:
        results: list[dict] = []
        for cve_id in cve_ids:
            entry = self._epss.get(cve_id) or self._epss.get(cve_id.upper())
            if entry:
                results.append(
                    {
                        "cve": cve_id,
                        "epss": entry.get("epss"),
                        "percentile": entry.get("percentile"),
                        "date": entry.get("date", ""),
                    }
                )
        return results
