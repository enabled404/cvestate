"""Persistent estate store for Watchtower (SQLite, aiosqlite).

Mirrors the storage idioms of ``cve_mcp.cache.sqlite_cache``: WAL journal
mode, NORMAL synchronous, busy timeout, async initialize/close lifecycle.
The estate DB is separate from the response cache — the cache is disposable
(TTL rows), the estate is memory and must survive.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import aiosqlite

from cve_mcp.watchtower.models import Finding, Package, Snapshot

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    package_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS snapshot_packages (
    snapshot_id INTEGER NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS findings (
    snapshot_id INTEGER NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    cve_id TEXT NOT NULL,
    osv_id TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    in_kev INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT NOT NULL DEFAULT '',
    kev_due_date TEXT NOT NULL DEFAULT '',
    epss REAL,
    percentile REAL,
    PRIMARY KEY (snapshot_id, ecosystem, name, version, cve_id)
);
"""


def default_db_path() -> str:
    """Estate DB path: $WATCHTOWER_DB_PATH or ~/.cve-mcp/estate.db."""
    env = os.getenv("WATCHTOWER_DB_PATH")
    if env:
        return env
    return str(Path.home() / ".cve-mcp" / "estate.db")


class EstateStore:
    """Async SQLite store for estate packages and exposure snapshots."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        if self._db is not None:
            return
        path = Path(self._db_path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        # Same WAL pragma set as VulnCache (see cache/sqlite_cache.py).
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._db.execute("PRAGMA temp_store=MEMORY")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("EstateStore not initialized — call initialize() first")
        return self._db

    # ── Packages ────────────────────────────────────────────────────────

    async def add_packages(
        self, packages: list[Package], *, today: str | None = None
    ) -> tuple[int, int]:
        """Insert packages; return (newly_added, estate_total).

        Re-adding an existing (ecosystem, name, version) keeps its original
        first_seen and only refreshes last_seen.
        """
        db = self._require_db()
        day = today or date.today().isoformat()
        added = 0
        for pkg in packages:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO packages "
                "(ecosystem, name, version, first_seen, last_seen, source) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (pkg.ecosystem, pkg.name, pkg.version, day, day, pkg.source),
            )
            if cursor.rowcount and cursor.rowcount > 0:
                added += 1
            else:
                await db.execute(
                    "UPDATE packages SET last_seen = ? "
                    "WHERE ecosystem = ? AND name = ? AND version = ?",
                    (day, pkg.ecosystem, pkg.name, pkg.version),
                )
        await db.commit()
        async with db.execute("SELECT COUNT(*) FROM packages") as cur:
            row = await cur.fetchone()
        return added, int(row[0]) if row else 0

    async def list_packages(self) -> list[Package]:
        db = self._require_db()
        packages: list[Package] = []
        async with db.execute(
            "SELECT ecosystem, name, version, first_seen, source FROM packages "
            "ORDER BY ecosystem, name, version"
        ) as cur:
            async for row in cur:
                packages.append(
                    Package(
                        ecosystem=row[0],
                        name=row[1],
                        version=row[2],
                        first_seen=row[3],
                        source=row[4],
                    )
                )
        return packages

    async def package_count(self) -> int:
        db = self._require_db()
        async with db.execute("SELECT COUNT(*) FROM packages") as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ── Snapshots ───────────────────────────────────────────────────────

    async def save_snapshot(self, snapshot: Snapshot) -> int:
        """Persist a snapshot (packages + findings); return its new id."""
        db = self._require_db()
        cursor = await db.execute(
            "INSERT INTO snapshots (created_at, label, package_count, finding_count) "
            "VALUES (?, ?, ?, ?)",
            (
                snapshot.created_at,
                snapshot.label,
                len(snapshot.packages),
                len(snapshot.findings),
            ),
        )
        snapshot_id = int(cursor.lastrowid or 0)
        await db.executemany(
            "INSERT OR IGNORE INTO snapshot_packages (snapshot_id, ecosystem, name, version) "
            "VALUES (?, ?, ?, ?)",
            [(snapshot_id, p.ecosystem, p.name, p.version) for p in snapshot.packages],
        )
        await db.executemany(
            "INSERT OR REPLACE INTO findings (snapshot_id, ecosystem, name, version, "
            "cve_id, osv_id, summary, in_kev, kev_date_added, kev_due_date, epss, percentile) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    snapshot_id,
                    f.ecosystem,
                    f.name,
                    f.version,
                    f.cve_id,
                    f.osv_id,
                    f.summary,
                    1 if f.in_kev else 0,
                    f.kev_date_added,
                    f.kev_due_date,
                    f.epss,
                    f.percentile,
                )
                for f in snapshot.findings
            ],
        )
        await db.commit()
        return snapshot_id

    async def get_snapshot(self, snapshot_id: int) -> Snapshot | None:
        db = self._require_db()
        async with db.execute(
            "SELECT id, created_at, label FROM snapshots WHERE id = ?", (snapshot_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return await self._load_snapshot(int(row[0]), row[1], row[2])

    async def latest_snapshots(self, limit: int = 2) -> list[Snapshot]:
        """Most recent snapshots first."""
        db = self._require_db()
        ids: list[tuple[int, str, str]] = []
        async with db.execute(
            "SELECT id, created_at, label FROM snapshots ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            async for row in cur:
                ids.append((int(row[0]), row[1], row[2]))
        return [await self._load_snapshot(i, c, lbl) for i, c, lbl in ids]

    async def snapshot_count(self) -> int:
        db = self._require_db()
        async with db.execute("SELECT COUNT(*) FROM snapshots") as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def _load_snapshot(self, snapshot_id: int, created_at: str, label: str) -> Snapshot:
        db = self._require_db()
        packages: list[Package] = []
        async with db.execute(
            "SELECT ecosystem, name, version FROM snapshot_packages "
            "WHERE snapshot_id = ? ORDER BY ecosystem, name, version",
            (snapshot_id,),
        ) as cur:
            async for row in cur:
                packages.append(Package(row[0], row[1], row[2]))
        findings: list[Finding] = []
        async with db.execute(
            "SELECT ecosystem, name, version, cve_id, osv_id, summary, in_kev, "
            "kev_date_added, kev_due_date, epss, percentile FROM findings "
            "WHERE snapshot_id = ? ORDER BY ecosystem, name, cve_id",
            (snapshot_id,),
        ) as cur:
            async for row in cur:
                findings.append(
                    Finding(
                        ecosystem=row[0],
                        name=row[1],
                        version=row[2],
                        cve_id=row[3],
                        osv_id=row[4],
                        summary=row[5],
                        in_kev=bool(row[6]),
                        kev_date_added=row[7],
                        kev_due_date=row[8],
                        epss=row[9],
                        percentile=row[10],
                    )
                )
        return Snapshot(
            id=snapshot_id,
            created_at=created_at,
            label=label,
            packages=packages,
            findings=findings,
        )
