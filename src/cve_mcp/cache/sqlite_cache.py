from __future__ import annotations

import json
import time

import aiosqlite

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""
_CREATE_INDEX = "CREATE INDEX IF NOT EXISTS idx_expires ON cve_cache(expires_at);"

# TTL constants (seconds)
TTL_CVE = 14400  # 4 hours
TTL_SEARCH = 600  # 10 minutes
TTL_OSV = 1800  # 30 minutes
TTL_EPSS = 3600  # 1 hour
TTL_KEV = 21600  # 6 hours
TTL_CVSS = 86400  # 24 hours

_MAX_ROWS = 10_000


class VulnCache:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        # ── WAL config (plan 6.2) ────────────────────────────────────────
        # WAL improves concurrency (readers don't block the writer); NORMAL
        # synchronous is durable under WAL while much faster than FULL; the
        # other pragmas reduce lock contention and keep temp data in memory.
        # NOTE: WAL requires the database to live on local disk (not a network
        # share), which is the case for the default ~/.cve-mcp cache path.
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._db.execute("PRAGMA temp_store=MEMORY")
        await self._db.execute("PRAGMA cache_size=-8000")
        await self._db.execute(_CREATE_TABLE)
        await self._db.execute(_CREATE_INDEX)
        now = time.time()
        # Evict expired rows
        await self._db.execute("DELETE FROM cve_cache WHERE expires_at < ?", (now,))
        # Enforce row cap: keep most-recently-expiring rows
        await self._db.execute(
            "DELETE FROM cve_cache WHERE cache_key NOT IN "
            "(SELECT cache_key FROM cve_cache ORDER BY expires_at DESC LIMIT ?)",
            (_MAX_ROWS,),
        )
        await self._db.commit()
        try:
            async with self._db.execute("SELECT * FROM pragma_freelist_count()") as cur:
                row = await cur.fetchone()
            if row and row[0] > 1000:
                await self._db.execute("VACUUM")
                await self._db.commit()
        except Exception:
            pass  # VACUUM is optional

    async def get(self, key: str) -> dict | list | None:
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT data, expires_at FROM cve_cache WHERE cache_key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        data_str, expires_at = row
        if time.time() > expires_at:
            return None
        return json.loads(data_str)

    async def set(self, key: str, data: dict | list, ttl: int) -> None:
        if self._db is None:
            return
        now = time.time()
        await self._db.execute(
            "INSERT OR REPLACE INTO cve_cache "
            "(cache_key, data, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (key, json.dumps(data), now, now + ttl),
        )
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
