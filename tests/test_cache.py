from __future__ import annotations

import asyncio

import pytest

from cve_mcp.cache.sqlite_cache import VulnCache


@pytest.fixture
async def cache(tmp_path):
    c = VulnCache(str(tmp_path / "test.db"))
    await c.initialize()
    yield c
    await c.close()


@pytest.mark.asyncio
async def test_set_and_get(cache):
    await cache.set("key1", {"foo": "bar"}, ttl=3600)
    result = await cache.get("key1")
    assert result == {"foo": "bar"}


@pytest.mark.asyncio
async def test_expired_returns_none(cache):
    await cache.set("key_exp", {"x": 1}, ttl=0)
    # ttl=0 means already expired
    await asyncio.sleep(0.01)
    result = await cache.get("key_exp")
    assert result is None


@pytest.mark.asyncio
async def test_overwrite(cache):
    await cache.set("key_ow", {"v": 1}, ttl=3600)
    await cache.set("key_ow", {"v": 2}, ttl=3600)
    result = await cache.get("key_ow")
    assert result == {"v": 2}


@pytest.mark.asyncio
async def test_row_cap(tmp_path, monkeypatch):
    import cve_mcp.cache.sqlite_cache as mod

    monkeypatch.setattr(mod, "_MAX_ROWS", 10)
    c = VulnCache(str(tmp_path / "cap.db"))
    await c.initialize()
    # Insert 15 rows
    for i in range(15):
        await c.set(f"key_{i}", {"i": i}, ttl=3600 + i)
    # Re-initialize to trigger cap enforcement
    await c.close()
    c2 = VulnCache(str(tmp_path / "cap.db"))
    await c2.initialize()
    import aiosqlite

    async with aiosqlite.connect(str(tmp_path / "cap.db")) as db:
        async with db.execute("SELECT COUNT(*) FROM cve_cache") as cur:
            count = (await cur.fetchone())[0]
    await c2.close()
    assert count <= 10
