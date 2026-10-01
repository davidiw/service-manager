from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from local_ops.models import iso, utcnow
from local_ops.storage import Database

pytestmark = pytest.mark.asyncio


async def _database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "state.sqlite", tmp_path / "evidence")
    await db.open()
    return db


async def test_discovery_checkpoint_compare_and_set_and_tombstone(tmp_path: Path) -> None:
    db = await _database(tmp_path)
    try:
        assert await db.discovery_checkpoint("opaque-key") is None
        assert await db.save_discovery_checkpoint("opaque-key", {"next_token": "page-2"}, None)
        first = await db.discovery_checkpoint("opaque-key")
        assert first and first["version"] == 0 and first["cursor"] == {"next_token": "page-2"}

        # A delayed page from an older scan cannot overwrite the newer cursor.
        assert not await db.save_discovery_checkpoint("opaque-key", {"next_token": "stale"}, None)
        assert await db.save_discovery_checkpoint("opaque-key", {"next_token": "page-3"}, 0)
        assert not await db.save_discovery_checkpoint("opaque-key", {"next_token": "late"}, 0)

        # Clearing is a versioned tombstone, so an old scan cannot resurrect it either.
        assert await db.save_discovery_checkpoint("opaque-key", None, 1)
        cleared = await db.discovery_checkpoint("opaque-key")
        assert cleared and cleared["version"] == 2 and cleared["cursor"] is None
        assert not await db.save_discovery_checkpoint("opaque-key", {"next_token": "resurrect"}, 1)
    finally:
        await db.close()


async def test_discovery_checkpoint_survives_reopen(tmp_path: Path) -> None:
    db = await _database(tmp_path)
    await db.save_discovery_checkpoint("opaque-key", {"marker": {"page": 9}}, None)
    await db.close()

    db = await _database(tmp_path)
    try:
        checkpoint = await db.discovery_checkpoint("opaque-key")
        assert checkpoint is not None
        assert checkpoint["key"] == "opaque-key"
        assert checkpoint["cursor"] == {"marker": {"page": 9}}
        assert checkpoint["version"] == 0
        assert checkpoint["updated_at"]
    finally:
        await db.close()


async def test_stale_checkpoint_withholds_cursor_but_retains_version(tmp_path: Path) -> None:
    db = await _database(tmp_path)
    try:
        assert await db.save_discovery_checkpoint("opaque-key", {"next_token": "expired"}, None)
        old = iso(utcnow() - timedelta(hours=24, seconds=1))
        async with db.tx() as connection:
            await connection.execute("UPDATE discovery_checkpoints SET updated_at=? WHERE key=?", (old, "opaque-key"))
        checkpoint = await db.discovery_checkpoint("opaque-key")
        assert checkpoint and checkpoint["version"] == 0 and checkpoint["cursor"] is None
    finally:
        await db.close()
