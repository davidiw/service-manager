"""Migration 0004 (D28): existing credentials, settings and history move to read/write capabilities and
data-class review settings without a key being reissued or any data class getting a laxer mode."""

from __future__ import annotations

import json
from pathlib import Path

from local_ops.storage import Database


async def test_legacy_grants_settings_and_requests_are_migrated(tmp_path: Path) -> None:
    db = Database(tmp_path / "db.sqlite", tmp_path / "evidence")
    await db.open()
    try:
        async with db.tx() as c:
            await c.execute("INSERT INTO principals(id,name,key_hash,key_prefix,grants,created_at) VALUES('p1','disc','h1','x1',?, '2026-01-01')", (json.dumps(["discovery", "diagnosis"]),))
            await c.execute("INSERT INTO principals(id,name,key_hash,key_prefix,grants,created_at) VALUES('p2','exec','h2','x2',?, '2026-01-01')", (json.dumps(["execution"]),))
            await c.execute("INSERT INTO review_settings(principal_id,capability,mode,updated_at,updated_by) VALUES('p1','discovery','yolo','t','r'),('p1','diagnosis','review_both','t','r'),('p2','execution','review_requests','t','r')")
            await c.execute("INSERT INTO review_overrides(id,principal_id,capability,mode,expires_at,created_by,created_at) VALUES('o1',NULL,'diagnosis','yolo','2099-01-01','r','t'),('o2',NULL,NULL,'yolo','2099-01-01','r','t')")
            # Dormant pre-D28 state that must not become authority once discovery is regranted as read:
            await c.execute("INSERT INTO principals(id,name,key_hash,key_prefix,grants,created_at) VALUES('p3','disc-only','h3','x3',?, '2026-01-01')", (json.dumps(["discovery"]),))
            await c.execute("INSERT INTO review_settings(principal_id,capability,mode,updated_at,updated_by) VALUES('p3','discovery','review_requests','t','r'),('p3','diagnosis','yolo','t','r'),('p3','execution','yolo','t','r')")
            await c.execute("INSERT INTO review_overrides(id,principal_id,capability,mode,expires_at,created_by,created_at) VALUES('o3','p3',NULL,'yolo','2099-01-01','r','t'),('o4','p3','diagnosis','yolo','2099-01-01','r','t'),('o5','p3','discovery','yolo','2099-01-01','r','t')")
            await c.execute("DELETE FROM schema_version WHERE version >= 4")
        await db.migrate()
        grants = {r["id"]: json.loads(r["grants"]) for r in await db.fetchall("SELECT id, grants FROM principals ORDER BY id")}
        assert grants == {"p1": ["read"], "p2": ["write"], "p3": ["read"]}
        settings = {(r["principal_id"], r["capability"]): r["mode"] for r in await db.fetchall("SELECT * FROM review_settings")}
        # p3's dormant diagnosis/execution yolo settings are dropped, not turned into content/mutation yolo
        assert settings == {("p1", "inventory"): "yolo", ("p1", "content"): "review_both", ("p2", "mutation"): "review_requests", ("p3", "inventory"): "review_requests"}
        overrides = {r["id"]: r["capability"] for r in await db.fetchall("SELECT id, capability FROM review_overrides")}
        # every temporary override is cleared: any could cover a data class a credential gains by the merge
        assert overrides == {}
    finally:
        await db.close()
