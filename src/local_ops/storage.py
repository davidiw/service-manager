"""Durable local state on SQLite (aiosqlite).

One connection per process, WAL, busy timeout, short serialized write transactions. Transactions never
span provider I/O or human review. Large evidence payloads live in a private evidence directory and are
referenced by opaque ids.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from local_ops.models import ExecutionStatus, ResponseStatus, iso, utcnow

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"
if not MIGRATIONS_DIR.exists():  # installed package layout
    MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


class PlanConflict(Exception):
    """Raised by insert_request_with_plan when the plan was already consumed by a different request."""

    def __init__(self, plan_id: str) -> None:
        super().__init__(f"plan {plan_id} already consumed")
        self.plan_id = plan_id


def _j(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _lj(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _row(r: aiosqlite.Row | None) -> dict[str, Any] | None:
    return dict(r) if r is not None else None


_DISCOVERY_CHECKPOINT_TTL = timedelta(hours=24)


def _checkpoint_is_stale(updated_at: str) -> bool:
    """Checkpoint expiry makes a provider restart paging without deleting its CAS tombstone."""
    try:
        recorded_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError:
        # A malformed timestamp must never make an old continuation token appear usable.
        return True
    return recorded_at < utcnow() - _DISCOVERY_CHECKPOINT_TTL


def _encode_update_fields(fields: dict[str, Any]) -> dict[str, Any]:
    fields = dict(fields)
    fields["updated_at"] = iso(utcnow())
    if "audience" in fields:
        fields["audience"] = _j(fields["audience"])
    if "public_error" in fields and fields["public_error"] is not None:
        fields["public_error"] = _j(fields["public_error"])
    return fields


class Database:
    def __init__(self, path: Path, evidence_dir: Path):
        self.path = path
        self.evidence_dir = evidence_dir
        self._conn: aiosqlite.Connection | None = None
        # Readers use their own connection: with a single shared connection, a read issued by another
        # coroutine mid-transaction would observe uncommitted writes. Under WAL each read sees only
        # committed state.
        self._rconn: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    @property
    def conn(self) -> aiosqlite.Connection:
        assert self._conn is not None, "database not opened"
        return self._conn

    @property
    def _reader(self) -> aiosqlite.Connection:
        return self._rconn if self._rconn is not None else self.conn

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.evidence_dir, stat.S_IRWXU)
        self._conn = await aiosqlite.connect(self.path, isolation_level=None, timeout=10)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            await self.migrate()
            self._rconn = await aiosqlite.connect(self.path, isolation_level=None, timeout=10)
            self._rconn.row_factory = aiosqlite.Row
            await self._rconn.execute("PRAGMA busy_timeout=5000")
            await self._rconn.execute("PRAGMA query_only=ON")
        except BaseException:
            await self._conn.close()
            self._conn = None
            raise

    async def close(self) -> None:
        if self._rconn is not None:
            await self._rconn.close()
            self._rconn = None
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def migrate(self) -> None:
        await self.conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        cur = await self.conn.execute("SELECT MAX(version) FROM schema_version")
        row = await cur.fetchone()
        current = row[0] or 0 if row else 0
        files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        for f in files:
            version = int(f.name.split("_", 1)[0])
            if version <= current:
                continue
            sql = f.read_text(encoding="utf-8")
            # sqlite3.executescript() implicitly COMMITs any pending transaction before running, so it
            # cannot sit inside tx(); the script carries its own BEGIN/COMMIT to stay atomic.
            async with self._write_lock:
                await self.conn.executescript(f"BEGIN IMMEDIATE;\n{sql}\nINSERT INTO schema_version(version) VALUES ({int(version)});\nCOMMIT;")

    @asynccontextmanager
    async def tx(self) -> AsyncIterator[aiosqlite.Connection]:
        """Serialized short write transaction."""
        async with self._write_lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise
            else:
                await self.conn.execute("COMMIT")

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        cur = await self._reader.execute(sql, tuple(params))
        return _row(await cur.fetchone())

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        cur = await self._reader.execute(sql, tuple(params))
        return [dict(r) for r in await cur.fetchall()]

    # ---------------------------------------------------------------- settings / audit
    async def get_setting(self, key: str, default: Any = None) -> Any:
        r = await self.fetchone("SELECT value FROM settings WHERE key=?", (key,))
        return _lj(r["value"]) if r else default

    async def set_setting(self, key: str, value: Any, by: str | None = None) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO settings(key,value,updated_at,updated_by) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (key, _j(value), iso(utcnow()), by),
            )

    async def app_audit(self, actor: str, actor_kind: str, action: str, request_id: str | None = None, detail: str | None = None) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO app_audit(at,actor,actor_kind,action,request_id,detail) VALUES(?,?,?,?,?,?)",
                (iso(utcnow()), actor, actor_kind, action, request_id, detail),
            )

    async def app_audit_list(self, limit: int = 200, request_id: str | None = None) -> list[dict[str, Any]]:
        if request_id:
            return await self.fetchall("SELECT * FROM app_audit WHERE request_id=? ORDER BY id DESC LIMIT ?", (request_id, limit))
        return await self.fetchall("SELECT * FROM app_audit ORDER BY id DESC LIMIT ?", (limit,))

    # ---------------------------------------------------------------- principals
    async def insert_principal(self, pid: str, name: str, key_hash: str, key_prefix: str, grants: list[str], note: str | None = None, rotated_from: str | None = None) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO principals(id,name,key_hash,key_prefix,grants,created_at,note,rotated_from) VALUES(?,?,?,?,?,?,?,?)",
                (pid, name, key_hash, key_prefix, _j(grants), iso(utcnow()), note, rotated_from),
            )

    async def principal_by_hash(self, key_hash: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM principals WHERE key_hash=?", (key_hash,))
        if r:
            r["grants"] = _lj(r["grants"], [])
        return r

    async def principal(self, pid: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM principals WHERE id=?", (pid,))
        if r:
            r["grants"] = _lj(r["grants"], [])
        return r

    async def principal_by_name(self, name: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM principals WHERE name=?", (name,))
        if r:
            r["grants"] = _lj(r["grants"], [])
        return r

    async def principals(self) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM principals ORDER BY created_at")
        for r in rows:
            r["grants"] = _lj(r["grants"], [])
        return rows

    async def touch_principal(self, pid: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE principals SET last_used_at=? WHERE id=?", (iso(utcnow()), pid))

    async def revoke_principal(self, pid: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE principals SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (iso(utcnow()), pid))

    async def rename_principal_for_rotation(self, pid: str, new_name: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE principals SET name=? WHERE id=?", (new_name, pid))

    # ---------------------------------------------------------------- reviewers / sessions
    async def upsert_reviewer(self, rid: str, username: str, password_hash: str) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO reviewers(id,username,password_hash,created_at) VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, disabled_at=NULL",
                (rid, username, password_hash, iso(utcnow())),
            )

    async def reviewer_by_username(self, username: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM reviewers WHERE username=? AND disabled_at IS NULL", (username,))

    async def reviewers(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT id, username, created_at, disabled_at FROM reviewers")

    async def create_session(self, reviewer_id: str, ttl: timedelta) -> dict[str, Any]:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = utcnow()
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO reviewer_sessions(id,reviewer_id,csrf_token,created_at,expires_at) VALUES(?,?,?,?,?)",
                (sid, reviewer_id, csrf, iso(now), iso(now + ttl)),
            )
        return {"id": sid, "reviewer_id": reviewer_id, "csrf_token": csrf, "expires_at": iso(now + ttl)}

    async def session(self, sid: str) -> dict[str, Any] | None:
        r = await self.fetchone(
            "SELECT s.*, r.username FROM reviewer_sessions s JOIN reviewers r ON r.id=s.reviewer_id WHERE s.id=? AND s.revoked_at IS NULL AND r.disabled_at IS NULL",
            (sid,),
        )
        if r and r["expires_at"] > iso(utcnow()):
            return r
        return None

    async def revoke_session(self, sid: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE reviewer_sessions SET revoked_at=? WHERE id=?", (iso(utcnow()), sid))

    # ---------------------------------------------------------------- review settings
    async def review_setting(self, principal_id: str, capability: str) -> str | None:
        r = await self.fetchone("SELECT mode FROM review_settings WHERE principal_id=? AND capability=?", (principal_id, capability))
        return r["mode"] if r else None

    async def review_settings_all(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM review_settings ORDER BY principal_id, capability")

    async def set_review_setting(self, principal_id: str, capability: str, mode: str, by: str) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO review_settings(principal_id,capability,mode,updated_at,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(principal_id,capability) DO UPDATE SET mode=excluded.mode, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (principal_id, capability, mode, iso(utcnow()), by),
            )

    async def add_override(self, principal_id: str | None, capability: str | None, mode: str, expires_at: datetime, by: str) -> str:
        oid = new_id("ovr")
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO review_overrides(id,principal_id,capability,mode,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (oid, principal_id, capability, mode, iso(expires_at), by, iso(utcnow())),
            )
        return oid

    async def active_overrides(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM review_overrides WHERE revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC", (iso(utcnow()),))

    async def revoke_override(self, oid: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE review_overrides SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (iso(utcnow()), oid))

    # ---------------------------------------------------------------- requests
    async def _insert_request_rows(self, c: aiosqlite.Connection, row: dict[str, Any], args_canonical: str, args_hash: str) -> None:
        now = iso(utcnow())
        await c.execute(
            """INSERT INTO requests(id,principal_id,capability,operation,reason,current_revision,execution_status,response_status,phase,
               idempotency_key,idempotency_hash,review_request,review_response,review_mode,catalog_revision,target_key,plan_id,audience,created_at,updated_at)
               VALUES(?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["principal_id"], row["capability"], row["operation"], row.get("reason"),
                row["execution_status"], row["response_status"], row.get("phase"),
                row.get("idempotency_key"), row.get("idempotency_hash"), int(row["review_request"]), int(row["review_response"]), row["review_mode"],
                row.get("catalog_revision"), row.get("target_key"), row.get("plan_id"), _j(row.get("audience", [row["principal_id"]])), now, now,
            ),
        )
        await c.execute(
            "INSERT INTO request_revisions(request_id,revision,args,args_hash,created_at,created_by,note) VALUES(?,1,?,?,?,?,?)",
            (row["id"], args_canonical, args_hash, now, row["principal_id"], "submitted"),
        )

    async def insert_request(self, row: dict[str, Any], args_canonical: str, args_hash: str) -> None:
        async with self.tx() as c:
            await self._insert_request_rows(c, row, args_canonical, args_hash)

    async def insert_request_with_plan(
        self, row: dict[str, Any], args_canonical: str, args_hash: str, *, idempotency_key: str | None, consume_plan_id: str | None,
    ) -> dict[str, Any] | None:
        """Atomic unit covering the whole submission race: in one transaction, (1) if a request already
        exists for this principal+idempotency_key, return it unchanged (idempotent replay: nothing new is
        written, no plan is touched); otherwise (2) consume ``consume_plan_id``'s plan (conditional on it
        not already being consumed) and insert the new request row, binding the plan to this request's
        real id directly -- there is no placeholder/pending state for another request to strand.
        Returns the existing row (raw, undecoded JSON columns) on idempotent replay, else None. Raises
        ``PlanConflict`` if a plan_id was given but the plan was already consumed by a different request
        (this can only happen for a genuinely distinct idempotency key reusing a stale plan)."""
        async with self.tx() as c:
            if idempotency_key:
                cur = await c.execute("SELECT * FROM requests WHERE principal_id=? AND idempotency_key=?", (row["principal_id"], idempotency_key))
                erow = await cur.fetchone()
                if erow is not None:
                    existing = dict(erow)
                    existing["audience"] = _lj(existing["audience"], [])
                    existing["public_error"] = _lj(existing["public_error"])
                    return existing
            if consume_plan_id:
                cur = await c.execute(
                    "UPDATE plans SET consumed_at=?, consumed_by_request_id=? WHERE plan_id=? AND consumed_at IS NULL",
                    (iso(utcnow()), row["id"], consume_plan_id),
                )
                if cur.rowcount != 1:
                    raise PlanConflict(consume_plan_id)
            await self._insert_request_rows(c, row, args_canonical, args_hash)
        return None

    async def request(self, request_id: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM requests WHERE id=?", (request_id,))
        if r:
            r["audience"] = _lj(r["audience"], [])
            r["public_error"] = _lj(r["public_error"])
        return r

    async def request_by_idempotency(self, principal_id: str, key: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM requests WHERE principal_id=? AND idempotency_key=?", (principal_id, key))
        if r:
            r["audience"] = _lj(r["audience"], [])
            r["public_error"] = _lj(r["public_error"])
        return r

    async def requests_list(self, *, execution_status: list[str] | None = None, response_status: list[str] | None = None, principal_id: str | None = None, capability: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        clauses, params = [], []
        if execution_status:
            clauses.append(f"execution_status IN ({','.join('?' * len(execution_status))})")
            params += execution_status
        if response_status:
            clauses.append(f"response_status IN ({','.join('?' * len(response_status))})")
            params += response_status
        if principal_id:
            clauses.append("principal_id=?")
            params.append(principal_id)
        if capability:
            clauses.append("capability=?")
            params.append(capability)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = await self.fetchall(f"SELECT * FROM requests {where} ORDER BY created_at DESC LIMIT ?", (*params, limit))
        for r in rows:
            r["audience"] = _lj(r["audience"], [])
            r["public_error"] = _lj(r["public_error"])
        return rows

    async def update_request(self, request_id: str, **fields: Any) -> None:
        """Unconditional update. Only for fields that are not part of the execution_status lifecycle
        (e.g. phase bookkeeping written by the dispatching worker itself, which already owns the row via
        its own claim). A reviewer/agent-initiated status transition must use `transition_request` (or
        `approve_transition` / `transition_with_approval_invalidation`) below instead, so it can never
        clobber a status change that happened concurrently."""
        if not fields:
            return
        fields = _encode_update_fields(fields)
        sets = ", ".join(f"{k}=?" for k in fields)
        async with self.tx() as c:
            await c.execute(f"UPDATE requests SET {sets} WHERE id=?", (*fields.values(), request_id))

    async def transition_request(self, request_id: str, expected: Iterable[str], **fields: Any) -> bool:
        """Compare-and-set lifecycle transition: UPDATE ... WHERE id=? AND execution_status IN
        (expected). Returns True iff exactly one row -- this request, still in one of the expected
        prior states -- was updated. Callers that lose the race (status already moved on, e.g. a
        worker claimed it or another reviewer action already resolved it) must re-read and decide
        what to do; they must never retry with the unconditional `update_request`."""
        if not fields:
            return False
        fields = _encode_update_fields(fields)
        expected = list(expected)
        placeholders = ",".join("?" * len(expected))
        sets = ", ".join(f"{k}=?" for k in fields)
        async with self.tx() as c:
            cur = await c.execute(f"UPDATE requests SET {sets} WHERE id=? AND execution_status IN ({placeholders})", (*fields.values(), request_id, *expected))
            return cur.rowcount == 1

    async def transition_with_approval_invalidation(self, request_id: str, expected: Iterable[str], fields: dict[str, Any], invalidate_reason: str) -> bool:
        """Used by reject/requeue: invalidate any active approval together with the CAS status
        transition, in one transaction, so a reviewer action can never land on a request that already
        moved on, and never leaves a stale active approval behind when it does land."""
        fields = _encode_update_fields(fields)
        expected = list(expected)
        placeholders = ",".join("?" * len(expected))
        sets = ", ".join(f"{k}=?" for k in fields)
        async with self.tx() as c:
            cur = await c.execute(f"UPDATE requests SET {sets} WHERE id=? AND execution_status IN ({placeholders})", (*fields.values(), request_id, *expected))
            if cur.rowcount != 1:
                return False
            await c.execute(
                "UPDATE approvals SET invalidated_at=?, invalidated_reason=? WHERE request_id=? AND invalidated_at IS NULL",
                (iso(utcnow()), invalidate_reason, request_id),
            )
        return True

    async def claim_queued(self, worker_token: str, limit: int = 1) -> list[dict[str, Any]]:
        """Atomically move queued requests to running for this worker."""
        claimed: list[dict[str, Any]] = []
        async with self.tx() as c:
            cur = await c.execute(
                "SELECT id FROM requests WHERE execution_status=? AND cancel_requested_at IS NULL ORDER BY (phase IS NOT NULL AND (phase LIKE 'waiting_for_lock%' OR phase = 'blocked_by_stop_switch')), created_at LIMIT ?",
                (ExecutionStatus.QUEUED.value, limit),
            )
            ids = [r["id"] for r in await cur.fetchall()]
            now = iso(utcnow())
            for rid in ids:
                await c.execute(
                    "UPDATE requests SET execution_status=?, phase='preparing', started_at=COALESCE(started_at, ?), updated_at=?, worker_token=? WHERE id=?",
                    (ExecutionStatus.RUNNING.value, now, now, worker_token, rid),
                )
        for rid in ids:
            r = await self.request(rid)
            if r:
                claimed.append(r)
        return claimed

    async def add_revision(self, request_id: str, args_canonical: str, args_hash: str, by: str, note: str) -> int:
        async with self.tx() as c:
            cur = await c.execute("SELECT current_revision FROM requests WHERE id=?", (request_id,))
            row = await cur.fetchone()
            rev = (row[0] if row else 0) + 1
            await c.execute(
                "INSERT INTO request_revisions(request_id,revision,args,args_hash,created_at,created_by,note) VALUES(?,?,?,?,?,?,?)",
                (request_id, rev, args_canonical, args_hash, iso(utcnow()), by, note),
            )
            await c.execute("UPDATE requests SET current_revision=?, updated_at=? WHERE id=?", (rev, iso(utcnow()), request_id))
            await c.execute(
                "UPDATE approvals SET invalidated_at=?, invalidated_reason='request revised' WHERE request_id=? AND invalidated_at IS NULL",
                (iso(utcnow()), request_id),
            )
        return rev

    async def revision(self, request_id: str, revision: int | None = None) -> dict[str, Any] | None:
        if revision is None:
            r = await self.fetchone("SELECT * FROM request_revisions WHERE request_id=? ORDER BY revision DESC LIMIT 1", (request_id,))
        else:
            r = await self.fetchone("SELECT * FROM request_revisions WHERE request_id=? AND revision=?", (request_id, revision))
        if r:
            r["args"] = _lj(r["args"], {})
        return r

    async def revisions(self, request_id: str) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM request_revisions WHERE request_id=? ORDER BY revision", (request_id,))
        for r in rows:
            r["args"] = _lj(r["args"], {})
        return rows

    # ---------------------------------------------------------------- approvals
    async def approve_transition(self, request_id: str, expected: Iterable[str], row: dict[str, Any]) -> str | None:
        """Insert the approval and move the request to QUEUED, atomically and conditional on the
        request still being in one of `expected` statuses. Returns the new approval id, or None (no
        approval written, no status change) if the request had already moved on -- e.g. a reject or
        cancel landed during the awaits leading up to this call."""
        aid = new_id("apr")
        expected = list(expected)
        placeholders = ",".join("?" * len(expected))
        async with self.tx() as c:
            cur = await c.execute(
                f"UPDATE requests SET execution_status=?, updated_at=? WHERE id=? AND execution_status IN ({placeholders})",
                (ExecutionStatus.QUEUED.value, iso(utcnow()), request_id, *expected),
            )
            if cur.rowcount != 1:
                return None
            await c.execute(
                """INSERT INTO approvals(id,request_id,revision,args_hash,principal_id,capability,implementation_version,catalog_revision,plan_hash,approved_by,approved_at,expires_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    aid, row["request_id"], row["revision"], row["args_hash"], row["principal_id"], row["capability"], row["implementation_version"],
                    row.get("catalog_revision"), row.get("plan_hash"), row["approved_by"], iso(utcnow()), iso(row["expires_at"]),
                ),
            )
        return aid

    async def active_approval(self, request_id: str) -> dict[str, Any] | None:
        return await self.fetchone(
            "SELECT * FROM approvals WHERE request_id=? AND invalidated_at IS NULL ORDER BY approved_at DESC LIMIT 1", (request_id,)
        )

    async def approvals(self, request_id: str) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM approvals WHERE request_id=? ORDER BY approved_at", (request_id,))

    # ---------------------------------------------------------------- results / evidence
    async def _store_candidate(self, c: aiosqlite.Connection, request_id: str, candidate: dict[str, Any], sanitization: dict[str, Any], evidence_ids: list[str], truncated: bool) -> None:
        payload = _j(candidate)
        await c.execute(
            "INSERT INTO results(request_id,candidate,candidate_bytes,sanitization,evidence_ids,truncated) VALUES(?,?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET candidate=excluded.candidate, candidate_bytes=excluded.candidate_bytes, sanitization=excluded.sanitization, evidence_ids=excluded.evidence_ids, truncated=excluded.truncated",
            (request_id, payload, len(payload), _j(sanitization), _j(evidence_ids), int(truncated)),
        )

    async def store_candidate(self, request_id: str, candidate: dict[str, Any], sanitization: dict[str, Any], evidence_ids: list[str], truncated: bool) -> None:
        async with self.tx() as c:
            await self._store_candidate(c, request_id, candidate, sanitization, evidence_ids, truncated)

    async def finalize_request(self, request_id: str, fields: dict[str, Any], candidate: dict[str, Any], sanitization: dict[str, Any], evidence_ids: list[str], truncated: bool, *, auto_release: bool, audience: list[str]) -> None:
        """Store the candidate, set the terminal execution status and (when no response review is required)
        release the projection, all in one transaction so no observer sees a half-finished request."""
        fields = dict(fields)
        fields["updated_at"] = iso(utcnow())
        if "public_error" in fields and fields["public_error"] is not None:
            fields["public_error"] = _j(fields["public_error"])
        async with self.tx() as c:
            await self._store_candidate(c, request_id, candidate, sanitization, evidence_ids, truncated)
            if auto_release:
                await self._release(c, request_id, candidate, "auto:review_mode", None, audience)
                fields["response_status"] = ResponseStatus.RELEASED.value
            sets = ", ".join(f"{k}=?" for k in fields)
            await c.execute(f"UPDATE requests SET {sets} WHERE id=?", (*fields.values(), request_id))

    async def result(self, request_id: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM results WHERE request_id=?", (request_id,))
        if r:
            r["candidate"] = _lj(r["candidate"])
            r["released"] = _lj(r["released"])
            r["redaction"] = _lj(r["redaction"])
            r["sanitization"] = _lj(r["sanitization"], {})
            r["evidence_ids"] = _lj(r["evidence_ids"], [])
        return r

    async def _release(self, c: aiosqlite.Connection, request_id: str, released: dict[str, Any], by: str, redaction: dict[str, Any] | None, audience: list[str]) -> None:
        now = iso(utcnow())
        await c.execute(
            "UPDATE results SET released=?, released_at=?, released_by=?, redaction=?, withheld_at=NULL, withheld_by=NULL, withhold_reason=NULL WHERE request_id=?",
            (_j(released), now, by, _j(redaction) if redaction else None, request_id),
        )
        await c.execute("UPDATE requests SET response_status=?, updated_at=? WHERE id=?", (ResponseStatus.RELEASED.value, now, request_id))
        # Mark underlying rows released to the audience. A path redaction cannot be applied to the stored
        # rows, so a redacted release grants *only* the redacted projection: no evidence, observation,
        # audit-event, finding or plan row becomes readable through other tools.
        if redaction and redaction.get("paths"):
            return
        excluded = set((redaction or {}).get("excluded_evidence_ids", []))
        for table in ("evidence", "observations", "audit_events", "findings", "plans"):
            idcol = {"evidence": "id", "observations": "id", "audit_events": "event_key", "findings": "id", "plans": "plan_id"}[table]
            reqcol = "scan_request_id" if table == "observations" else "request_id"
            cur = await c.execute(f"SELECT {idcol}, released_to FROM {table} WHERE {reqcol}=?", (request_id,))
            for row in await cur.fetchall():
                if row[0] in excluded:
                    continue
                if excluded and table in ("observations", "audit_events", "findings"):
                    col = "evidence_ids" if table == "findings" else "evidence_id"
                    c2 = await c.execute(f"SELECT {col} FROM {table} WHERE {idcol}=?", (row[0],))
                    fetched = await c2.fetchone()
                    ref = fetched[0] if fetched else None
                    refs = set(_lj(ref, [])) if table == "findings" else {ref}
                    if refs & excluded:
                        continue  # derived from an excluded evidence fragment
                current = set(_lj(row[1], []))
                current.update(audience)
                await c.execute(f"UPDATE {table} SET released_to=? WHERE {idcol}=?", (_j(sorted(current)), row[0]))

    async def release_result(self, request_id: str, released: dict[str, Any], by: str, redaction: dict[str, Any] | None, audience: list[str]) -> None:
        async with self.tx() as c:
            await self._release(c, request_id, released, by, redaction, audience)

    async def withhold_result(self, request_id: str, by: str, reason: str) -> None:
        now = iso(utcnow())
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO results(request_id,evidence_ids) VALUES(?,'[]') ON CONFLICT(request_id) DO NOTHING", (request_id,)
            )
            await c.execute(
                "UPDATE results SET withheld_at=?, withheld_by=?, withhold_reason=?, released=NULL, released_at=NULL, released_by=NULL WHERE request_id=?",
                (now, by, reason, request_id),
            )
            await c.execute("UPDATE requests SET response_status=?, updated_at=? WHERE id=?", (ResponseStatus.WITHHELD.value, now, request_id))
            # Revoke this request's audience from the derived rows its own release previously granted
            # (the mirror of `_release`'s grant below). Without this, findings_read/evidence_get/plan
            # submission keep disclosing a withheld result's raw rows, and a later redacted re-release
            # (which deliberately grants none of these rows -- D17) would leave the earlier, unredacted
            # grant in place.
            #
            # Rule: only touch rows whose own ownership column (`request_id`, or `scan_request_id` for
            # observations) equals *this* request's id -- the exact scoping `_release` uses to grant
            # them in the first place -- and only remove *this* request's audience members. Evidence,
            # audit_events (owned by the first collector; a later request's duplicate collection never
            # takes ownership) and findings/plans are singly-owned by their one originating request, so
            # this can never touch a row another request owns. Observations are reset to released_to=
            # '[]' every time they are re-observed by a different scan (`upsert_observations`), so once
            # a different request's scan reclaims `scan_request_id`, nothing of this request's grant
            # remains for us to (mis)touch -- we simply find no matching row.
            cur = await c.execute("SELECT audience FROM requests WHERE id=?", (request_id,))
            arow = await cur.fetchone()
            audience = set(_lj(arow[0], [])) if arow else set()
            if audience:
                for table in ("evidence", "observations", "audit_events", "findings", "plans"):
                    idcol = {"evidence": "id", "observations": "id", "audit_events": "event_key", "findings": "id", "plans": "plan_id"}[table]
                    reqcol = "scan_request_id" if table == "observations" else "request_id"
                    cur2 = await c.execute(f"SELECT {idcol}, released_to FROM {table} WHERE {reqcol}=?", (request_id,))
                    for row in await cur2.fetchall():
                        current = set(_lj(row[1], []))
                        if not (current & audience):
                            continue
                        current -= audience
                        await c.execute(f"UPDATE {table} SET released_to=? WHERE {idcol}=?", (_j(sorted(current)), row[0]))

    async def insert_evidence(self, eid: str, request_id: str | None, source: str, kind: str, payload: bytes, summary: str | None, sanitization: dict[str, Any] | None, provenance: dict[str, Any] | None) -> None:
        rel = f"{eid[:6]}/{eid}.bin"
        full = self.evidence_dir / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        tmp = full.with_suffix(".tmp")

        def _write() -> None:
            with open(tmp, "wb") as fh:
                fh.write(payload)
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, full)

        await asyncio.to_thread(_write)  # local file write kept off the event loop
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO evidence(id,request_id,source,kind,created_at,bytes,path,summary,sanitization,provenance) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (eid, request_id, source, kind, iso(utcnow()), len(payload), rel, summary, _j(sanitization or {}), _j(provenance or {})),
            )

    async def evidence(self, eid: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM evidence WHERE id=?", (eid,))
        if r:
            r["released_to"] = _lj(r["released_to"], [])
            r["sanitization"] = _lj(r["sanitization"], {})
            r["provenance"] = _lj(r["provenance"], {})
        return r

    async def evidence_for_request(self, request_id: str) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM evidence WHERE request_id=? ORDER BY created_at", (request_id,))
        for r in rows:
            r["released_to"] = _lj(r["released_to"], [])
            r["sanitization"] = _lj(r["sanitization"], {})
            r["provenance"] = _lj(r["provenance"], {})
        return rows

    def evidence_bytes(self, record: dict[str, Any]) -> bytes:
        rel = record["path"]
        full = (self.evidence_dir / rel).resolve()
        if not str(full).startswith(str(self.evidence_dir.resolve()) + os.sep):
            raise PermissionError("evidence path escapes evidence directory")
        if full.is_symlink():
            raise PermissionError("evidence path is a symlink")
        return full.read_bytes()

    async def set_retention_hold(self, eid: str, hold: bool) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE evidence SET retention_hold=? WHERE id=?", (int(hold), eid))

    # ---------------------------------------------------------------- observations / scans
    async def record_scan(self, request_id: str, provider_ids: list[str], scope: dict[str, Any]) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO scans(request_id,provider_ids,scope,started_at) VALUES(?,?,?,?) ON CONFLICT(request_id) DO NOTHING",
                (request_id, _j(provider_ids), _j(scope), iso(utcnow())),
            )

    async def finish_scan(self, request_id: str, denominators: dict[str, Any], completed_scopes: list[str], unavailable: list[dict[str, Any]]) -> None:
        async with self.tx() as c:
            await c.execute(
                "UPDATE scans SET denominators=?, completed_scopes=?, unavailable=?, finished_at=? WHERE request_id=?",
                (_j(denominators), _j(completed_scopes), _j(unavailable), iso(utcnow()), request_id),
            )

    async def scans(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))
        for r in rows:
            for k in ("provider_ids", "scope", "denominators", "completed_scopes", "unavailable"):
                r[k] = _lj(r[k])
        return rows

    async def upsert_observations(self, scan_request_id: str, rows: list[dict[str, Any]]) -> list[str]:
        """Insert or refresh observations keyed by (provider_id, resource_key). Returns ids."""
        ids: list[str] = []
        now = iso(utcnow())
        async with self.tx() as c:
            for o in rows:
                cur = await c.execute("SELECT id, first_seen_at FROM observations WHERE provider_id=? AND resource_key=?", (o["provider_id"], o["resource_key"]))
                existing = await cur.fetchone()
                if existing:
                    oid = existing[0]
                    await c.execute(
                        """UPDATE observations SET scan_request_id=?, resource_type=?, identity=?, attributes=?, observed_at=?, evidence_id=?, match_service_id=?, match_binding_id=?,
                           match_basis=?, match_confidence=?, last_seen_at=?, missing_since=NULL, scope_key=?, released_to='[]' WHERE id=?""",
                        (
                            scan_request_id, o["resource_type"], _j(o["identity"]), _j(o["attributes"]), o.get("observed_at") or now, o.get("evidence_id"),
                            o.get("match_service_id"), o.get("match_binding_id"), o.get("match_basis"), o.get("match_confidence"), now, o.get("scope_key"), oid,
                        ),
                    )
                else:
                    oid = new_id("obs")
                    await c.execute(
                        """INSERT INTO observations(id,scan_request_id,provider_id,resource_key,resource_type,identity,attributes,observed_at,evidence_id,match_service_id,match_binding_id,
                           match_basis,match_confidence,first_seen_at,last_seen_at,scope_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            oid, scan_request_id, o["provider_id"], o["resource_key"], o["resource_type"], _j(o["identity"]), _j(o["attributes"]),
                            o.get("observed_at") or now, o.get("evidence_id"), o.get("match_service_id"), o.get("match_binding_id"), o.get("match_basis"),
                            o.get("match_confidence"), now, now, o.get("scope_key"),
                        ),
                    )
                ids.append(oid)
        return ids

    async def mark_missing(self, provider_id: str, scope_key: str, seen_resource_keys: set[str]) -> int:
        """Only called for a complete comparable scope scan."""
        n = 0
        async with self.tx() as c:
            cur = await c.execute("SELECT id, resource_key FROM observations WHERE provider_id=? AND scope_key=? AND missing_since IS NULL", (provider_id, scope_key))
            for row in await cur.fetchall():
                if row[1] not in seen_resource_keys:
                    await c.execute("UPDATE observations SET missing_since=? WHERE id=?", (iso(utcnow()), row[0]))
                    n += 1
        return n

    async def observations(self, *, service_id: str | None = None, provider_id: str | None = None, audience: str | None = None, include_missing: bool = True, limit: int = 1000) -> list[dict[str, Any]]:
        clauses, params = [], []
        if service_id:
            clauses.append("match_service_id=?")
            params.append(service_id)
        if provider_id:
            clauses.append("provider_id=?")
            params.append(provider_id)
        if not include_missing:
            clauses.append("missing_since IS NULL")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = await self.fetchall(f"SELECT * FROM observations {where} ORDER BY resource_type, resource_key LIMIT ?", (*params, limit))
        out = []
        for r in rows:
            r["identity"] = _lj(r["identity"], {})
            r["attributes"] = _lj(r["attributes"], {})
            r["released_to"] = _lj(r["released_to"], [])
            if audience is not None and audience not in r["released_to"]:
                continue
            out.append(r)
        return out

    async def observations_for_scan(self, scan_request_id: str) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM observations WHERE scan_request_id=? ORDER BY resource_type, resource_key", (scan_request_id,))
        for r in rows:
            r["identity"] = _lj(r["identity"], {})
            r["attributes"] = _lj(r["attributes"], {})
            r["released_to"] = _lj(r["released_to"], [])
        return rows

    # ---------------------------------------------------------------- audit events / cursors
    async def upsert_audit_events(self, request_id: str | None, events: list[dict[str, Any]]) -> tuple[int, int]:
        inserted = duplicates = 0
        async with self.tx() as c:
            for e in events:
                cur = await c.execute("SELECT 1 FROM audit_events WHERE event_key=?", (e["event_key"],))
                if await cur.fetchone():
                    duplicates += 1
                    continue
                await c.execute(
                    """INSERT INTO audit_events(event_key,provider,source_id,account,region,event_id,occurred_at,collected_at,actor,actor_type,session,action,resource,resource_type,
                       source_ip,user_agent,outcome,category,request_id,evidence_id,fields) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        e["event_key"], e["provider"], e["source_id"], e.get("account"), e.get("region"), e.get("event_id"), e["occurred_at"], e["collected_at"],
                        e.get("actor"), e.get("actor_type"), e.get("session"), e["action"], e.get("resource"), e.get("resource_type"), e.get("source_ip"),
                        e.get("user_agent"), e.get("outcome"), e.get("category", "management"), request_id, e.get("evidence_ref"), _j(e.get("fields", {})),
                    ),
                )
                inserted += 1
        return inserted, duplicates

    async def audit_events(self, *, source_ids: list[str] | None = None, start: str | None = None, end: str | None = None, request_id: str | None = None, audience: str | None = None, limit: int = 5000) -> list[dict[str, Any]]:
        clauses, params = [], []
        if source_ids:
            clauses.append(f"source_id IN ({','.join('?' * len(source_ids))})")
            params += source_ids
        if start:
            clauses.append("occurred_at>=?")
            params.append(start)
        if end:
            clauses.append("occurred_at<=?")
            params.append(end)
        if request_id:
            clauses.append("request_id=?")
            params.append(request_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = await self.fetchall(f"SELECT * FROM audit_events {where} ORDER BY occurred_at LIMIT ?", (*params, limit))
        out = []
        for r in rows:
            r["fields"] = _lj(r["fields"], {})
            r["released_to"] = _lj(r["released_to"], [])
            if audience is not None and audience not in r["released_to"]:
                continue
            out.append(r)
        return out

    async def cursor(self, source_id: str, scope: str) -> dict[str, Any] | None:
        return await self.fetchone("SELECT * FROM audit_cursors WHERE source_id=? AND scope=?", (source_id, scope))

    async def save_cursor(self, source_id: str, scope: str, cursor: str | None, last_event_at: str | None, note: str | None = None) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO audit_cursors(source_id,scope,cursor,last_event_at,updated_at,note) VALUES(?,?,?,?,?,?) ON CONFLICT(source_id,scope) DO UPDATE SET cursor=excluded.cursor, last_event_at=excluded.last_event_at, updated_at=excluded.updated_at, note=excluded.note",
                (source_id, scope, cursor, last_event_at, iso(utcnow()), note),
            )

    async def cursors(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM audit_cursors ORDER BY source_id, scope")

    # ---------------------------------------------------------------- discovery checkpoints
    async def discovery_checkpoint(self, key: str) -> dict[str, Any] | None:
        """Return a private continuation checkpoint, withholding a cursor older than 24 hours.

        The opaque key is supplied by the caller and must bind the principal, provider,
        configuration, verified identity, filters, API, and region.  Expired entries are retained
        as versioned tombstones so a late writer cannot overwrite a newer scan.
        """
        row = await self.fetchone(
            "SELECT key,cursor,version,updated_at FROM discovery_checkpoints WHERE key=?", (key,)
        )
        if row is None:
            return None
        row["cursor"] = None if row["cursor"] is None or _checkpoint_is_stale(row["updated_at"]) else _lj(row["cursor"])
        return row

    async def save_discovery_checkpoint(
        self, key: str, cursor: dict[str, Any] | None, expected_version: int | None
    ) -> bool:
        """Compare-and-set a private discovery continuation token.

        ``cursor=None`` records a tombstone rather than deleting the row.  Every successful write
        advances ``version`` so delayed scans cannot resurrect or clear a newer checkpoint.
        """
        if cursor is not None and not isinstance(cursor, dict):
            raise TypeError("discovery checkpoint cursor must be a structured token object or None")
        encoded_cursor = _j(cursor) if cursor is not None else None
        async with self.tx() as c:
            if expected_version is None:
                result = await c.execute(
                    "INSERT INTO discovery_checkpoints(key,cursor,version,updated_at) VALUES(?,?,0,?) ON CONFLICT(key) DO NOTHING",
                    (key, encoded_cursor, iso(utcnow())),
                )
            else:
                result = await c.execute(
                    "UPDATE discovery_checkpoints SET cursor=?,version=version+1,updated_at=? WHERE key=? AND version=?",
                    (encoded_cursor, iso(utcnow()), key, expected_version),
                )
            return result.rowcount == 1

    # ---------------------------------------------------------------- findings
    async def insert_findings(self, request_id: str | None, findings: list[dict[str, Any]]) -> None:
        async with self.tx() as c:
            for f in findings:
                await c.execute(
                    "INSERT INTO findings(id,request_id,rule_id,rule_version,severity,confidence,body,evidence_ids,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                    (f["finding_id"], request_id, f["rule_id"], f["rule_version"], f["severity"], f["confidence"], _j(f), _j(f.get("evidence_ids", [])), iso(utcnow())),
                )

    async def findings(self, *, request_id: str | None = None, audience: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        if request_id:
            rows = await self.fetchall("SELECT * FROM findings WHERE request_id=? ORDER BY created_at DESC LIMIT ?", (request_id, limit))
        else:
            rows = await self.fetchall("SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            r["body"] = _lj(r["body"], {})
            r["released_to"] = _lj(r["released_to"], [])
            r["evidence_ids"] = _lj(r["evidence_ids"], [])
            if audience is not None and audience not in r["released_to"]:
                continue
            out.append(r)
        return out

    # ---------------------------------------------------------------- plans / receipts / locks / intents
    async def insert_plan(self, plan_id: str, request_id: str, principal_id: str, plan_hash: str, body: dict[str, Any], target_key: str, expires_at: datetime) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO plans(plan_id,request_id,principal_id,plan_hash,body,target_key,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
                (plan_id, request_id, principal_id, plan_hash, _j(body), target_key, iso(utcnow()), iso(expires_at)),
            )

    async def plan(self, plan_id: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM plans WHERE plan_id=?", (plan_id,))
        if r:
            r["body"] = _lj(r["body"], {})
            r["released_to"] = _lj(r["released_to"], [])
        return r

    async def consume_plan(self, plan_id: str, request_id: str) -> bool:
        async with self.tx() as c:
            cur = await c.execute("UPDATE plans SET consumed_at=?, consumed_by_request_id=? WHERE plan_id=? AND consumed_at IS NULL", (iso(utcnow()), request_id, plan_id))
            return cur.rowcount == 1

    async def release_plan_consumption(self, plan_id: str) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE plans SET consumed_at=NULL, consumed_by_request_id=NULL WHERE plan_id=?", (plan_id,))

    async def insert_receipt(self, receipt_id: str, request_id: str, plan_id: str, body: dict[str, Any]) -> None:
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO receipts(receipt_id,request_id,plan_id,body,created_at) VALUES(?,?,?,?,?) ON CONFLICT(receipt_id) DO UPDATE SET body=excluded.body",
                (receipt_id, request_id, plan_id, _j(body), iso(utcnow())),
            )

    async def receipt_for_request(self, request_id: str) -> dict[str, Any] | None:
        r = await self.fetchone("SELECT * FROM receipts WHERE request_id=? ORDER BY created_at DESC LIMIT 1", (request_id,))
        if r:
            r["body"] = _lj(r["body"], {})
        return r

    async def receipts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM receipts ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["body"] = _lj(r["body"], {})
        return rows

    async def receipts_released_to(self, principal_id: str, limit: int = 200) -> list[dict[str, Any]]:
        """Receipts whose owning request's response was released to this principal: either the
        principal is in the request's audience, or the principal is the submitter and the response was
        released. A receipt whose request was never released (or released to someone else only) is
        omitted so one principal cannot read another principal's execution history via service_inspect."""
        rows = await self.fetchall(
            """SELECT rc.*, rq.response_status AS req_response_status, rq.audience AS req_audience, rq.principal_id AS req_principal_id
               FROM receipts rc JOIN requests rq ON rq.id = rc.request_id ORDER BY rc.created_at DESC LIMIT ?""",
            (limit,),
        )
        out = []
        for r in rows:
            audience = _lj(r.pop("req_audience"), [])
            released = r.pop("req_response_status") == ResponseStatus.RELEASED.value
            req_principal = r.pop("req_principal_id")
            if released and (principal_id in audience or principal_id == req_principal):
                r["body"] = _lj(r["body"], {})
                out.append(r)
        return out

    async def try_lock(self, target_keys: list[str], request_id: str) -> str | None:
        """Acquire all locks in deterministic order or none. Returns the conflicting key on failure."""
        keys = sorted(set(target_keys))
        async with self.tx() as c:
            for k in keys:
                cur = await c.execute("SELECT request_id FROM operation_locks WHERE target_key=?", (k,))
                row = await cur.fetchone()
                if row and row[0] != request_id:
                    return k
            for k in keys:
                await c.execute("INSERT INTO operation_locks(target_key,request_id,acquired_at) VALUES(?,?,?) ON CONFLICT(target_key) DO NOTHING", (k, request_id, iso(utcnow())))
        return None

    async def unlock(self, request_id: str) -> None:
        async with self.tx() as c:
            await c.execute("DELETE FROM operation_locks WHERE request_id=?", (request_id,))

    async def locks(self) -> list[dict[str, Any]]:
        return await self.fetchall("SELECT * FROM operation_locks ORDER BY acquired_at")

    async def record_intent(self, request_id: str, phase: str, target_key: str | None, description: str, provider_op: dict[str, Any]) -> str:
        iid = new_id("int")
        async with self.tx() as c:
            await c.execute(
                "INSERT INTO provider_intents(id,request_id,phase,target_key,description,provider_op,recorded_at) VALUES(?,?,?,?,?,?,?)",
                (iid, request_id, phase, target_key, description, _j(provider_op), iso(utcnow())),
            )
        return iid

    async def complete_intent(self, iid: str, result: dict[str, Any]) -> None:
        async with self.tx() as c:
            await c.execute("UPDATE provider_intents SET completed_at=?, result=? WHERE id=?", (iso(utcnow()), _j(result), iid))

    async def intents(self, request_id: str) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM provider_intents WHERE request_id=? ORDER BY recorded_at", (request_id,))
        for r in rows:
            r["provider_op"] = _lj(r["provider_op"], {})
            r["result"] = _lj(r["result"])
        return rows

    # ---------------------------------------------------------------- schedules
    async def insert_schedule(self, row: dict[str, Any]) -> str:
        sid = new_id("sch")
        async with self.tx() as c:
            await c.execute(
                """INSERT INTO schedules(id,name,principal_id,capability,operation,template,frequency_seconds,lookback_seconds,budgets,approval_expires_at,disclosure,enabled,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid, row["name"], row["principal_id"], row["capability"], row["operation"], _j(row["template"]), row["frequency_seconds"], row["lookback_seconds"],
                    _j(row.get("budgets", {})), iso(row["approval_expires_at"]), _j(row.get("disclosure", {})), int(row.get("enabled", False)), row["created_by"], iso(utcnow()),
                ),
            )
        return sid

    async def schedules(self) -> list[dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM schedules ORDER BY created_at")
        for r in rows:
            r["template"] = _lj(r["template"], {})
            r["budgets"] = _lj(r["budgets"], {})
            r["disclosure"] = _lj(r["disclosure"], {})
        return rows

    async def update_schedule(self, sid: str, **fields: Any) -> None:
        if not fields:
            return
        for k in ("template", "budgets", "disclosure"):
            if k in fields:
                fields[k] = _j(fields[k])
        sets = ", ".join(f"{k}=?" for k in fields)
        async with self.tx() as c:
            await c.execute(f"UPDATE schedules SET {sets} WHERE id=?", (*fields.values(), sid))

    # ---------------------------------------------------------------- retention
    # ---------------------------------------------------------------- catalog proposals (D24)
    async def insert_proposal(self, row: dict[str, Any]) -> tuple[str, bool]:
        """Insert a proposal, or return the existing one with the same principal and content hash.
        Returns (proposal_id, existing)."""
        async with self.tx() as c:
            cur = await c.execute("SELECT id FROM proposals WHERE principal_id=? AND content_hash=?", (row["principal_id"], row["content_hash"]))
            found = await cur.fetchone()
            if found:
                return str(found[0]), True
            pid = new_id("prp")
            await c.execute(
                """INSERT INTO proposals(id,principal_id,capability,service_id,is_new_service,base_revision,base_file_hash,target_path,reason,changes,citations,proposed_text,proposed_file_hash,diff,content_hash,notes,status,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pid, row["principal_id"], row["capability"], row["service_id"], int(row["is_new_service"]), row["base_revision"], row.get("base_file_hash"), row["target_path"], row.get("reason"),
                 _j(row["changes"]), _j(row["citations"]), row["proposed_text"], row["proposed_file_hash"], row["diff"], row["content_hash"], _j(row.get("notes", [])), "pending_review", iso(utcnow())),
            )
        return pid, False

    def _proposal_row(self, r: dict[str, Any] | None) -> dict[str, Any] | None:
        if r is None:
            return None
        r["changes"] = _lj(r["changes"], [])
        r["citations"] = _lj(r["citations"], [])
        r["notes"] = _lj(r["notes"], [])
        r["is_new_service"] = bool(r["is_new_service"])
        return r

    async def proposal(self, proposal_id: str) -> dict[str, Any] | None:
        return self._proposal_row(await self.fetchone("SELECT * FROM proposals WHERE id=?", (proposal_id,)))

    async def proposals(self, *, principal_id: str | None = None, service_id: str | None = None, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        where, params = [], []
        for col, val in (("principal_id", principal_id), ("service_id", service_id), ("status", status)):
            if val is not None:
                where.append(f"{col}=?")
                params.append(val)
        sql = "SELECT * FROM proposals" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY created_at DESC LIMIT ?"
        return [r for r in (self._proposal_row(x) for x in await self.fetchall(sql, (*params, limit))) if r]

    async def proposal_by_content(self, principal_id: str, content_hash: str) -> dict[str, Any] | None:
        return self._proposal_row(await self.fetchone("SELECT * FROM proposals WHERE principal_id=? AND content_hash=?", (principal_id, content_hash)))

    async def decide_proposal(self, proposal_id: str, status: str, by: str, note: str | None, patch_path: str | None = None) -> bool:
        """Compare-and-set from pending_review to accepted/rejected."""
        async with self.tx() as c:
            cur = await c.execute(
                "UPDATE proposals SET status=?, decided_at=?, decided_by=?, decision_note=?, patch_path=? WHERE id=? AND status='pending_review'",
                (status, iso(utcnow()), by, note, patch_path, proposal_id),
            )
            return cur.rowcount == 1

    async def unreleased_citations(self, principal_id: str, ids: Iterable[str]) -> list[str]:
        """Cited evidence/observation/finding ids that do not exist or were not released to the principal."""
        missing: list[str] = []
        for cid in ids:
            released = None
            for table in ("evidence", "observations", "findings"):
                r = await self.fetchone(f"SELECT released_to FROM {table} WHERE id=?", (cid,))
                if r is not None:
                    released = _lj(r["released_to"], [])
                    break
            if released is None or principal_id not in released:
                missing.append(cid)
        return missing

    async def prune(self, *, collected_days: int, released_days: int, audit_days: int, request_days: int) -> dict[str, int]:
        now = utcnow()
        cutoff_collected = iso(now - timedelta(days=collected_days))
        cutoff_released = iso(now - timedelta(days=released_days))
        cutoff_audit = iso(now - timedelta(days=audit_days))
        cutoff_req = iso(now - timedelta(days=request_days))
        counts = {"evidence": 0, "audit_events": 0, "requests": 0}
        async with self.tx() as c:
            cur = await c.execute(
                "SELECT id, path, released_to FROM evidence WHERE retention_hold=0 AND ((released_to='[]' AND created_at<?) OR (released_to<>'[]' AND created_at<?))",
                (cutoff_collected, cutoff_released),
            )
            rows = await cur.fetchall()
            for row in rows:
                if row[1]:
                    try:
                        (self.evidence_dir / row[1]).unlink(missing_ok=True)
                    except OSError:
                        pass
                await c.execute("DELETE FROM evidence WHERE id=?", (row[0],))
                counts["evidence"] += 1
            cur = await c.execute("DELETE FROM audit_events WHERE collected_at<?", (cutoff_audit,))
            counts["audit_events"] = cur.rowcount
            cur = await c.execute(
                "DELETE FROM requests WHERE created_at<? AND execution_status IN ('succeeded','partial','failed','rejected','expired','cancelled')", (cutoff_req,)
            )
            counts["requests"] = cur.rowcount
        return counts
