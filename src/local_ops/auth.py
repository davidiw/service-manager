"""Principals, grants, reviewer login and effective review-mode resolution."""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from local_ops.config import ServerConfig
from local_ops.models import Capability, ErrorCode, OpsError, ReviewMode, sha256_hex, utcnow
from local_ops.storage import Database, new_id

KEY_PREFIX = "lop"
_password_hasher = PasswordHasher()


@dataclass
class Principal:
    id: str
    name: str
    grants: frozenset[Capability]
    revoked: bool = False
    note: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def has(self, capability: Capability) -> bool:
        return not self.revoked and capability in self.grants

    def require(self, capability: Capability) -> None:
        if self.revoked:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "credential revoked")
        if capability not in self.grants:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"principal {self.name!r} is not granted {capability.value}")


def generate_api_key(name: str) -> tuple[str, str, str]:
    """Return (secret, hash, prefix). 32 random bytes of entropy; hash is a non-reversible SHA-256.

    High-entropy random keys do not need a slow password KDF; the hash only protects the
    stored verifier against disclosure of the database."""
    raw = secrets.token_bytes(32)
    secret = f"{KEY_PREFIX}_{name}_{base64.urlsafe_b64encode(raw).decode().rstrip('=')}"
    return secret, sha256_hex(secret), secret[: len(KEY_PREFIX) + 1 + len(name) + 1 + 6]


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 - malformed hash
        return False


class AuthService:
    def __init__(self, db: Database, config: ServerConfig):
        self.db = db
        self.config = config

    # ------------------------------------------------------------- API keys
    async def create_key(self, name: str, grants: list[Capability], note: str | None = None, rotated_from: str | None = None) -> tuple[Principal, str]:
        if await self.db.principal_by_name(name):
            raise OpsError(ErrorCode.CONFLICT, f"a credential named {name!r} already exists")
        secret, key_hash, prefix = generate_api_key(name)
        pid = new_id("prn")
        await self.db.insert_principal(pid, name, key_hash, prefix, [g.value for g in grants], note=note, rotated_from=rotated_from)
        await self.db.app_audit("local-admin", "admin", "principal.create", detail=f"{name} grants={[g.value for g in grants]}")
        return Principal(pid, name, frozenset(grants), note=note), secret

    async def revoke_key(self, name: str) -> None:
        p = await self.db.principal_by_name(name)
        if not p:
            raise OpsError(ErrorCode.NOT_FOUND, f"no credential named {name!r}")
        await self.db.revoke_principal(p["id"])
        await self.db.app_audit("local-admin", "admin", "principal.revoke", detail=name)

    async def rotate_key(self, name: str) -> tuple[Principal, str]:
        p = await self.db.principal_by_name(name)
        if not p:
            raise OpsError(ErrorCode.NOT_FOUND, f"no credential named {name!r}")
        await self.db.revoke_principal(p["id"])
        await self.db.rename_principal_for_rotation(p["id"], f"{name}.rotated.{p['id'][-6:]}")
        return await self.create_key(name, [Capability(g) for g in p["grants"]], note=p.get("note"), rotated_from=p["id"])

    async def authenticate_key(self, secret: str | None) -> Principal | None:
        if not secret or not secret.startswith(KEY_PREFIX + "_"):
            return None
        row = await self.db.principal_by_hash(sha256_hex(secret))
        if not row:
            return None
        # constant-time compare of the stored hash as defence in depth
        if not hmac.compare_digest(row["key_hash"], sha256_hex(secret)):
            return None
        await self.db.touch_principal(row["id"])
        return self.principal_from_row(row)

    @staticmethod
    def principal_from_row(row: dict[str, Any]) -> Principal:
        return Principal(
            id=row["id"],
            name=row["name"],
            grants=frozenset(Capability(g) for g in row["grants"]),
            revoked=row.get("revoked_at") is not None,
            note=row.get("note"),
            extra={"last_used_at": row.get("last_used_at"), "created_at": row.get("created_at"), "key_prefix": row.get("key_prefix")},
        )

    async def principal(self, pid: str) -> Principal | None:
        row = await self.db.principal(pid)
        return self.principal_from_row(row) if row else None

    async def list_principals(self) -> list[Principal]:
        return [self.principal_from_row(r) for r in await self.db.principals()]

    # ------------------------------------------------------------- reviewers
    async def set_reviewer_password(self, username: str, password: str) -> None:
        if len(password) < 12:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "reviewer password must be at least 12 characters")
        await self.db.upsert_reviewer(new_id("rev"), username, hash_password(password))
        await self.db.app_audit("local-admin", "admin", "reviewer.set_password", detail=username)

    async def login_reviewer(self, username: str, password: str, ttl: timedelta = timedelta(hours=12)) -> dict[str, Any] | None:
        row = await self.db.reviewer_by_username(username)
        if not row:
            # burn time comparably to a real verify
            verify_password(hash_password("x" * 16), password)
            return None
        if not verify_password(row["password_hash"], password):
            return None
        session = await self.db.create_session(row["id"], ttl)
        session["username"] = username
        await self.db.app_audit(username, "reviewer", "reviewer.login")
        return session

    async def session(self, sid: str | None) -> dict[str, Any] | None:
        if not sid:
            return None
        return await self.db.session(sid)

    async def logout(self, sid: str) -> None:
        await self.db.revoke_session(sid)

    # ------------------------------------------------------------- review modes
    async def effective_mode(self, principal_id: str, capability: Capability) -> tuple[ReviewMode, str, datetime | None]:
        """Returns (mode, source, expiry). Overrides (developer-controlled, time-bound) beat settings beat defaults.
        `review_responses` is only valid for read-only capabilities; execution falls back to review_both."""
        now = utcnow()
        for o in await self.db.active_overrides():
            if (o["principal_id"] in (None, principal_id)) and (o["capability"] in (None, capability.value)):
                mode = ReviewMode(o["mode"])
                exp = datetime.fromisoformat(o["expires_at"].replace("Z", "+00:00"))
                if exp > now:
                    return self._valid_for(mode, capability), f"override:{o['id']}", exp
        setting = await self.db.review_setting(principal_id, capability.value)
        if setting:
            return self._valid_for(ReviewMode(setting), capability), "setting", None
        return self._valid_for(self.config.review.default_mode, capability), "default", None

    @staticmethod
    def _valid_for(mode: ReviewMode, capability: Capability) -> ReviewMode:
        if capability == Capability.EXECUTION and mode == ReviewMode.REVIEW_RESPONSES:
            return ReviewMode.REVIEW_BOTH
        return mode

    async def set_mode(self, principal_id: str, capability: Capability, mode: ReviewMode, by: str) -> None:
        if capability == Capability.EXECUTION and mode == ReviewMode.REVIEW_RESPONSES:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "review_responses is only supported for read-only capabilities")
        await self.db.set_review_setting(principal_id, capability.value, mode.value, by)
        await self.db.app_audit(by, "reviewer", "review_mode.set", detail=f"{principal_id}/{capability.value} -> {mode.value}")

    async def add_yolo_override(self, principal_id: str | None, capability: Capability | None, minutes: int, by: str) -> str:
        minutes = max(1, min(minutes, self.config.review.yolo_override_max_minutes))
        oid = await self.db.add_override(principal_id, capability.value if capability else None, ReviewMode.YOLO.value, utcnow() + timedelta(minutes=minutes), by)
        await self.db.app_audit(by, "reviewer", "review_override.add", detail=f"{oid} yolo {principal_id or '*'}/{capability.value if capability else '*'} {minutes}m")
        return oid

    async def revoke_override(self, oid: str, by: str) -> None:
        await self.db.revoke_override(oid)
        await self.db.app_audit(by, "reviewer", "review_override.revoke", detail=oid)

    # ------------------------------------------------------------- stop switch
    async def mutations_stopped(self) -> bool:
        return bool(await self.db.get_setting("mutations_stopped", False))

    async def set_mutations_stopped(self, stopped: bool, by: str) -> None:
        await self.db.set_setting("mutations_stopped", stopped, by)
        await self.db.app_audit(by, "reviewer", "stop_switch.set", detail=str(stopped))
