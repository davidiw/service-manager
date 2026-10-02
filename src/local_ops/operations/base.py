from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from local_ops.models import (
    Capability,
    Coverage,
    DataClass,
    Effect,
    ErrorCode,
    ExecutionStatus,
    OpsError,
    utcnow,
)
from local_ops.storage import Database, new_id

if TYPE_CHECKING:
    from local_ops.auth import Principal
    from local_ops.catalog import Catalog
    from local_ops.config import ServerConfig
    from local_ops.providers.base import ProviderRegistry
    from local_ops.release import Sanitizer

IMPLEMENTATION_VERSION = "1"


@dataclass
class Budget:
    deadline: datetime
    max_bytes: int
    max_events: int = 10_000
    max_pages: int = 100

    def remaining_seconds(self) -> float:
        return max(0.0, (self.deadline - utcnow()).total_seconds())

    def check(self) -> None:
        if self.remaining_seconds() <= 0:
            raise OpsError(ErrorCode.LIMIT_REACHED, "operation time budget exhausted")


@dataclass
class OperationContext:
    db: Database
    config: ServerConfig
    catalog: Catalog
    providers: ProviderRegistry
    sanitizer: Sanitizer
    principal: Principal
    request: dict[str, Any]
    budget: Budget
    evidence_ids: list[str] = field(default_factory=list)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    notes: list[str] = field(default_factory=list)

    @property
    def request_id(self) -> str:
        return self.request["id"]

    def scrub(self, value: Any) -> Any:
        """Mandatory credential sanitization for anything persisted outside the evidence store."""
        scrubbed, _ = self.sanitizer.scrub(value)
        return scrubbed

    async def store_evidence(self, source: str, kind: str, payload: Any, summary: str | None = None, provenance: dict[str, Any] | None = None) -> str:
        """Scrub and persist a private evidence fragment; returns its opaque id."""
        scrubbed, removed = self.sanitizer.scrub(payload)
        raw = json.dumps(scrubbed, sort_keys=True, default=str).encode("utf-8")
        if len(raw) > self.budget.max_bytes:
            raw = raw[: self.budget.max_bytes] + b"\n...[evidence truncated at ingestion]"
            removed["truncated_bytes"] = 1
        eid = new_id("evd")
        await self.db.insert_evidence(eid, self.request_id, source, kind, raw, summary, {"removed": removed}, provenance)
        self.evidence_ids.append(eid)
        return eid

    async def record_intent(self, phase: str, target_key: str | None, description: str, provider_op: dict[str, Any]) -> str:
        await self.db.update_request(self.request_id, phase=phase)
        return await self.db.record_intent(self.request_id, phase, target_key, description, provider_op)

    async def set_phase(self, phase: str) -> None:
        await self.db.update_request(self.request_id, phase=phase)

    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise asyncio.CancelledError("cancellation requested")


@dataclass
class OperationOutcome:
    execution_status: ExecutionStatus
    result: dict[str, Any]
    coverage: Coverage | None = None
    public_error: dict[str, Any] | None = None
    private_error: str | None = None
    plan: dict[str, Any] | None = None  # action_prepare stores a plan
    receipt: dict[str, Any] | None = None


Handler = Callable[[OperationContext, Any], Awaitable[OperationOutcome]]
Describer = Callable[[Any, "Catalog", "ServerConfig"], dict[str, Any]]
TargetKeys = Callable[[Any, "Catalog", "ServerConfig"], list[str]]
# pre_submit(args, principal, db, catalog) -> {"target_keys": [...], "plan_id": ...}; may raise OpsError
PreSubmit = Callable[[Any, "Principal", Database, "Catalog"], Awaitable[dict[str, Any]]]


@dataclass
class OperationSpec:
    name: str
    data_class: DataClass
    effect: Effect
    args_model: type[BaseModel]
    handler: Handler
    describe: Describer
    summary: str
    version: str = IMPLEMENTATION_VERSION
    target_keys: TargetKeys | None = None
    pre_submit: PreSubmit | None = None
    budget_seconds: int | None = None
    requires_idempotency_key: bool = False

    @property
    def is_mutation(self) -> bool:
        return self.effect == Effect.MUTATION

    @property
    def capability(self) -> Capability:
        return self.data_class.capability


class OperationRegistry:
    def __init__(self) -> None:
        self._ops: dict[str, OperationSpec] = {}

    def register(self, spec: OperationSpec) -> None:
        if spec.name in self._ops:
            raise ValueError(f"operation {spec.name} already registered")
        self._ops[spec.name] = spec

    def get(self, name: str) -> OperationSpec:
        spec = self._ops.get(name)
        if spec is None:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"unknown operation {name!r}")
        return spec

    def for_capability(self, capability: Capability) -> list[OperationSpec]:
        return [s for s in self._ops.values() if s.capability == capability]

    def all(self) -> list[OperationSpec]:
        return list(self._ops.values())
