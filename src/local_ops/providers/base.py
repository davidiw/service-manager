"""Provider adapter protocol.

Each adapter declares what it supports, what it needs, and its limitations. An unconfigured or
unreachable integration reports an explicit unavailable capability; it never returns fixture data as
if it were live.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, Field

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, StrictModel, UnavailableScope
from local_ops.release import Sanitizer

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext


class SupportedOperation(StrictModel):
    name: str
    effect: Effect
    description: str
    provider_side_filters: list[str] = Field(default_factory=list)
    local_filters: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AdapterDescription(StrictModel):
    provider_id: str
    kind: str
    description: str | None = None
    operations: list[SupportedOperation]
    required_credentials: list[str]
    credential_configured: bool
    scope_constraints: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    live_verified: bool = False
    families: list[str] = Field(default_factory=list)


class Availability(StrictModel):
    available: bool
    reason: str | None = None
    detail: str | None = None
    identity: dict[str, Any] | None = None  # verified identity (e.g. STS account), never secrets
    checked_live: bool = False


class DiscoveryScope(StrictModel):
    regions: list[str] = Field(default_factory=list)
    namespaces: list[str] = Field(default_factory=list)
    families: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)
    repositories: list[str] = Field(default_factory=list)
    vaults: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """A single observed resource. `resource_key` must be stable across scans for the same resource."""

    provider_id: str
    resource_key: str
    resource_type: str
    identity: dict[str, Any]
    attributes: dict[str, Any] = Field(default_factory=dict)
    scope_key: str | None = None
    evidence_id: str | None = None
    relationships: list[dict[str, str]] = Field(default_factory=list)  # {"kind": "owner|depends_on|serves|dns", "target": resource_key}


class DiscoveryReport(BaseModel):
    provider_id: str
    observations: list[Observation] = Field(default_factory=list)
    completed_scopes: list[str] = Field(default_factory=list)  # scope keys fully enumerated (comparable scans)
    partial_scopes: list[str] = Field(default_factory=list)
    unavailable: list[dict[str, Any]] = Field(default_factory=list)
    identity: dict[str, Any] | None = None
    notes: list[str] = Field(default_factory=list)
    truncated: bool = False
    expiries: list[dict[str, Any]] = Field(default_factory=list)


class EvidenceResult(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)  # normalized audit events (dicts of NormalizedEvent)
    coverage: Coverage
    cursor: str | None = None
    raw_evidence_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    query_description: dict[str, Any] = Field(default_factory=dict)


class ProviderAdapter(Protocol):
    provider_id: str
    kind: str
    config: ProviderConfig

    def describe(self) -> AdapterDescription: ...

    async def check_availability(self, *, live: bool = False) -> Availability: ...

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport: ...

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult: ...


@dataclass
class ProviderRegistry:
    adapters: dict[str, ProviderAdapter] = field(default_factory=dict)
    per_provider_semaphores: dict[str, asyncio.Semaphore] = field(default_factory=dict)
    concurrency_per_provider: int = 2

    def register(self, adapter: ProviderAdapter) -> None:
        self.adapters[adapter.provider_id] = adapter
        self.per_provider_semaphores[adapter.provider_id] = asyncio.Semaphore(self.concurrency_per_provider)

    def get(self, provider_id: str) -> ProviderAdapter | None:
        return self.adapters.get(provider_id)

    def by_kind(self, kind: str) -> list[ProviderAdapter]:
        return [a for a in self.adapters.values() if a.kind == kind]

    def semaphore(self, provider_id: str) -> asyncio.Semaphore:
        return self.per_provider_semaphores.setdefault(provider_id, asyncio.Semaphore(self.concurrency_per_provider))

    def describe_all(self) -> list[AdapterDescription]:
        return [a.describe() for a in self.adapters.values()]


class UnavailableAdapter:
    """Placeholder registered when a configured provider cannot be constructed (missing dependency, bad config)."""

    def __init__(self, config: ProviderConfig, reason: str):
        self.config = config
        self.provider_id = config.id
        self.kind = config.kind
        # `reason` is normally an exception message (`build_providers` in app.py) reaching
        # `capabilities_get` unreviewed; it is scrubbed here too, defense-in-depth, so a caller that
        # constructs this directly (tests, a future call site) cannot skip the floor.
        self.reason, _ = Sanitizer().scrub_text(reason)

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=[], required_credentials=[c for c in [self.config.credential] if c], credential_configured=False, limitations=[self.reason])

    async def check_availability(self, *, live: bool = False) -> Availability:
        return Availability(available=False, reason="adapter_unavailable", detail=self.reason)

    async def discover(self, ctx: Any, scope: DiscoveryScope, budget: Any) -> DiscoveryReport:
        return DiscoveryReport(provider_id=self.provider_id, unavailable=[{"source": self.provider_id, "reason": "adapter_unavailable", "detail": self.reason}])

    async def query(self, ctx: Any, query: dict[str, Any], budget: Any) -> EvidenceResult:
        return EvidenceResult(coverage=Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=self.provider_id, reason="adapter_unavailable", detail=self.reason)], conclusion_scope="Source unavailable; no conclusion."))


AdapterFactory = Callable[[ProviderConfig, ServerConfig, Any], Awaitable[ProviderAdapter] | ProviderAdapter]
