"""Shared public contracts.

Everything in this module may be serialized to an MCP client or rendered in
the review site. Nothing here may carry a secret value.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashing and idempotency comparison."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class StrictModel(BaseModel):
    """Rejects unknown fields; used at trust boundaries."""

    model_config = ConfigDict(extra="forbid")


class Capability(StrEnum):
    """What a credential may do (D28): read anything the server can read, or write (reviewed mutations)."""

    READ = "read"
    WRITE = "write"


class DataClass(StrEnum):
    """What an operation returns or changes; review policy is set per client and data class (D28).

    inventory: provider metadata (resource names, tags, configuration, access assignments).
    content: data the provider holds (log lines, audit events with users and IPs, container output).
    mutation: changes to a provider."""

    INVENTORY = "inventory"
    CONTENT = "content"
    MUTATION = "mutation"

    @property
    def capability(self) -> Capability:
        return Capability.WRITE if self is DataClass.MUTATION else Capability.READ

    @classmethod
    def for_capability(cls, capability: Capability) -> list[DataClass]:
        return [d for d in cls if d.capability == capability]


class ReviewMode(StrEnum):
    REVIEW_BOTH = "review_both"
    REVIEW_REQUESTS = "review_requests"
    REVIEW_RESPONSES = "review_responses"
    YOLO = "yolo"

    @property
    def reviews_request(self) -> bool:
        return self in (ReviewMode.REVIEW_BOTH, ReviewMode.REVIEW_REQUESTS)

    @property
    def reviews_response(self) -> bool:
        return self in (ReviewMode.REVIEW_BOTH, ReviewMode.REVIEW_RESPONSES)


class ExecutionStatus(StrEnum):
    PENDING_REQUEST_REVIEW = "pending_request_review"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in (
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.FAILED,
            ExecutionStatus.OUTCOME_UNKNOWN,
            ExecutionStatus.REJECTED,
            ExecutionStatus.EXPIRED,
            ExecutionStatus.CANCELLED,
        )


class ResponseStatus(StrEnum):
    UNAVAILABLE = "unavailable"
    PENDING_RESPONSE_REVIEW = "pending_response_review"
    RELEASED = "released"
    WITHHELD = "withheld"


class Effect(StrEnum):
    """Classification of a provider operation by its effect on the inspected system."""

    READ = "read"
    READ_WITH_BOOKKEEPING = "read_with_bookkeeping"  # e.g. creates a provider-side query job
    MUTATION = "mutation"


class ErrorCode(StrEnum):
    AUTHORIZATION_DENIED = "authorization_denied"
    AUTH_REQUIRED = "auth_required"
    SCOPE_UNRESOLVED = "scope_unresolved"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    UNSUPPORTED_DEPLOYMENT_MECHANISM = "unsupported_deployment_mechanism"
    REVIEW_REQUIRED = "review_required"
    PLAN_STALE = "plan_stale"
    LIMIT_REACHED = "limit_reached"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    INVALID_ARGUMENT = "invalid_argument"
    STOPPED = "stopped"


class OpsError(Exception):
    """Typed error returned to callers. `private_detail` is only shown to the reviewer."""

    def __init__(self, code: ErrorCode, message: str, *, private_detail: str | None = None, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.private_detail = private_detail
        self.data = data or {}

    def public(self) -> dict[str, Any]:
        return {"error": self.code.value, "message": self.message, **({"data": self.data} if self.data else {})}


class Confidence(StrEnum):
    VERIFIED = "verified"
    OBSERVED = "observed"
    CLAIMED = "claimed"
    INFERRED = "inferred"
    CONTRADICTORY = "contradictory"
    UNKNOWN = "unknown"


class TimeRange(StrictModel):
    start: datetime
    end: datetime


class Limits(StrictModel):
    max_events: int = Field(default=500, ge=1, le=10000)
    max_pages: int = Field(default=20, ge=1, le=500)
    max_duration_seconds: int = Field(default=120, ge=1, le=3600)
    max_bytes: int = Field(default=2_000_000, ge=1024, le=50_000_000)


class UnavailableScope(StrictModel):
    source: str
    reason: str
    detail: str | None = None


class Coverage(BaseModel):
    """Structured collection coverage returned with every query/investigation."""

    model_config = ConfigDict(extra="forbid")

    requested_sources: list[str] = Field(default_factory=list)
    completed_scopes: list[str] = Field(default_factory=list)
    unavailable_scopes: list[UnavailableScope] = Field(default_factory=list)
    event_categories: list[str] = Field(default_factory=list)
    time_range_requested: dict[str, str | None] | None = None
    time_range_observed: dict[str, str | None] = Field(default_factory=lambda: dict.fromkeys(("first_event", "last_event")))
    source_retention_known: bool = False
    source_retention_note: str | None = None
    pagination_complete: bool = True
    truncated: bool = False
    collection_gaps: list[str] = Field(default_factory=list)
    accounts_expected: list[str] = Field(default_factory=list)
    accounts_reached: list[str] = Field(default_factory=list)
    regions_requested: list[str] = Field(default_factory=list)
    regions_completed: list[str] = Field(default_factory=list)
    clusters_covered: list[str] = Field(default_factory=list)
    permission_failures: list[str] = Field(default_factory=list)
    disabled_logging: list[str] = Field(default_factory=list)
    collection_lag_seconds: int | None = None
    filters_provider_side: list[str] = Field(default_factory=list)
    filters_local: list[str] = Field(default_factory=list)
    conclusion_scope: str = "No conclusion is implied about sources or scopes that were not completed."


class EvidenceRef(StrictModel):
    """Opaque reference to a stored evidence fragment."""

    evidence_id: str
    source: str
    kind: str
    summary: str | None = None


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_key: str  # provider-scoped unique identity used for dedup
    provider: str
    source_id: str
    account: str | None = None
    region: str | None = None
    event_id: str | None = None
    occurred_at: datetime
    collected_at: datetime
    actor: str | None = None
    actor_type: str | None = None
    session: str | None = None
    action: str
    resource: str | None = None
    resource_type: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    outcome: str | None = None
    category: str = "management"
    evidence_ref: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    rule_version: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    title: str
    observed_facts: list[str]
    evidence_ids: list[str] = Field(default_factory=list)
    event_keys: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    benign_explanations: list[str] = Field(default_factory=list)
    next_queries: list[str] = Field(default_factory=list)
    possible_remediation: list[str] = Field(default_factory=list)
    provider_severity: str | None = None
    identity_join: Literal["exact", "uncertain", "none"] | None = None


class Hypothesis(StrictModel):
    statement: str
    support: Literal["weak", "moderate", "strong"]
    supporting_observations: list[str] = Field(default_factory=list)
    contradicting_observations: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class SuggestedQuery(StrictModel):
    description: str
    tool: str
    arguments: dict[str, Any]


class PossibleAction(StrictModel):
    action: str
    service_id: str | None = None
    binding_id: str | None = None
    rationale: str
    inappropriate_when: list[str] = Field(default_factory=list)
    executable: bool = False


class HealthCheckResult(StrictModel):
    check_id: str
    kind: str
    passed: bool | None  # None = could not run
    detail: str
    observed: dict[str, Any] = Field(default_factory=dict)


class ArtifactRef(StrictModel):
    reference: str  # repo:tag or repo@sha256:...
    repository: str | None = None
    tag: str | None = None
    digest: str | None = None
    digest_kind: Literal["index", "manifest", "unknown"] | None = None
    running_image_id: str | None = None
    version_label: str | None = None


class ActionPlan(BaseModel):
    """Immutable, exact mutation plan produced by action_prepare."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str
    plan_hash: str
    service_id: str
    binding_id: str
    action: Literal["restart", "update", "rollback", "redeploy"]
    environment: str
    executor: str
    mechanism: str
    target: dict[str, Any]
    target_fingerprint: str
    current_artifact: ArtifactRef | None = None
    requested_artifact: ArtifactRef | None = None
    provider_mutations: list[dict[str, Any]]
    pre_reads: list[str] = Field(default_factory=list)
    post_reads: list[str] = Field(default_factory=list)
    health_checks: list[str] = Field(default_factory=list)
    unavailable_health_checks: list[str] = Field(default_factory=list)
    timeout_seconds: int
    expected_disruption: str
    rollback: dict[str, Any] | None = None
    dependencies: list[str] = Field(default_factory=list)
    dependents: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    locks: list[str] = Field(default_factory=list)
    catalog_revision: str
    implementation_version: str
    prepared_by: str
    prepared_at: datetime
    expires_at: datetime
    hooks_or_auxiliary_work: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str
    request_id: str
    plan_id: str
    initiating_principal: str
    review_mode: str
    service_id: str
    binding_id: str
    action: str
    target: dict[str, Any]
    before_state: dict[str, Any]
    after_state: dict[str, Any]
    before_artifact: ArtifactRef | None = None
    after_artifact: ArtifactRef | None = None
    provider_operation_ids: list[str] = Field(default_factory=list)
    started_at: datetime
    dispatched_at: datetime | None = None
    finished_at: datetime | None = None
    ran: Literal["not_started", "preparation_failed", "ran", "partial", "uncertain"]
    outcome: str
    health_checks: list[HealthCheckResult] = Field(default_factory=list)
    rollback_result: dict[str, Any] | None = None
    notes: list[str] = Field(default_factory=list)


class SubmissionResult(StrictModel):
    request_id: str
    operation: str
    execution_status: ExecutionStatus
    response_status: ResponseStatus
    review_url: str
    poll_after_ms: int = 1000
    existing: bool = False


class RequestStatusResult(StrictModel):
    request_id: str
    operation: str
    capability: Capability
    execution_status: ExecutionStatus
    response_status: ResponseStatus
    review_url: str
    submitted_at: datetime
    updated_at: datetime
    revision: int
    poll_after_ms: int = 1000
    public_error: dict[str, Any] | None = None


class Page(StrictModel):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)


class ScanDenominators(StrictModel):
    accounts_expected: int = 0
    accounts_reached: int = 0
    regions_requested: int = 0
    regions_completed: int = 0
    clusters_requested: int = 0
    clusters_reached: int = 0
    workloads_observed: int = 0
    workloads_mapped: int = 0
    workloads_unresolved: int = 0
    sources_available: int = 0
    sources_missing: int = 0
