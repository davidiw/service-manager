"""Executor contract: prepare an exact immutable plan, verify the target before dispatch, dispatch with
recorded intent, verify health, and produce a receipt. Reconciliation classifies interrupted work."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Protocol

from local_ops.catalog import Binding, OperationConfig, ServiceSpec
from local_ops.models import (
    ActionPlan,
    ArtifactRef,
    ErrorCode,
    ExecutionStatus,
    HealthCheckResult,
    OpsError,
    Receipt,
    canonical_json,
    iso,
    sha256_hex,
    utcnow,
)
from local_ops.operations.base import IMPLEMENTATION_VERSION, OperationContext, OperationOutcome
from local_ops.providers.kubernetes import KubernetesAdapter
from local_ops.storage import new_id

if TYPE_CHECKING:
    from local_ops.pagerduty_contracts import PagerDutyConfiguration


DISPATCHED_PHASES = ("dispatching", "dispatched", "verifying")


def dispatched_intents(intents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Intents recorded at/after dispatch that may have reached the provider. D6: a mutation with one of
    these is reconciled, never finalized as cancelled/failed without inspecting the target; a mutation
    with none is safe to requeue since nothing was ever sent."""
    return [i for i in intents if i["phase"] in DISPATCHED_PHASES]


class Executor(Protocol):
    name: str

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None, *, desired_configuration: PagerDutyConfiguration | None = None) -> ActionPlan: ...

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt: ...

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]: ...


def plan_hash(plan_fields: dict[str, Any]) -> str:
    """Hash of the plan excluding its own id/hash/timestamps; secret-free by construction."""
    body = {k: v for k, v in plan_fields.items() if k not in ("plan_id", "plan_hash", "prepared_at", "expires_at")}
    return sha256_hex(canonical_json(body))


def target_fingerprint(workload: dict[str, Any]) -> str:
    """Fingerprint of the mutable, relevant parts of a workload: uid, container images, template
    annotations, ownership markers and replica count. Status timestamps are excluded on purpose."""
    md = workload.get("metadata", {})
    tmpl = workload.get("spec", {}).get("template", {})
    material = {
        "uid": md.get("uid"),
        "images": sorted((c.get("name", ""), c.get("image", "")) for c in tmpl.get("spec", {}).get("containers", [])),
        "template_annotations": tmpl.get("metadata", {}).get("annotations") or {},
        "managed_by": (md.get("labels") or {}).get("app.kubernetes.io/managed-by"),
        "helm_release": (md.get("annotations") or {}).get("meta.helm.sh/release-name"),
        "replicas": workload.get("spec", {}).get("replicas"),
    }
    return hashlib.sha256(canonical_json(material).encode()).hexdigest()


def kube_adapter_for(ctx: OperationContext, binding: Binding) -> KubernetesAdapter:
    adapter = ctx.providers.get(binding.provider_id)
    if adapter is None or getattr(adapter, "kind", None) != "kubernetes":
        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} references provider {binding.provider_id!r} which is not a configured kubernetes provider")
    return adapter  # type: ignore[return-value]


async def verify_cluster_identity(adapter: KubernetesAdapter, binding: Binding, *, execution: bool = False) -> dict[str, Any]:
    """`execution=True` verifies the connection a mutation will use (the execution credential when configured)."""
    ident = await adapter.verified_identity(execution=execution)
    if not ident.get("approved"):
        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"provider {adapter.provider_id} has no approved cluster identity recorded; refusing to mutate an unverified cluster")
    if binding.cluster_identity and binding.cluster_identity not in (adapter.cluster_identity_string(), adapter.provider_id):
        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} cluster_identity {binding.cluster_identity!r} does not match provider {adapter.provider_id}", private_detail=f"adapter identity {adapter.cluster_identity_string()}")
    return ident


def new_plan(ctx: OperationContext, **fields: Any) -> ActionPlan:
    now = utcnow()
    fields.setdefault("catalog_revision", ctx.catalog.revision)
    fields.setdefault("implementation_version", IMPLEMENTATION_VERSION)
    fields.setdefault("prepared_by", ctx.principal.id)
    pid = new_id("plan")
    fields["plan_id"] = pid
    fields["prepared_at"] = now
    fields["expires_at"] = now + timedelta(minutes=ctx.config.review.plan_ttl_minutes)
    fields["plan_hash"] = plan_hash(json.loads(ActionPlan.model_validate({**fields, "plan_hash": "x"}).model_dump_json()))
    return ActionPlan.model_validate(fields)


def receipt_from(plan: ActionPlan, ctx: OperationContext, *, before: dict[str, Any], after: dict[str, Any], before_artifact: ArtifactRef | None, after_artifact: ArtifactRef | None, provider_ids: list[str], started_at: Any, dispatched_at: Any, ran: str, outcome: str, checks: list[HealthCheckResult], rollback_result: dict[str, Any] | None = None, notes: list[str] | None = None) -> Receipt:
    return Receipt(
        receipt_id=new_id("rcpt"), request_id=ctx.request_id, plan_id=plan.plan_id, initiating_principal=ctx.principal.id, review_mode=ctx.request.get("review_mode", "unknown"),
        service_id=plan.service_id, binding_id=plan.binding_id, action=plan.action, target=plan.target, before_state=before, after_state=after, before_artifact=before_artifact, after_artifact=after_artifact,
        provider_operation_ids=provider_ids, started_at=started_at, dispatched_at=dispatched_at, finished_at=utcnow(), ran=ran, outcome=outcome, health_checks=checks, rollback_result=rollback_result, notes=notes or [],  # type: ignore[arg-type]
    )


def outcome_from_receipt(receipt: Receipt, plan: ActionPlan) -> OperationOutcome:
    checks_failed = [c for c in receipt.health_checks if c.passed is False]
    checks_unknown = [c for c in receipt.health_checks if c.passed is None]
    if receipt.ran == "uncertain":
        status = ExecutionStatus.OUTCOME_UNKNOWN
    elif receipt.ran in ("preparation_failed", "not_started"):
        status = ExecutionStatus.FAILED
    elif checks_failed:
        status = ExecutionStatus.FAILED if receipt.ran == "ran" else ExecutionStatus.PARTIAL
    elif checks_unknown:
        status = ExecutionStatus.PARTIAL
    elif receipt.ran == "partial":
        status = ExecutionStatus.PARTIAL
    else:
        status = ExecutionStatus.SUCCEEDED
    result = {"receipt": receipt.model_dump(mode="json"), "plan_id": plan.plan_id, "verified_health": status == ExecutionStatus.SUCCEEDED and bool(receipt.health_checks), "summary": receipt.outcome}
    public_error = None
    if status == ExecutionStatus.OUTCOME_UNKNOWN:
        public_error = {"error": "outcome_unknown", "message": "mutation dispatched but outcome could not be confirmed; reconcile before any retry"}
    elif status == ExecutionStatus.FAILED:
        public_error = {"error": "provider_unavailable" if receipt.ran != "ran" else "limit_reached", "message": receipt.outcome}
    return OperationOutcome(status, result, public_error=public_error, receipt=receipt.model_dump(mode="json"))


async def reconcile_request(ctx: OperationContext, req: dict[str, Any], intents: list[dict[str, Any]]) -> OperationOutcome:
    """Used by the worker on startup for mutations found mid-flight. Never re-dispatches."""
    from local_ops.executors import registry as executor_registry

    plan_id = req.get("plan_id")
    plan_row = await ctx.db.plan(plan_id) if plan_id else None
    if not plan_row:
        return OperationOutcome(ExecutionStatus.OUTCOME_UNKNOWN, {"reconciliation": {"status": "uncertain", "reason": "no plan recorded for interrupted mutation"}}, public_error={"error": "outcome_unknown", "message": "no plan recorded; explicit handling required"})
    plan = ActionPlan.model_validate(plan_row["body"])
    executor = executor_registry.get(plan.executor)
    status, detail = await executor.reconcile(ctx, plan, intents)
    public_error = None
    if status == ExecutionStatus.OUTCOME_UNKNOWN:
        public_error = {"error": "outcome_unknown", "message": "state could not be safely determined after restart; explicit handling required"}
    elif status == ExecutionStatus.FAILED:
        public_error = {"error": "provider_unavailable", "message": "mutation was interrupted and is not applied"}
    receipt = receipt_from(plan, ctx, before={}, after=detail.get("observed", {}), before_artifact=plan.current_artifact, after_artifact=detail.get("after_artifact"), provider_ids=[i["id"] for i in intents], started_at=req.get("started_at") or utcnow(), dispatched_at=next((i["recorded_at"] for i in intents if i["phase"] == "dispatching"), None), ran={"succeeded": "ran", "partial": "partial", "failed": "not_started", "outcome_unknown": "uncertain", "running": "partial"}.get(status.value, "uncertain"), outcome=detail.get("summary", status.value), checks=[HealthCheckResult.model_validate(c) for c in detail.get("checks", [])], notes=["reconciled after an interrupted dispatch (process restart or a worker exception after the provider call); no mutation was re-sent"])
    await ctx.db.insert_receipt(receipt.receipt_id, ctx.request_id, plan.plan_id, receipt.model_dump(mode="json"))
    return OperationOutcome(status, {"reconciliation": {"status": status.value, **detail}, "receipt": receipt.model_dump(mode="json")}, public_error=public_error, receipt=receipt.model_dump(mode="json"))


def artifact_from_image(image: str | None, running_image_id: str | None = None) -> ArtifactRef | None:
    if not image:
        return None
    from local_ops.providers.kubernetes import parse_image_ref

    p = parse_image_ref(image)
    return ArtifactRef(reference=image, repository=p["repository"], tag=p["tag"], digest=p["digest"], digest_kind="unknown" if p["digest"] else None, running_image_id=running_image_id)


def intent_record(plan: ActionPlan, mutation: dict[str, Any]) -> dict[str, Any]:
    return {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "mutation": mutation, "recorded_at": iso(utcnow())}
