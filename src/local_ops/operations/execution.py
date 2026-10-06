"""Execution operations: action_prepare (read-only exact plan) and action_submit (mutation)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from local_ops.auth import Principal
from local_ops.aws_change_contracts import (
    EksAccessEntryRemoveConfiguration,
    IamCredentialStateConfiguration,
    IamUserRemoveConfiguration,
    IdentityCenterAssignmentRemoveConfiguration,
    Route53RecordConfiguration,
    aws_configuration_matches_target,
)
from local_ops.catalog import Catalog
from local_ops.config import ServerConfig
from local_ops.executors import registry as executors
from local_ops.executors.base import outcome_from_receipt
from local_ops.models import (
    ActionPlan,
    DataClass,
    Effect,
    ErrorCode,
    ExecutionStatus,
    OpsError,
    StrictModel,
    iso,
    utcnow,
)
from local_ops.operations.base import OperationContext, OperationOutcome, OperationRegistry, OperationSpec
from local_ops.pagerduty_contracts import (
    EscalationPolicyConfiguration,
    IncidentReassignmentConfiguration,
    ScheduleConfiguration,
    ScheduleDeleteConfiguration,
    ServiceRoutingConfiguration,
    configuration_matches_target,
)
from local_ops.storage import Database

# One discriminated union over every typed configuration a configure action may carry (PagerDuty D32, AWS D35).
DesiredConfiguration = Annotated[
    ScheduleConfiguration | EscalationPolicyConfiguration | ServiceRoutingConfiguration | ScheduleDeleteConfiguration | IncidentReassignmentConfiguration
    | Route53RecordConfiguration | IamCredentialStateConfiguration | IamUserRemoveConfiguration | IdentityCenterAssignmentRemoveConfiguration | EksAccessEntryRemoveConfiguration,
    Field(discriminator="kind"),
]
AWS_CONFIGURATIONS = (Route53RecordConfiguration, IamCredentialStateConfiguration, IamUserRemoveConfiguration, IdentityCenterAssignmentRemoveConfiguration, EksAccessEntryRemoveConfiguration)


class ActionPrepareArgs(StrictModel):
    service_id: str
    binding_id: str
    action: Literal["restart", "update", "rollback", "redeploy", "configure"]
    desired_artifact: str | None = Field(default=None, description="repo:tag or repo@sha256:... for update; helm revision for helm rollback")
    desired_configuration: DesiredConfiguration | None = None
    reason: str | None = None

    @field_validator("desired_artifact")
    @classmethod
    def _artifact(cls, v: str | None) -> str | None:
        return _validate_artifact(v)

    @model_validator(mode="after")
    def _configuration_for_configure(self) -> ActionPrepareArgs:
        if self.action == "configure":
            if self.desired_artifact is not None:
                raise ValueError("desired_artifact is forbidden for configure")
            if self.desired_configuration is None:
                raise ValueError("desired_configuration is required for configure")
        elif self.desired_configuration is not None:
            raise ValueError("desired_configuration is only allowed for configure")
        return self


ARTIFACT_RE = re.compile(r"^[a-z0-9][a-z0-9._\-/:]*[a-z0-9](?::[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})?(?:@sha256:[0-9a-f]{64})?$|^[0-9]{1,6}$")


def _validate_artifact(v: str | None) -> str | None:
    if v is None:
        return v
    if len(v) > 512 or not ARTIFACT_RE.fullmatch(v) or any(ch in v for ch in ",=\\ {}[]\n"):
        raise ValueError("desired_artifact must be repository[:tag][@sha256:<64 hex>] (or a helm revision number)")
    return v


class ActionSubmitArgs(StrictModel):
    plan_id: str
    plan_hash: str
    reason: str | None = None


def _resolve(catalog: Catalog, args: ActionPrepareArgs) -> tuple[Any, Any, Any]:
    doc = catalog.service(args.service_id)
    if doc is None:
        raise OpsError(ErrorCode.NOT_FOUND, f"service {args.service_id!r} not in catalog")
    binding = doc.spec.binding(args.binding_id)
    if binding is None:
        raise OpsError(ErrorCode.NOT_FOUND, f"binding {args.binding_id!r} not found on {args.service_id}")
    op_name = "update" if args.action == "redeploy" and "redeploy" not in doc.spec.operations else args.action
    op = doc.spec.operations.get(op_name)
    if op is None:
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"service {args.service_id} does not declare a {args.action} operation")
    if op.binding_id != binding.id:
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"{args.action} is declared for binding {op.binding_id!r}, not {binding.id!r}")
    if args.action == "configure":
        if op.kind != "configure":
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "configure requires a configure-kind operation")
        if op.executor == "aws_change":
            aws_target = binding.aws_target
            if aws_target is None:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} has no AWS target")
            if args.desired_configuration is None or not isinstance(args.desired_configuration, AWS_CONFIGURATIONS) or not aws_configuration_matches_target(args.desired_configuration, aws_target):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "desired_configuration does not match the AWS target")
            if op.health_checks != ["aws_configuration_matches"]:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "aws_change configure requires exactly aws_configuration_matches health check")
        elif op.executor == "pagerduty_configuration":
            target = binding.pagerduty_target
            if target is None:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} has no PagerDuty target")
            if args.desired_configuration is None or isinstance(args.desired_configuration, AWS_CONFIGURATIONS) or not configuration_matches_target(args.desired_configuration, target):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "desired_configuration does not match the PagerDuty target")
            if op.health_checks != ["pagerduty_configuration_matches"]:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "configure requires exactly pagerduty_configuration_matches health check")
        else:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "configure requires the pagerduty_configuration or aws_change executor")
    if not catalog.meta.execution_allowed:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "catalog does not allow execution")
    if not binding.execution_enabled:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"binding {binding.id} is not execution-enabled (source_state={binding.source_state})")
    if args.action != "configure":
        missing = binding.execution_missing_fields()
        if missing:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} is missing execution fields {missing}")
    return doc.spec, binding, op


def describe_prepare(args: ActionPrepareArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    doc = catalog.service(args.service_id)
    b = doc.spec.binding(args.binding_id) if doc else None
    op = doc.spec.operations.get(args.action) if doc else None
    pagerduty = args.action == "configure"
    return {
        "summary": f"Prepare (read-only) {args.action} plan for {args.service_id}/{args.binding_id}",
        "service": {"id": args.service_id, "name": doc.spec.name if doc else None},
        "binding": b.model_dump() if b else None,
        "operation": op.model_dump() if op else None,
        "desired_artifact": args.desired_artifact,
        "desired_configuration": args.desired_configuration.model_dump(mode="json") if args.desired_configuration else None,
        "reads": (["execution account identity", "exact current state of the bound AWS resource"] if (pagerduty and op is not None and op.executor == "aws_change") else ["PagerDuty account and exact resource", "current routing and referenced configuration"] if pagerduty else ["cluster identity", "workload/release state", "registry tag->digest resolution", "replicaset/helm history"]),
        "effect": "read; produces an immutable plan that must be released before it can be submitted",
        "reason": args.reason,
    }


async def run_prepare(ctx: OperationContext, args: ActionPrepareArgs) -> OperationOutcome:
    service, binding, op = _resolve(ctx.catalog, args)
    executor = executors.get(op.executor)
    if args.action == "configure":
        plan: ActionPlan = await executor.prepare(ctx, service, binding, op, args.action, args.desired_artifact, args.reason, desired_configuration=args.desired_configuration)
    else:
        plan = await executor.prepare(ctx, service, binding, op, args.action, args.desired_artifact, args.reason)
    body = plan.model_dump(mode="json")
    await ctx.db.insert_plan(plan.plan_id, ctx.request_id, ctx.principal.id, plan.plan_hash, body, plan.locks[0] if plan.locks else f"service:{service.id}", plan.expires_at)
    target_summary = (f"{plan.target.get('resource_type')}/{plan.target.get('name')} in {plan.target.get('account_domain')}" if args.action == "configure" else f"{plan.target.get('kind')}/{plan.target.get('name')} in {plan.target.get('namespace')}")
    result = {"plan": body, "plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "submit_with": {"tool": "action_submit", "arguments": {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "idempotency_key": "<client-chosen unique key>"}}, "expires_at": iso(plan.expires_at), "summary": f"{plan.action} {target_summary} via {plan.mechanism}"}
    return OperationOutcome(ExecutionStatus.SUCCEEDED, result, plan=body)


async def pre_submit(args: ActionSubmitArgs, principal: Principal, db: Database, catalog: Catalog) -> dict[str, Any]:
    """Read-only validation; does not consume the plan. Consumption happens atomically with the
    request insert itself (`Database.insert_request_with_plan`), so a plan can never be left consumed
    by a request that fails to get created, and a concurrent identical (same idempotency_key)
    submission replays the already-inserted request instead of racing this plan's consumption."""
    row = await db.plan(args.plan_id)
    if row is None or principal.id not in row["released_to"]:
        raise OpsError(ErrorCode.NOT_FOUND, "no released plan with that id for this principal")
    if row["principal_id"] != principal.id:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "a plan can only be submitted by the principal that prepared it")
    if row["plan_hash"] != args.plan_hash:
        raise OpsError(ErrorCode.PLAN_STALE, "plan_hash does not match the released plan")
    if row["consumed_at"] is not None:
        raise OpsError(ErrorCode.CONFLICT, "plan was already submitted; prepare a new plan", data={"consumed_by": row["consumed_by_request_id"]})
    if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) < utcnow():
        raise OpsError(ErrorCode.PLAN_STALE, "plan expired; prepare a new plan")
    plan = ActionPlan.model_validate(row["body"])
    if plan.catalog_revision != catalog.revision:
        raise OpsError(ErrorCode.PLAN_STALE, "catalog configuration changed since the plan was prepared")
    return {"target_keys": plan.locks, "plan_id": plan.plan_id}


def describe_submit(args: ActionSubmitArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    return {"summary": f"Execute plan {args.plan_id}", "plan_id": args.plan_id, "plan_hash": args.plan_hash, "effect": "mutation", "reason": args.reason, "note": "the reviewer page attaches the full released plan (before/after state) from the plans table"}


async def run_submit(ctx: OperationContext, args: ActionSubmitArgs) -> OperationOutcome:
    row = await ctx.db.plan(args.plan_id)
    if row is None:
        raise OpsError(ErrorCode.NOT_FOUND, "plan not found")
    if row.get("consumed_by_request_id") in (None, "pending-submit"):
        await ctx.db.consume_plan(args.plan_id, ctx.request_id)
        async with ctx.db.tx() as c:
            await c.execute("UPDATE plans SET consumed_by_request_id=? WHERE plan_id=?", (ctx.request_id, args.plan_id))
    elif row["consumed_by_request_id"] != ctx.request_id:
        raise OpsError(ErrorCode.CONFLICT, "plan was consumed by another request")
    plan = ActionPlan.model_validate(row["body"])
    if plan.expires_at < utcnow():
        raise OpsError(ErrorCode.PLAN_STALE, "plan expired before dispatch; prepare a new plan")
    if plan.catalog_revision != ctx.catalog.revision:
        raise OpsError(ErrorCode.PLAN_STALE, "catalog configuration changed; plan invalidated")
    if row["principal_id"] != ctx.principal.id:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "plan belongs to another principal")
    doc = ctx.catalog.service(plan.service_id)
    if doc is None:
        raise OpsError(ErrorCode.PLAN_STALE, "service removed from catalog")
    binding = doc.spec.binding(plan.binding_id)
    if binding is None or not binding.execution_enabled or not ctx.catalog.meta.execution_allowed:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "execution is no longer enabled for this binding")
    executor = executors.get(plan.executor)
    try:
        receipt = await executor.execute(ctx, plan)
    except OpsError as e:
        if e.code in (ErrorCode.PLAN_STALE, ErrorCode.AUTHORIZATION_DENIED, ErrorCode.SCOPE_UNRESOLVED, ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, ErrorCode.UNSUPPORTED_OPERATION):
            return OperationOutcome(ExecutionStatus.REJECTED if e.code != ErrorCode.SCOPE_UNRESOLVED else ExecutionStatus.FAILED, {"error": e.public(), "plan_id": plan.plan_id, "ran": "not_started"}, public_error=e.public(), private_error=e.private_detail)
        raise
    await ctx.db.insert_receipt(receipt.receipt_id, ctx.request_id, plan.plan_id, receipt.model_dump(mode="json"))
    return outcome_from_receipt(receipt, plan)


def submit_target_keys(args: ActionSubmitArgs, catalog: Catalog, config: ServerConfig) -> list[str]:
    return []  # resolved in pre_submit from the plan


def register(registry: OperationRegistry) -> None:
    registry.register(OperationSpec(name="action_prepare", data_class=DataClass.MUTATION, effect=Effect.READ, args_model=ActionPrepareArgs, handler=run_prepare, describe=describe_prepare, summary="Read-only preparation of an exact, immutable restart/update/rollback/redeploy/configure plan.", budget_seconds=300))
    registry.register(OperationSpec(name="action_submit", data_class=DataClass.MUTATION, effect=Effect.MUTATION, args_model=ActionSubmitArgs, handler=run_submit, describe=describe_submit, summary="Submit a released plan for reviewed execution (mutation).", budget_seconds=900, requires_idempotency_key=True, pre_submit=pre_submit, target_keys=submit_target_keys))
