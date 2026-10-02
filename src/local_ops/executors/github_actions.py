"""Typed adapter interface for a fixed GitHub Actions deployment workflow.

This is deliberately not a generic workflow-dispatch tool. A service may declare a workflow contract
(repository, workflow file, ref and a fixed input mapping). Until a service supplies that contract and a
dispatch-capable credential, prepare returns `unsupported_deployment_mechanism` instead of bypassing the
pipeline with a direct patch."""

from __future__ import annotations

from typing import Any

from local_ops.catalog import Binding, OperationConfig, ServiceSpec
from local_ops.executors.base import new_plan, receipt_from
from local_ops.models import (
    ActionPlan,
    ArtifactRef,
    ErrorCode,
    ExecutionStatus,
    HealthCheckResult,
    OpsError,
    Receipt,
    utcnow,
)
from local_ops.operations.base import OperationContext

ALLOWED_INPUT_SOURCES = {"artifact_reference", "artifact_digest", "artifact_tag", "environment", "service_id", "request_id", "reason"}


class GitHubActionsWorkflowExecutor:
    name = "github_actions_workflow"

    def __init__(self, dispatcher: Any | None = None):
        self._dispatcher = dispatcher  # async callable(repo, workflow_file, ref, inputs, credential) -> run info

    def _contract(self, op: OperationConfig) -> dict[str, Any]:
        missing = [f for f in ("repository", "workflow_file", "ref") if not getattr(op, f)]
        if missing or not op.inputs_contract:
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, f"no fixed workflow contract supplied for this service (missing {missing or 'inputs_contract'}); refusing to bypass the recorded deployment mechanism")
        for k, src in op.inputs_contract.items():
            if src not in ALLOWED_INPUT_SOURCES:
                raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, f"inputs_contract maps {k!r} to unsupported source {src!r}")
        return {"repository": op.repository, "workflow_file": op.workflow_file, "ref": op.ref, "inputs_contract": op.inputs_contract}

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None) -> ActionPlan:
        contract = self._contract(op)
        gh = next((a for a in ctx.providers.by_kind("github") if getattr(a.config, "execution_credential", None)), None)
        if gh is None:
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, "no github provider with an execution_credential is configured for workflow dispatch")
        if action not in ("update", "redeploy"):
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"workflow executor supports update/redeploy, not {action}")
        artifact = None
        if desired_artifact:
            from local_ops.executors.kubernetes_native import resolve_artifact

            artifact = await resolve_artifact(ctx, desired_artifact, op)
        values = {"artifact_reference": artifact.reference if artifact else "", "artifact_digest": artifact.digest if artifact else "", "artifact_tag": artifact.tag if artifact else "", "environment": binding.environment, "service_id": service.id, "request_id": ctx.request_id, "reason": reason or ""}
        inputs = {k: values[src] for k, src in contract["inputs_contract"].items()}
        target = {"provider_id": gh.provider_id, "repository": contract["repository"], "workflow_file": contract["workflow_file"], "ref": contract["ref"], "binding": binding.id}
        return new_plan(ctx, service_id=service.id, binding_id=binding.id, action=action, environment=binding.environment, executor=self.name, mechanism=f"GitHub Actions workflow_dispatch {contract['repository']}/{contract['workflow_file']}@{contract['ref']}", target=target, target_fingerprint=f"workflow:{contract['repository']}:{contract['workflow_file']}:{contract['ref']}", current_artifact=None, requested_artifact=artifact, provider_mutations=[{"op": "workflow_dispatch", "repository": contract["repository"], "workflow_file": contract["workflow_file"], "ref": contract["ref"], "inputs": inputs}], health_checks=op.health_checks, unavailable_health_checks=[h for h in op.health_checks if service.health_check(h) is None and h != "ready_replicas"], timeout_seconds=op.readiness_timeout_seconds, expected_disruption="as defined by the workflow; this server only observes the run", rollback={"supported": False, "note": "rollback must be a separately declared workflow contract"}, dependencies=service.depends_on, dependents=ctx.catalog.dependents_of(service.id), locks=[f"workflow:{contract['repository']}:{contract['workflow_file']}"], preconditions=["workflow file exists on ref", "dispatch credential has actions:write"], notes=["the workflow performs the actual deployment; verification is limited to the run conclusion and configured health checks"])

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt:
        started = utcnow()
        if self._dispatcher is None:
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, "workflow dispatch is not wired to a live GitHub execution credential")
        mutation = plan.provider_mutations[0]
        intent_id = await ctx.record_intent("dispatching", plan.locks[0], f"workflow_dispatch {mutation['repository']}", {"plan_id": plan.plan_id, "mutation": mutation})
        dispatched = utcnow()
        run = await self._dispatcher(mutation["repository"], mutation["workflow_file"], mutation["ref"], mutation["inputs"])
        await ctx.db.complete_intent(intent_id, {"status": "dispatched", "run": run})
        checks = [HealthCheckResult(check_id="workflow_run", kind="workflow_run", passed=run.get("conclusion") == "success" if run.get("conclusion") else None, detail=f"run {run.get('id')} status={run.get('status')} conclusion={run.get('conclusion')}", observed=run)]
        return receipt_from(plan, ctx, before={}, after={"run": run}, before_artifact=None, after_artifact=plan.requested_artifact, provider_ids=[intent_id, f"workflow-run:{run.get('id')}"], started_at=started, dispatched_at=dispatched, ran="ran" if run.get("conclusion") == "success" else "partial", outcome=f"workflow run {run.get('id')} {run.get('conclusion') or run.get('status')}", checks=checks)

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]:
        last = intents[-1] if intents else None
        run = (last or {}).get("result", {}) or {}
        if run.get("run"):
            return ExecutionStatus.PARTIAL, {"summary": "workflow was dispatched; inspect the run in GitHub", "observed": run}
        return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "unknown whether the workflow dispatch was sent", "observed": {}}


def _unused(_: ArtifactRef) -> None:  # keep import for typing clarity
    return None
