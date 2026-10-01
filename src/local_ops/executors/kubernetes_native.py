"""Native Kubernetes executor: rollout restart via a request-specific pod-template annotation and
image update via a conditional strategic-merge patch on the exact approved controller."""

from __future__ import annotations

import re
from typing import Any

import httpx

from local_ops.catalog import Binding, OperationConfig, ServiceSpec
from local_ops.executors.base import (
    artifact_from_image,
    intent_record,
    kube_adapter_for,
    new_plan,
    receipt_from,
    target_fingerprint,
    verify_cluster_identity,
)
from local_ops.executors.health import run_service_checks, wait_for_rollout
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
from local_ops.providers.kube_client import KubeConflict
from local_ops.providers.kubernetes import detect_ownership, parse_image_ref, rollout_state, workload_key

RESTART_ANNOTATION = "local-ops.dev/restart-plan"
SUPPORTED_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


async def resolve_artifact(ctx: OperationContext, image: str, op: OperationConfig) -> ArtifactRef:
    if any(ch in image for ch in ",= \\{}[]\n"):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "artifact reference contains forbidden characters")
    p = parse_image_ref(image)
    if p["digest"] and not DIGEST_RE.fullmatch(p["digest"]):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "artifact digest must be sha256:<64 lowercase hex>")
    repo = p["repository"] or ""
    if op.allowed_image_repositories and repo not in op.allowed_image_repositories:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"image repository {repo!r} is not in allowed_image_repositories for this operation")
    registries = ctx.providers.by_kind("registry")
    for reg in registries:
        if reg.allowed(repo):  # type: ignore[attr-defined]
            resolved: ArtifactRef = await reg.resolve(image)  # type: ignore[attr-defined]
            return resolved
    if p["digest"]:
        return ArtifactRef(reference=image, repository=repo, tag=p["tag"], digest=p["digest"], digest_kind="unknown")
    if op.require_digest:
        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"cannot resolve tag {p['tag']!r} to a digest: no registry provider covers {repo!r} and require_digest is set")
    return ArtifactRef(reference=image, repository=repo, tag=p["tag"])


class KubernetesNativeExecutor:
    name = "kubernetes_native"

    async def _current(self, ctx: OperationContext, binding: Binding) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        adapter = kube_adapter_for(ctx, binding)
        ident = await verify_cluster_identity(adapter, binding)
        client = await adapter.client()
        kind = binding.workload_kind or "Deployment"
        if kind not in SUPPORTED_KINDS:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"{kind} is not supported by the native executor")
        wl = await client.get_workload(kind, binding.namespace or "", binding.workload_name or "")
        if wl is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"{kind}/{binding.workload_name} not found in namespace {binding.namespace}")
        if binding.workload_uid and wl["metadata"]["uid"] != binding.workload_uid:
            raise OpsError(ErrorCode.PLAN_STALE, "workload UID differs from the approved binding (recreated?)", private_detail=f"approved={binding.workload_uid} live={wl['metadata']['uid']}")
        if kind == "StatefulSet":
            strategy = (wl.get("spec", {}).get("update_strategy") or wl.get("spec", {}).get("updateStrategy") or {})
            partition = ((strategy.get("rolling_update") or strategy.get("rollingUpdate") or {}).get("partition"))
            if strategy.get("type", "RollingUpdate") != "RollingUpdate" or (partition and partition > 0):
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "StatefulSet update strategy/partition requires explicit service-specific enrollment", private_detail=str(strategy))
        return adapter, ident, wl

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None) -> ActionPlan:
        adapter, ident, wl = await self._current(ctx, binding)
        ownership = detect_ownership(wl)
        if ownership["mechanism"] == "controller":
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, f"workload is owned by {ownership.get('controller')}; patching it directly would be reverted by that controller")
        if ownership["mechanism"] in ("argocd", "flux"):
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, f"workload is managed by {ownership['mechanism']} ({ownership.get('evidence')}); a direct patch would be overwritten. Use the recorded GitOps mechanism.")
        if ownership["mechanism"] == "helm" and action != "restart":
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, "workload is Helm-managed; image updates must use the helm executor")
        kind = binding.workload_kind or "Deployment"
        cid = adapter.cluster_identity_string()
        containers = wl.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        container_name = op.container or binding.container_name or (containers[0]["name"] if containers else None)
        current = next((c for c in containers if c["name"] == container_name), None)
        if current is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"container {container_name!r} not found in {kind}/{binding.workload_name}")
        pods = await (await adapter.client()).list_pods(binding.namespace or "")
        running_ids = sorted({cs.get("image_id", cs.get("imageID")) for p in pods for cs in (p.get("status", {}).get("container_statuses") or []) if cs.get("name") == container_name and cs.get("image") == current.get("image")} - {None})
        current_artifact = artifact_from_image(current.get("image"), running_ids[0] if running_ids else None)
        target: dict[str, Any] = {"provider_id": binding.provider_id, "cluster_identity": cid, "cluster_context": adapter.config.context, "namespace": binding.namespace, "kind": kind, "name": binding.workload_name, "uid": wl["metadata"]["uid"], "container": container_name, "ownership": ownership}
        tkey = workload_key(cid, binding.namespace or "", kind, wl["metadata"]["uid"])
        common = dict(service_id=service.id, binding_id=binding.id, environment=binding.environment, executor=self.name, target=target, target_fingerprint=target_fingerprint(wl), current_artifact=current_artifact, health_checks=op.health_checks, unavailable_health_checks=[h for h in op.health_checks if h != "ready_replicas" and service.health_check(h) is None], timeout_seconds=op.readiness_timeout_seconds, dependencies=service.depends_on, dependents=ctx.catalog.dependents_of(service.id), locks=[tkey], preconditions=[f"{kind} uid == {wl['metadata']['uid']}", f"container {container_name} image == {current.get('image')}", f"cluster kube-system uid == {cid}"], pre_reads=[f"get {kind}/{binding.workload_name}", "list pods", "cluster identity"], post_reads=["watch rollout convergence", "list pods", "service health checks"])
        if action == "restart":
            if op.kind != "rollout_restart":
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "restart operation is not configured as rollout_restart")
            marker = f"req:{ctx.request_id}"
            patch: dict[str, Any] = {"spec": {"template": {"metadata": {"annotations": {RESTART_ANNOTATION: marker}}}}}
            return new_plan(ctx, action="restart", mechanism="kubernetes rollout restart (pod-template annotation patch)", provider_mutations=[{"op": "strategic_merge_patch", "kind": kind, "namespace": binding.namespace, "name": binding.workload_name, "patch": patch, "conditional_on_uid": wl["metadata"]["uid"]}], requested_artifact=current_artifact, expected_disruption=f"rolling restart of {wl.get('spec', {}).get('replicas', '?')} replica(s); brief capacity reduction per surge policy", rollback={"supported": False, "note": "restart has no rollback; a second restart is a new action"}, notes=[f"restart annotation value {marker} is idempotent: re-applying it does not trigger another rollout"], **common)
        if action in ("update", "rollback"):
            if action == "update" and op.kind != "image_update":
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "update operation is not configured as image_update")
            if action == "rollback":
                if op.kind != "rollback" or op.rollback_policy == "unsupported":
                    raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "rollback is not explicitly supported for this service")
                desired_artifact = desired_artifact or await self._previous_image(adapter, binding, wl, container_name)
            if not desired_artifact:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "desired_artifact is required for update")
            svc_doc = ctx.catalog.service(service.id)
            update_op = (svc_doc.spec.operations.get("update") if svc_doc else None) if action == "rollback" else op
            resolved = await resolve_artifact(ctx, desired_artifact, update_op or op)
            if (update_op or op).require_digest and not resolved.digest:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "could not pin the requested artifact to an immutable digest")
            if resolved.reference == current.get("image"):
                raise OpsError(ErrorCode.CONFLICT, "requested artifact is already the desired image on this workload")
            patch = {"spec": {"template": {"spec": {"containers": [{"name": container_name, "image": resolved.reference}]}}}}
            http_checks = [h for h in op.health_checks if h != "ready_replicas"]
            return new_plan(ctx, action=action, mechanism="kubernetes container image patch (strategic merge, conditional on UID)", provider_mutations=[{"op": "strategic_merge_patch", "kind": kind, "namespace": binding.namespace, "name": binding.workload_name, "patch": patch, "conditional_on_uid": wl["metadata"]["uid"]}], requested_artifact=resolved, expected_disruption=f"rolling update of {wl.get('spec', {}).get('replicas', '?')} replica(s) to {resolved.reference}", rollback={"supported": "rollback" in service.operations, "previous_artifact": current.get("image"), "note": "rollback is a separate reviewed action; it does not reverse schema/data changes"}, notes=(["version label: " + resolved.version_label] if resolved.version_label else []) + ([f"digest kind: {resolved.digest_kind} (index digests differ from per-platform running image ids)"] if resolved.digest_kind else []) + ([f"http checks: {http_checks}"] if http_checks else []), **common)
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"action {action!r} is not supported by the native executor")

    async def _previous_image(self, adapter: Any, binding: Binding, wl: dict[str, Any], container_name: str | None) -> str:
        client = await adapter.client()
        rs = [r for r in await client.list_replicasets(binding.namespace or "") if any(o.get("uid") == wl["metadata"]["uid"] for o in (r["metadata"].get("owner_references") or r["metadata"].get("ownerReferences") or []))]
        rs.sort(key=lambda r: int((r["metadata"].get("annotations") or {}).get("deployment.kubernetes.io/revision", "0")))
        current_img = next((c.get("image") for c in wl["spec"]["template"]["spec"]["containers"] if c["name"] == container_name), None)
        for r in reversed(rs):
            img = next((c.get("image") for c in r.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) if c["name"] == container_name), None)
            if img and img != current_img:
                return img
        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "no previous ReplicaSet with a different image was found to roll back to")

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt:
        started = utcnow()
        binding = ctx.catalog.service(plan.service_id).spec.binding(plan.binding_id)  # type: ignore[union-attr]
        service = ctx.catalog.service(plan.service_id).spec  # type: ignore[union-attr]
        assert binding is not None
        adapter, ident, wl = await self._current(ctx, binding)
        before = {"fingerprint": target_fingerprint(wl), "rollout": rollout_state(wl), "images": [(c["name"], c.get("image")) for c in wl["spec"]["template"]["spec"]["containers"]], "generation": wl["metadata"].get("generation")}
        if before["fingerprint"] != plan.target_fingerprint or wl["metadata"]["uid"] != plan.target["uid"]:
            raise OpsError(ErrorCode.PLAN_STALE, "target changed since the plan was prepared (fingerprint mismatch); prepare a new plan", private_detail=f"plan={plan.target_fingerprint} live={before['fingerprint']}")
        client = await adapter.client()
        mutation = plan.provider_mutations[0]
        intent_id = await ctx.record_intent("dispatching", plan.locks[0] if plan.locks else None, f"{plan.action} {mutation['kind']}/{mutation['name']}", intent_record(plan, mutation))
        dispatched = utcnow()
        try:
            try:
                patched = await client.patch_workload(mutation["kind"], mutation["namespace"], mutation["name"], mutation["patch"], expected_uid=plan.target["uid"], expected_resource_version=wl["metadata"].get("resource_version", wl["metadata"].get("resourceVersion")))
            except KubeConflict:
                # race: re-read, re-verify fingerprint, retry once
                wl2 = await client.get_workload(mutation["kind"], mutation["namespace"], mutation["name"])
                if wl2 is None or target_fingerprint(wl2) != plan.target_fingerprint:
                    raise OpsError(ErrorCode.PLAN_STALE, "target changed concurrently; plan not applied") from None
                patched = await client.patch_workload(mutation["kind"], mutation["namespace"], mutation["name"], mutation["patch"], expected_uid=plan.target["uid"], expected_resource_version=wl2["metadata"].get("resource_version", wl2["metadata"].get("resourceVersion")))
        except OpsError:
            await ctx.db.complete_intent(intent_id, {"status": "not_applied"})
            raise
        except Exception as e:  # noqa: BLE001 - connection loss after send: outcome unknown
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "error": type(e).__name__})
            # A transport error carries no confirmation of what the server did with the request: only a
            # re-read that *positively* shows the patch applied may report succeeded/partial; if the
            # re-read shows it absent that is still ambiguous (the write may be in flight), not a confirmed
            # failure, so `uncertain_if_absent` keeps that case outcome_unknown instead of failed.
            status, detail = await self.reconcile(ctx, plan, await ctx.db.intents(ctx.request_id), uncertain_if_absent=True)
            return receipt_from(plan, ctx, before=before, after=detail.get("observed", {}), before_artifact=plan.current_artifact, after_artifact=detail.get("after_artifact"), provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran={"succeeded": "ran", "failed": "not_started", "partial": "partial"}.get(status.value, "uncertain"), outcome=f"patch send failed ({type(e).__name__}); reconciled: {detail.get('summary')}", checks=[HealthCheckResult.model_validate(c) for c in detail.get("checks", [])], notes=["connection lost after dispatch; state reconciled, mutation not re-sent"])
        await ctx.db.complete_intent(intent_id, {"status": "accepted", "generation": patched["metadata"].get("generation"), "resource_version": patched["metadata"].get("resource_version", patched["metadata"].get("resourceVersion"))})
        await ctx.set_phase("verifying")
        expected_images = [plan.requested_artifact.reference] if plan.requested_artifact and plan.action != "restart" else None
        rollout = await wait_for_rollout(client, mutation["kind"], mutation["namespace"], mutation["name"], plan.target["uid"], plan.timeout_seconds, expected_images=expected_images, cancel=ctx.cancel_event)
        checks = [rollout]
        if rollout.passed:
            async with httpx.AsyncClient(timeout=ctx.config.limits.http_timeout_seconds) as http:
                checks += await run_service_checks(service, plan.health_checks, http, expected_version=plan.requested_artifact.version_label if plan.requested_artifact else None)
        else:
            checks += [HealthCheckResult(check_id=h, kind=h, passed=None, detail="skipped: rollout did not converge") for h in plan.health_checks if h != "ready_replicas"]
        after_wl = await client.get_workload(mutation["kind"], mutation["namespace"], mutation["name"])
        after = {"fingerprint": target_fingerprint(after_wl) if after_wl else None, "rollout": rollout_state(after_wl) if after_wl else None, "images": [(c["name"], c.get("image")) for c in (after_wl or {}).get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])], "generation": (after_wl or {}).get("metadata", {}).get("generation")}
        pods = await client.list_pods(mutation["namespace"])
        running_ids = sorted({cs.get("image_id", cs.get("imageID")) for p in pods for cs in (p.get("status", {}).get("container_statuses") or []) if plan.requested_artifact and cs.get("image") == plan.requested_artifact.reference} - {None})
        after_artifact = plan.requested_artifact.model_copy(update={"running_image_id": running_ids[0] if running_ids else None}) if plan.requested_artifact else None
        all_ok = all(c.passed for c in checks)
        outcome = "rollout converged and health checks passed" if all_ok else ("rollout converged but a health check failed or could not run" if rollout.passed else "rollout did not converge")
        return receipt_from(plan, ctx, before=before, after=after, before_artifact=plan.current_artifact, after_artifact=after_artifact, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="ran", outcome=outcome, checks=checks)

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]:
        binding = ctx.catalog.service(plan.service_id).spec.binding(plan.binding_id)  # type: ignore[union-attr]
        assert binding is not None
        try:
            adapter = kube_adapter_for(ctx, binding)
            client = await adapter.client()
            wl = await client.get_workload(plan.target["kind"], plan.target["namespace"], plan.target["name"])
        except Exception as e:  # noqa: BLE001
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": f"target could not be inspected: {type(e).__name__}", "observed": {}}
        if wl is None or wl["metadata"]["uid"] != plan.target["uid"]:
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "target workload is gone or was recreated; cannot determine whether the mutation applied", "observed": {}}
        mutation = plan.provider_mutations[0]
        tmpl = wl["spec"]["template"]
        applied: bool
        if plan.action == "restart":
            want = mutation["patch"]["spec"]["template"]["metadata"]["annotations"][RESTART_ANNOTATION]
            applied = (tmpl.get("metadata", {}).get("annotations") or {}).get(RESTART_ANNOTATION) == want
        else:
            want_img = mutation["patch"]["spec"]["template"]["spec"]["containers"][0]["image"]
            applied = any(c.get("image") == want_img for c in tmpl["spec"]["containers"])
        rs = rollout_state(wl)
        observed = {"applied": applied, "rollout": rs, "images": [(c["name"], c.get("image")) for c in tmpl["spec"]["containers"]]}
        if not applied:
            if uncertain_if_absent:
                return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "mutation is not visible on the target after a transport error; whether the request reached the provider cannot be confirmed", "observed": observed}
            return ExecutionStatus.FAILED, {"summary": "mutation is not present on the target; it was not applied", "observed": observed}
        if rs["converged"]:
            checks = []
            if plan.action != "restart":
                service = ctx.catalog.service(plan.service_id).spec  # type: ignore[union-attr]
                async with httpx.AsyncClient(timeout=ctx.config.limits.http_timeout_seconds) as http:
                    checks = [c.model_dump() for c in await run_service_checks(service, plan.health_checks, http, expected_version=plan.requested_artifact.version_label if plan.requested_artifact else None)]
            ok = all(c["passed"] for c in checks) if checks else True
            return (ExecutionStatus.SUCCEEDED if ok else ExecutionStatus.PARTIAL), {"summary": "mutation applied and rollout converged" + ("" if ok else "; a health check failed"), "observed": observed, "checks": checks, "after_artifact": plan.requested_artifact.model_dump() if plan.requested_artifact else None}
        remaining = int(ctx.budget.remaining_seconds())
        if remaining > 5:
            rollout = await wait_for_rollout(client, plan.target["kind"], plan.target["namespace"], plan.target["name"], plan.target["uid"], min(remaining - 2, plan.timeout_seconds), expected_images=[plan.requested_artifact.reference] if plan.requested_artifact and plan.action != "restart" else None)
            if rollout.passed:
                return ExecutionStatus.SUCCEEDED, {"summary": "mutation applied; rollout converged during reconciliation", "observed": {**observed, "rollout": rollout.observed}, "checks": [rollout.model_dump()], "after_artifact": plan.requested_artifact.model_dump() if plan.requested_artifact else None}
            return ExecutionStatus.PARTIAL, {"summary": "mutation applied but rollout has not converged", "observed": {**observed, "rollout": rollout.observed}, "checks": [rollout.model_dump()]}
        return ExecutionStatus.PARTIAL, {"summary": "mutation applied; rollout still in progress (still running)", "observed": observed}
