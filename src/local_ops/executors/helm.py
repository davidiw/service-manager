"""Helm executor: operates on an explicitly configured release/namespace/cluster, pins the artifact,
discloses hooks, and never returns raw values/manifests. Rollback is a separate explicit action."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
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
from local_ops.executors.kubernetes_native import KubernetesNativeExecutor, resolve_artifact
from local_ops.models import (
    ActionPlan,
    ErrorCode,
    ExecutionStatus,
    HealthCheckResult,
    OpsError,
    Receipt,
    utcnow,
)
from local_ops.operations.base import OperationContext
from local_ops.pagerduty_contracts import PagerDutyConfiguration
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.kubernetes import rollout_state

HOOK_RE = re.compile(r"helm\.sh/hook[\"']?\s*:\s*[\"']?([a-z,\-\s]+)")


def chart_fingerprint(chart_dir: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in chart_dir.rglob("*") if x.is_file() and ".git" not in x.parts):
        h.update(str(p.relative_to(chart_dir)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def chart_hooks(chart_dir: Path) -> list[str]:
    hooks: list[str] = []
    for p in sorted((chart_dir / "templates").glob("*.y*ml")) if (chart_dir / "templates").exists() else []:
        for m in HOOK_RE.finditer(p.read_text(encoding="utf-8", errors="replace")):
            hooks.append(f"{p.name}: {m.group(1).strip()}")
    return hooks


def resolve_values_file(catalog_root: Path, values_file: str) -> Path:
    """A values file passed to `helm -f` must resolve inside the catalog root; no `..`/symlink escape
    to a path the operator never approved."""
    root = catalog_root.resolve()
    p = (catalog_root / values_file).resolve()
    if p != root and root not in p.parents:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"values file {values_file!r} resolves outside the catalog root")
    return p


def values_files_fingerprint(catalog_root: Path, values_files: list[str]) -> str:
    """Hash of every declared values file's content, in declared order; neither the catalog revision nor
    the chart fingerprint otherwise covers files passed to `helm -f`, so an edit here must also invalidate
    the plan (plan_stale) like any other drift."""
    h = hashlib.sha256()
    for vf in values_files:
        p = resolve_values_file(catalog_root, vf)
        if not p.is_file():
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"values file {vf!r} not found under the catalog root")
        h.update(vf.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


class HelmRunner:
    """Async wrapper for the trusted installed helm binary. Fixed argument arrays, minimal environment."""

    def __init__(self, binary: str, kubeconfig: str | None, context: str, timeout: float = 600):
        self.binary = binary
        self.kubeconfig = kubeconfig
        self.context = context
        self.timeout = timeout
        self.log: list[list[str]] = []

    async def run(self, args: list[str]) -> tuple[int, str, str]:
        cmd = [self.binary, *args, "--kube-context", self.context]
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        self.log.append(cmd)
        env = CredentialResolver.minimal_subprocess_env({"HELM_PLUGINS": "/nonexistent"})  # no plugins
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env, cwd=os.getcwd())
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            raise OpsError(ErrorCode.OUTCOME_UNKNOWN, "helm did not finish within the budget; the release may be mid-upgrade") from None
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")

    async def status(self, release: str, namespace: str) -> dict[str, Any] | None:
        rc, out, err = await self.run(["status", release, "-n", namespace, "-o", "json"])
        if rc != 0:
            if "not found" in err.lower():
                return None
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "helm status failed", private_detail=err[:800])
        data = json.loads(out)
        # project to permitted metadata: never values/manifests
        return {"name": data.get("name"), "namespace": data.get("namespace"), "version": data.get("version"), "status": (data.get("info") or {}).get("status"), "chart": (data.get("chart") or {}).get("metadata", {}).get("name"), "chart_version": (data.get("chart") or {}).get("metadata", {}).get("version"), "app_version": (data.get("chart") or {}).get("metadata", {}).get("appVersion"), "last_deployed": (data.get("info") or {}).get("last_deployed")}

    async def history(self, release: str, namespace: str) -> list[dict[str, Any]]:
        rc, out, err = await self.run(["history", release, "-n", namespace, "-o", "json", "--max", "20"])
        if rc != 0:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "helm history failed", private_detail=err[:800])
        return [{"revision": h.get("revision"), "status": h.get("status"), "chart": h.get("chart"), "app_version": h.get("app_version"), "updated": h.get("updated"), "description": h.get("description")} for h in json.loads(out)]


class HelmExecutor:
    name = "helm"

    def __init__(self, runner_factory: Any | None = None):
        self._runner_factory = runner_factory

    async def _runner(self, ctx: OperationContext, binding: Binding) -> HelmRunner:
        adapter = kube_adapter_for(ctx, binding)
        if self._runner_factory:
            return self._runner_factory(ctx, adapter)
        context, kubeconfig = await adapter.connection()  # the same resolution adapter.client() verified
        return HelmRunner(ctx.config.helm_binary, kubeconfig, context, timeout=min(ctx.budget.remaining_seconds(), 900))

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None, *, desired_configuration: PagerDutyConfiguration | None = None) -> ActionPlan:
        if desired_configuration is not None:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "helm does not support PagerDuty configuration")
        if action == "restart":
            if op.kind != "rollout_restart":
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "helm restart must be configured as rollout_restart (registered restart mechanism)")
            plan = await KubernetesNativeExecutor().prepare(ctx, service, binding, op, "restart", None, reason)
            return plan.model_copy(update={"executor": self.name, "mechanism": "registered restart mechanism for a Helm-owned workload (pod-template annotation patch; no unmanaged image change)"})
        adapter = kube_adapter_for(ctx, binding)
        await verify_cluster_identity(adapter, binding)
        runner = await self._runner(ctx, binding)
        release, ns = op.release or "", binding.namespace or ""
        status = await runner.status(release, ns)
        if status is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"helm release {release!r} not found in namespace {ns}")
        client = await adapter.client()
        wl = await client.get_workload(binding.workload_kind or "Deployment", ns, binding.workload_name or "")
        if wl is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"workload {binding.workload_kind}/{binding.workload_name} for release {release} not found")
        rel_ann = (wl["metadata"].get("annotations") or {}).get("meta.helm.sh/release-name")
        if rel_ann and rel_ann != release:
            raise OpsError(ErrorCode.UNSUPPORTED_DEPLOYMENT_MECHANISM, f"workload belongs to Helm release {rel_ann!r}, not the configured {release!r}")
        containers = wl["spec"]["template"]["spec"]["containers"]
        container_name = op.container or binding.container_name or containers[0]["name"]
        current = next((c for c in containers if c["name"] == container_name), None)
        if current is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"container {container_name!r} not found")
        chart_dir = ctx.catalog.root / (op.chart_path or "")
        if not op.chart_path or not chart_dir.exists():
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "helm operation requires an approved chart_path inside the catalog directory")
        chart_fp = chart_fingerprint(chart_dir)
        values_fp = values_files_fingerprint(ctx.catalog.root, op.values_files)
        hooks = chart_hooks(chart_dir)
        cid = adapter.cluster_identity_string()
        effective_context, _kubeconfig = await adapter.connection()
        target = {"provider_id": binding.provider_id, "cluster_identity": cid, "cluster_context": effective_context, "namespace": ns, "release": release, "kind": binding.workload_kind, "name": binding.workload_name, "uid": wl["metadata"]["uid"], "container": container_name, "chart": status.get("chart"), "chart_version": status.get("chart_version"), "release_revision": status.get("version"), "chart_fingerprint": chart_fp, "values_files": op.values_files, "values_fingerprint": values_fp}
        lock = f"helm:{cid}:{ns}:{release}"
        common = dict(service_id=service.id, binding_id=binding.id, environment=binding.environment, executor=self.name, target=target, target_fingerprint=target_fingerprint(wl) + ":" + chart_fp[:16] + ":rev" + str(status.get("version")) + ":vf" + values_fp[:16], current_artifact=artifact_from_image(current.get("image")), health_checks=op.health_checks, unavailable_health_checks=[h for h in op.health_checks if h not in ("ready_replicas", "helm_release_deployed") and service.health_check(h) is None], timeout_seconds=op.readiness_timeout_seconds, dependencies=service.depends_on, dependents=ctx.catalog.dependents_of(service.id), locks=[lock, f"k8s:{cid}:{ns}:{binding.workload_kind}:{wl['metadata']['uid']}"], preconditions=[f"release {release} revision == {status.get('version')}", f"chart fingerprint == {chart_fp[:16]}", f"workload uid == {wl['metadata']['uid']}"] + ([f"values files fingerprint == {values_fp[:16]}"] if op.values_files else []), pre_reads=["helm status", "get workload", "cluster identity"], post_reads=["helm status", "watch rollout", "service health checks"], hooks_or_auxiliary_work=hooks or ["no helm.sh/hook annotations found in chart templates"])
        if action == "update":
            if op.kind != "helm_upgrade" or not op.image_value_path:
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "helm update must be configured as helm_upgrade with image_value_path")
            if not desired_artifact:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "desired_artifact is required")
            resolved = await resolve_artifact(ctx, desired_artifact, op)
            if any(ch in resolved.reference for ch in ",=\\ {}[]\n"):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "resolved artifact reference is not a safe --set-string value")
            if op.require_digest and not resolved.digest:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "could not pin the requested artifact to a digest")
            args = ["upgrade", release, str(chart_dir), "-n", ns, "--reuse-values", "--set-string", f"{op.image_value_path}={resolved.reference}", "--wait=false", "--timeout", f"{op.readiness_timeout_seconds}s"]
            for vf in op.values_files:
                args += ["-f", str(resolve_values_file(ctx.catalog.root, vf))]
            return new_plan(ctx, action="update", mechanism="helm upgrade of the configured release with the artifact pinned by --set-string", provider_mutations=[{"op": "helm_upgrade", "args": args, "release": release, "namespace": ns, "expected_revision_after": (status.get("version") or 0) + 1}], requested_artifact=resolved, expected_disruption=f"helm upgrade -> rolling update of {wl['spec'].get('replicas', '?')} replica(s)", rollback={"supported": "rollback" in service.operations, "previous_revision": status.get("version"), "note": "helm rollback is a separate explicit action"}, notes=([f"version label: {resolved.version_label}"] if resolved.version_label else []), **common)
        if action == "rollback":
            if op.kind != "helm_rollback":
                raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "rollback is not explicitly configured as helm_rollback for this service")
            hist = await runner.history(release, ns)
            deployed = [h for h in hist if h.get("status") in ("superseded", "deployed") and h.get("revision") != status.get("version")]
            if not deployed:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "no previous helm revision to roll back to")
            target_rev = int(desired_artifact) if desired_artifact and str(desired_artifact).isdigit() else int(str(deployed[-1]["revision"]))
            return new_plan(ctx, action="rollback", mechanism=f"helm rollback to revision {target_rev}", provider_mutations=[{"op": "helm_rollback", "args": ["rollback", release, str(target_rev), "-n", ns, "--wait=false", "--timeout", f"{op.readiness_timeout_seconds}s"], "release": release, "namespace": ns, "target_revision": target_rev, "expected_revision_after": (status.get("version") or 0) + 1}], requested_artifact=None, expected_disruption="helm rollback -> rolling update to the previous revision's artifact", rollback={"supported": False, "note": "a rollback of a rollback is a new explicit action"}, notes=[f"history: {[(h['revision'], h['status']) for h in hist][-5:]}"], **common)
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"action {action!r} not supported by helm executor")

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt:
        if plan.action == "restart":
            return await KubernetesNativeExecutor().execute(ctx, plan)
        started = utcnow()
        doc = ctx.catalog.service(plan.service_id)
        assert doc is not None
        service = doc.spec
        binding = service.binding(plan.binding_id)
        assert binding is not None
        adapter = kube_adapter_for(ctx, binding)
        await verify_cluster_identity(adapter, binding)
        runner = await self._runner(ctx, binding)
        client = await adapter.client()
        ns, release = plan.target["namespace"], plan.target["release"]
        status = await runner.status(release, ns)
        wl = await client.get_workload(plan.target["kind"], ns, plan.target["name"])
        op = service.operations[plan.action]
        chart_dir = ctx.catalog.root / (op.chart_path or "")
        live_values_fp = values_files_fingerprint(ctx.catalog.root, op.values_files)
        live_fp = (target_fingerprint(wl) if wl else "gone") + ":" + chart_fingerprint(chart_dir)[:16] + ":rev" + str((status or {}).get("version")) + ":vf" + live_values_fp[:16]
        if live_fp != plan.target_fingerprint:
            raise OpsError(ErrorCode.PLAN_STALE, "release/workload/chart changed since the plan was prepared", private_detail=f"plan={plan.target_fingerprint} live={live_fp}")
        before = {"release_revision": (status or {}).get("version"), "rollout": rollout_state(wl) if wl else None, "images": [(c["name"], c.get("image")) for c in (wl or {}).get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])]}
        mutation = plan.provider_mutations[0]
        intent_id = await ctx.record_intent("dispatching", plan.locks[0], f"{mutation['op']} {release}", intent_record(plan, {k: v for k, v in mutation.items()}))
        dispatched = utcnow()
        try:
            rc, out, err = await runner.run(mutation["args"])
        except OpsError as e:
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "error": e.message})
            st, detail = await self.reconcile(ctx, plan, await ctx.db.intents(ctx.request_id), uncertain_if_absent=True)
            return receipt_from(plan, ctx, before=before, after=detail.get("observed", {}), before_artifact=plan.current_artifact, after_artifact=detail.get("after_artifact"), provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="uncertain" if st == ExecutionStatus.OUTCOME_UNKNOWN else "partial", outcome=detail.get("summary", "uncertain"), checks=[], notes=["helm timed out; reconciled without re-running"])
        if rc != 0:
            await ctx.db.complete_intent(intent_id, {"status": "failed", "rc": rc})
            after_status = await runner.status(release, ns)
            scrubbed_err, _ = ctx.sanitizer.scrub_text(err[:1500])
            return receipt_from(plan, ctx, before=before, after={"release_revision": (after_status or {}).get("version"), "release_status": (after_status or {}).get("status")}, before_artifact=plan.current_artifact, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="partial" if (after_status or {}).get("version") != before["release_revision"] else "not_started", outcome=f"helm exited {rc}", checks=[HealthCheckResult(check_id="helm_release_deployed", kind="helm_release_deployed", passed=False, detail=scrubbed_err)], notes=["no automatic rollback: rollback is a separate explicit action"])
        await ctx.db.complete_intent(intent_id, {"status": "accepted", "rc": rc})
        await ctx.set_phase("verifying")
        after_status = await runner.status(release, ns)
        checks = [HealthCheckResult(check_id="helm_release_deployed", kind="helm_release_deployed", passed=(after_status or {}).get("status") == "deployed" and (after_status or {}).get("version") == mutation.get("expected_revision_after"), detail=f"release status {(after_status or {}).get('status')} revision {(after_status or {}).get('version')} (expected {mutation.get('expected_revision_after')})", observed=after_status or {})]
        wl_after = await client.get_workload(plan.target["kind"], ns, plan.target["name"])
        expected_images = [plan.requested_artifact.reference] if plan.requested_artifact else None
        rollout = await wait_for_rollout(client, plan.target["kind"], ns, plan.target["name"], (wl_after or wl or {}).get("metadata", {}).get("uid", plan.target["uid"]), plan.timeout_seconds, expected_images=expected_images, cancel=ctx.cancel_event)
        checks.append(rollout)
        if rollout.passed:
            async with httpx.AsyncClient(timeout=ctx.config.limits.http_timeout_seconds) as http:
                checks += await run_service_checks(service, plan.health_checks, http, expected_version=plan.requested_artifact.version_label if plan.requested_artifact else None)
        wl_after = await client.get_workload(plan.target["kind"], ns, plan.target["name"])
        after = {"release_revision": (after_status or {}).get("version"), "release_status": (after_status or {}).get("status"), "rollout": rollout_state(wl_after) if wl_after else None, "images": [(c["name"], c.get("image")) for c in (wl_after or {}).get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])]}
        raw_images = after.get("images")
        after_images: list[Any] = list(raw_images) if isinstance(raw_images, list) else []
        after_artifact = plan.requested_artifact or (artifact_from_image(after_images[0][1]) if after_images else None)
        ok = all(c.passed for c in checks)
        return receipt_from(plan, ctx, before=before, after=after, before_artifact=plan.current_artifact, after_artifact=after_artifact, provider_ids=[intent_id, f"helm-revision:{after['release_revision']}"], started_at=started, dispatched_at=dispatched, ran="ran", outcome="helm upgrade applied; rollout converged and checks passed" if ok else "helm operation applied but verification did not fully pass", checks=checks)

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]:
        if plan.action == "restart":
            return await KubernetesNativeExecutor().reconcile(ctx, plan, intents, uncertain_if_absent=uncertain_if_absent)
        doc = ctx.catalog.service(plan.service_id)
        binding = doc.spec.binding(plan.binding_id) if doc else None
        if binding is None:
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "binding no longer exists", "observed": {}}
        try:
            runner = await self._runner(ctx, binding)
            status = await runner.status(plan.target["release"], plan.target["namespace"])
        except Exception as e:  # noqa: BLE001
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": f"helm status unavailable: {type(e).__name__}", "observed": {}}
        if status is None:
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "release not found during reconciliation", "observed": {}}
        expected = plan.provider_mutations[0].get("expected_revision_after")
        observed = {"release_revision": status.get("version"), "release_status": status.get("status")}
        if status.get("version") == plan.target.get("release_revision"):
            if uncertain_if_absent:
                return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "release revision unchanged after a transport/timeout error; whether the request reached helm cannot be confirmed", "observed": observed}
            return ExecutionStatus.FAILED, {"summary": "release revision unchanged; upgrade was not applied", "observed": observed}
        if status.get("version") == expected and status.get("status") == "deployed":
            return ExecutionStatus.SUCCEEDED, {"summary": "release at expected revision and deployed", "observed": observed, "after_artifact": plan.requested_artifact.model_dump() if plan.requested_artifact else None}
        if status.get("status") in ("pending-upgrade", "pending-rollback", "pending-install"):
            return ExecutionStatus.PARTIAL, {"summary": f"release is {status.get('status')} (still running)", "observed": observed}
        return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": f"release revision {status.get('version')} status {status.get('status')} does not match expectations", "observed": observed}
