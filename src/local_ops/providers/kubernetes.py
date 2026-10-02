"""Kubernetes discovery/diagnosis adapter over the KubeClient boundary."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, ErrorCode, OpsError, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    SupportedOperation,
)
from local_ops.providers.kube_client import KubeClient, RealKubeClient

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

MANAGED_BY_ANNOTATIONS = {
    "argocd": ["argocd.argoproj.io/instance", "argocd.argoproj.io/tracking-id"],
    "flux": ["kustomize.toolkit.fluxcd.io/name", "helm.toolkit.fluxcd.io/name"],
}


def detect_ownership(workload: dict[str, Any]) -> dict[str, Any]:
    """Classify who manages a workload: native, helm, argocd, flux or unknown-controller."""
    md = workload.get("metadata", {})
    labels = md.get("labels", {}) or {}
    ann = md.get("annotations", {}) or {}
    owner_refs = md.get("owner_references", md.get("ownerReferences", [])) or []
    for mech, keys in MANAGED_BY_ANNOTATIONS.items():
        for k in keys:
            if k in labels or k in ann:
                return {"mechanism": mech, "evidence": f"{k}={labels.get(k, ann.get(k))}"}
    if labels.get("app.kubernetes.io/managed-by", "").lower() == "helm" or "meta.helm.sh/release-name" in ann:
        return {"mechanism": "helm", "release": ann.get("meta.helm.sh/release-name"), "release_namespace": ann.get("meta.helm.sh/release-namespace"), "evidence": "helm labels/annotations"}
    if owner_refs:
        return {"mechanism": "controller", "controller": f"{owner_refs[0].get('kind')}/{owner_refs[0].get('name')}", "evidence": "ownerReferences"}
    return {"mechanism": "native", "evidence": "no managed-by markers"}


def parse_image_ref(image: str) -> dict[str, str | None]:
    repo, tag, digest = image, None, None
    if "@" in image:
        repo, digest = image.split("@", 1)
    if ":" in repo and "/" in repo and repo.rfind(":") > repo.rfind("/"):
        repo, tag = repo.rsplit(":", 1)
    elif ":" in repo and "/" not in repo:
        repo, tag = repo.rsplit(":", 1)
    return {"repository": repo, "tag": tag, "digest": digest}


def _kube_reason(e: BaseException) -> str:
    status = getattr(e, "status", None)
    return {401: "auth_required", 403: "permission_denied", 404: "not_found"}.get(status, "provider_unavailable") if isinstance(status, int) else "provider_unavailable"


def _kube_detail(e: BaseException) -> str:
    """Status code and reason only; an ApiException body can echo request content."""
    status, reason = getattr(e, "status", None), getattr(e, "reason", None)
    return f"{type(e).__name__}" + (f" {status}" if status else "") + (f" {reason}" if reason else "")


def workload_key(cluster_identity: str, ns: str, kind: str, uid: str) -> str:
    return f"k8s:{cluster_identity}:{ns}:{kind}:{uid}"


def rollout_state(workload: dict[str, Any]) -> dict[str, Any]:
    md, spec, status = workload.get("metadata", {}), workload.get("spec", {}), workload.get("status", {}) or {}
    desired_raw = spec.get("replicas", 1) if workload.get("kind") != "DaemonSet" else status.get("desired_number_scheduled", status.get("desiredNumberScheduled", 0))
    desired = int(desired_raw) if desired_raw is not None else None
    gen_raw, og_raw = md.get("generation"), status.get("observed_generation", status.get("observedGeneration"))
    gen = int(gen_raw) if gen_raw is not None else None
    og = int(og_raw) if og_raw is not None else None
    ready = int(status.get("ready_replicas", status.get("readyReplicas", status.get("number_ready", 0))) or 0)
    updated = int(status.get("updated_replicas", status.get("updatedReplicas", status.get("updated_number_scheduled", 0))) or 0)
    converged = og is not None and gen is not None and og >= gen and desired is not None and ready == desired and updated == desired
    return {"desired": desired, "ready": ready, "updated": updated, "generation": gen, "observed_generation": og, "converged": bool(converged)}


class KubernetesAdapter:
    kind = "kubernetes"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, client: KubeClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._client = client
        self._identity_cache: dict[str, Any] | None = None

    # ---------------------------------------------------------------- plumbing
    async def connection(self) -> tuple[str, str | None]:
        """The effective (context, kubeconfig path). The client and any out-of-process tool (helm) use this one
        resolution, so a tool can never target a different cluster from the one whose identity was verified."""
        if self.resolver is None or not self.config.credential:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubernetes provider {self.provider_id} has no credential configured")
        cred = await self.resolver.resolve(self.config.credential)
        return cred.context or self.config.context or "", cred.path

    async def client(self) -> KubeClient:
        if self._client is None:
            context, kubeconfig = await self.connection()
            self._client = RealKubeClient(kubeconfig, context, allow_exec_plugins=self.config.allow_exec_plugins)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    def approved_identity(self) -> dict[str, Any] | None:
        if self.config.cluster_identity:
            return dict(self.config.cluster_identity)
        if self.config.cluster_identity_file:
            p = self.server.resolve_path(self.config.cluster_identity_file)
            if p.exists():
                try:
                    return json.loads(Path(p).read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    return None
        return None

    async def verified_identity(self) -> dict[str, Any]:
        """Live identity compared with the approved identity. Raises if they differ."""
        live = await (await self.client()).cluster_identity()
        approved = self.approved_identity()
        if approved and not approved.get("kube_system_uid"):
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"approved cluster identity for provider {self.provider_id} has no kube_system_uid; nothing to verify the live context against")
        if approved:
            for k in ("kube_system_uid",):
                if approved.get(k) and approved[k] != live.get(k):
                    raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"cluster identity mismatch for provider {self.provider_id}: context points at a different cluster than approved", private_detail=f"approved={approved.get(k)} live={live.get(k)}")
            live["approved"] = True
        else:
            live["approved"] = False
        self._identity_cache = live
        return live

    def cluster_identity_string(self) -> str:
        approved = self.approved_identity()
        if approved and approved.get("kube_system_uid"):
            return str(approved["kube_system_uid"])
        if self._identity_cache:
            return str(self._identity_cache.get("kube_system_uid"))
        return f"context:{self.config.context}"

    def describe(self) -> AdapterDescription:
        return AdapterDescription(
            provider_id=self.provider_id, kind=self.kind, description=self.config.description,
            operations=[
                SupportedOperation(name="discover", effect=Effect.READ, description="Namespaces, workloads, pods/owners, services/ingress, PVCs, role bindings, events.", limitations=["No Secret data, exec, port-forward or manifest application."]),
                SupportedOperation(name="kubernetes_events", effect=Effect.READ, description="Namespace events in a bounded window.", provider_side_filters=["namespace"], local_filters=["reason", "involved_object", "time_range"]),
                SupportedOperation(name="container_logs", effect=Effect.READ, description="Bounded current/previous container logs.", provider_side_filters=["namespace", "pod", "container", "tail_lines", "since_seconds", "previous"], local_filters=["grep"]),
                SupportedOperation(name="workload_inspect", effect=Effect.READ, description="Exact running identity, artifact, rollout and restart state."),
            ],
            required_credentials=[c for c in [self.config.credential] if c],
            credential_configured=bool(self.resolver and self.resolver.configured(self.config.credential)) or self._client is not None,
            scope_constraints={"context": self.config.context, "namespaces": self.config.namespaces or "all"},
            limitations=["Kubernetes events are best-effort and short-lived; they are not an audit log.", "EKS/control-plane audit logs are a separate source (CloudWatch)."],
        )

    async def check_availability(self, *, live: bool = False) -> Availability:
        configured = self._client is not None or bool(self.resolver and self.resolver.configured(self.config.credential))
        if not configured:
            return Availability(available=False, reason="credential_not_configured", detail=f"kubeconfig/context for {self.provider_id} not found")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        try:
            ident = await self.verified_identity()
            return Availability(available=True, identity=ident, checked_live=True)
        except OpsError as e:
            return Availability(available=False, reason=e.code.value, detail=e.message, checked_live=True)
        except Exception as e:  # noqa: BLE001
            return Availability(available=False, reason="provider_unavailable", detail=type(e).__name__, checked_live=True)

    # ---------------------------------------------------------------- discovery
    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id)
        try:
            ident = await self.verified_identity()
        except OpsError as e:
            report.unavailable.append({"source": self.provider_id, "reason": e.code.value, "detail": e.message})
            return report
        except Exception as e:  # noqa: BLE001
            report.unavailable.append({"source": self.provider_id, "reason": "provider_unavailable", "detail": type(e).__name__})
            return report
        report.identity = ident
        approved = bool(ident.get("approved"))
        if not approved:
            report.notes.append(f"{self.provider_id} has no approved cluster_identity/cluster_identity_file configured; live context is unverified, so no scope is marked complete in this scan")
        cid = self.cluster_identity_string()
        client = await self.client()
        requested = list(scope.namespaces)
        configured = list(self.config.namespaces)
        if requested and configured:
            namespaces = [n for n in requested if n in configured]
            for n in requested:
                if n not in configured:
                    report.unavailable.append({"source": f"{self.provider_id}/{cid}/{n}", "reason": "namespace_outside_configured_scope", "detail": f"namespace {n} is not in the provider's configured namespaces"})
        elif requested:
            namespaces = requested
        else:
            namespaces = configured
        if not namespaces:
            namespaces = [n["metadata"]["name"] for n in await client.list_namespaces()]
        for ns in namespaces:
            budget.check()
            ctx.check_cancel()
            try:
                workloads = await client.list_workloads(ns)
                pods = await client.list_pods(ns)
                services = await client.list_services(ns)
                ingresses = await client.list_ingresses(ns)
                pvcs = await client.list_pvcs(ns)
            except Exception as e:  # noqa: BLE001
                report.unavailable.append({"source": f"{self.provider_id}/{cid}/{ns}", "reason": _kube_reason(e), "detail": _kube_detail(e)})
                report.partial_scopes.append(f"{self.provider_id}/{cid}/{ns}")
                continue
            # RoleBindings are a separate comparable scope (D23): Kubernetes' built-in read-only `view` role
            # (e.g. EKS AmazonEKSViewPolicy) deliberately excludes RBAC objects, and that denial must not
            # discard the namespace's workloads, pods and services.
            rb_scope = f"{self.provider_id}/{cid}/{ns}/rolebindings"
            try:
                rbs = await client.list_rolebindings(ns)
                rbs_ok = True
            except Exception as e:  # noqa: BLE001
                report.unavailable.append({"source": rb_scope, "reason": _kube_reason(e), "detail": _kube_detail(e)})
                report.partial_scopes.append(rb_scope)
                rbs, rbs_ok = [], False
            eid = await ctx.store_evidence(self.provider_id, "kubernetes_namespace_snapshot", {"namespace": ns, "workloads": workloads, "pods": pods, "services": services, "ingresses": ingresses, "pvcs": pvcs, "rolebindings": rbs}, summary=f"namespace {ns}: {len(workloads)} workloads, {len(pods)} pods")
            scope_key = f"{self.provider_id}/{cid}/{ns}"
            for wl in workloads:
                md = wl["metadata"]
                containers = wl.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) if wl.get("kind") != "CronJob" else wl.get("spec", {}).get("job_template", {}).get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
                own_pods = [p for p in pods if _pod_belongs(p, wl)]
                running = []
                for p in own_pods:
                    for cs in (p.get("status", {}).get("container_statuses") or []):
                        running.append({"pod": p["metadata"]["name"], "container": cs.get("name"), "image": cs.get("image"), "image_id": cs.get("image_id", cs.get("imageID")), "ready": cs.get("ready"), "restart_count": cs.get("restart_count", cs.get("restartCount"))})
                report.observations.append(Observation(
                    provider_id=self.provider_id, resource_key=workload_key(cid, ns, wl["kind"], md["uid"]), resource_type=f"k8s/{wl['kind']}",
                    identity={"cluster_identity": cid, "namespace": ns, "kind": wl["kind"], "name": md["name"], "uid": md["uid"], "context": self.config.context},
                    attributes={"desired_images": [{"container": c["name"], "image": c.get("image"), **parse_image_ref(c.get("image", ""))} for c in containers], "running": running, "ownership": detect_ownership(wl), "rollout": rollout_state(wl), "labels": md.get("labels", {}), "annotations": {k: v for k, v in (md.get("annotations") or {}).items() if len(str(v)) < 300}, "pod_names": [p["metadata"]["name"] for p in own_pods], "creation_timestamp": str(md.get("creation_timestamp", md.get("creationTimestamp")))},
                    scope_key=scope_key, evidence_id=eid,
                ))
            for svc in services:
                md = svc["metadata"]
                sel = svc.get("spec", {}).get("selector") or {}
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"k8s:{cid}:{ns}:Service:{md['uid']}", resource_type="k8s/Service", identity={"cluster_identity": cid, "namespace": ns, "name": md["name"], "uid": md["uid"]}, attributes={"type": svc.get("spec", {}).get("type"), "selector": sel, "ports": svc.get("spec", {}).get("ports", []), "cluster_ip": svc.get("spec", {}).get("cluster_ip", svc.get("spec", {}).get("clusterIP")), "load_balancer": (svc.get("status", {}).get("load_balancer") or {}).get("ingress")}, scope_key=scope_key, evidence_id=eid, relationships=[{"kind": "serves", "target": f"selector:{json.dumps(sel, sort_keys=True)}"}]))
            for ing in ingresses:
                md = ing["metadata"]
                hosts = [r.get("host") for r in ing.get("spec", {}).get("rules", []) if r.get("host")]
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"k8s:{cid}:{ns}:Ingress:{md['uid']}", resource_type="k8s/Ingress", identity={"cluster_identity": cid, "namespace": ns, "name": md["name"], "uid": md["uid"]}, attributes={"hosts": hosts, "class": ing.get("spec", {}).get("ingress_class_name", ing.get("spec", {}).get("ingressClassName"))}, scope_key=scope_key, evidence_id=eid))
            for pvc in pvcs:
                md = pvc["metadata"]
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"k8s:{cid}:{ns}:PVC:{md['uid']}", resource_type="k8s/PersistentVolumeClaim", identity={"cluster_identity": cid, "namespace": ns, "name": md["name"], "uid": md["uid"]}, attributes={"storage_class": pvc.get("spec", {}).get("storage_class_name", pvc.get("spec", {}).get("storageClassName")), "capacity": (pvc.get("status", {}).get("capacity") or {}).get("storage"), "phase": pvc.get("status", {}).get("phase"), "volume_name": pvc.get("spec", {}).get("volume_name", pvc.get("spec", {}).get("volumeName"))}, scope_key=scope_key, evidence_id=eid))
            for rb in rbs:
                md = rb["metadata"]
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"k8s:{cid}:{ns}:RoleBinding:{md['uid']}", resource_type="k8s/RoleBinding", identity={"cluster_identity": cid, "namespace": ns, "name": md["name"], "uid": md["uid"]}, attributes={"role_ref": rb.get("role_ref", rb.get("roleRef")), "subjects": rb.get("subjects", [])}, scope_key=rb_scope, evidence_id=eid))
            (report.completed_scopes if approved else report.partial_scopes).append(scope_key)
            if rbs_ok:
                (report.completed_scopes if approved else report.partial_scopes).append(rb_scope)
        return report

    # ---------------------------------------------------------------- evidence queries
    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        qtype = query.get("query_type")
        client = await self.client()
        cov = Coverage(requested_sources=[self.provider_id])
        if qtype == "kubernetes_events":
            ns = query["scope"]["namespace"]
            since = utcnow() - timedelta(seconds=int(query.get("filters", {}).get("since_seconds", 3600)))
            events = await client.list_events(ns, since=since, limit=int(query.get("limits", {}).get("max_events", 200)))
            involved = query.get("filters", {}).get("involved_object")
            if involved:
                events = [e for e in events if involved in str(e.get("involved_object", e.get("involvedObject", {})).get("name", ""))]
                cov.filters_local.append("involved_object")
            eid = await ctx.store_evidence(self.provider_id, "kubernetes_events", events, summary=f"{len(events)} events in {ns}")
            cov.completed_scopes.append(f"{self.provider_id}/{ns}")
            cov.filters_provider_side.append("namespace")
            cov.source_retention_note = "Kubernetes events are retained briefly (typically 1h) and are not an audit source."
            items = [{"time": e.get("last_timestamp") or e.get("event_time") or e.get("first_timestamp"), "type": e.get("type"), "reason": e.get("reason"), "object": f"{(e.get('involved_object') or e.get('involvedObject') or {}).get('kind')}/{(e.get('involved_object') or e.get('involvedObject') or {}).get('name')}", "message": e.get("message"), "count": e.get("count")} for e in events]
            return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=[eid], query_description={"namespace": ns, "since": since.isoformat()})
        if qtype == "container_logs":
            sc = query["scope"]
            ns, pod, container = sc["namespace"], sc.get("pod"), sc.get("container")
            pods = [pod] if pod else []
            if not pods and sc.get("workload_name"):
                wl = await client.get_workload(sc.get("workload_kind", "Deployment"), ns, sc["workload_name"])
                if wl:
                    pods = [p["metadata"]["name"] for p in await client.list_pods(ns) if _pod_belongs(p, wl)]
            # `max_events` is the public evidence_query limit (one log line is one event); investigation recipes
            # call the adapter directly with `max_lines`. Either bounds the tail; the server cap always applies.
            limits = query.get("limits", {})
            tail = min(int(limits.get("max_lines") or limits.get("max_events") or 500), self.server.limits.max_log_lines)
            previous = bool(query.get("filters", {}).get("previous", False))
            grep = query.get("filters", {}).get("grep")
            items, eids = [], []
            for p in pods[: int(query.get("limits", {}).get("max_pods", 5))]:
                budget.check()
                text = await client.pod_logs(ns, p, container, tail, previous=previous, since_seconds=query.get("filters", {}).get("since_seconds"))
                lines = text.splitlines()
                if grep:
                    lines = [ln for ln in lines if grep in ln]
                    cov.filters_local.append("grep")
                eids.append(await ctx.store_evidence(self.provider_id, "container_logs", {"pod": p, "container": container, "previous": previous, "lines": lines}, summary=f"{len(lines)} lines from {p}{' (previous)' if previous else ''}"))
                items.append({"pod": p, "container": container, "previous": previous, "line_count": len(lines), "lines": lines[-tail:]})
            cov.completed_scopes.append(f"{self.provider_id}/{ns}/logs")
            cov.filters_provider_side += ["tail_lines", "since_seconds", "previous"]
            cov.truncated = any(int(str(i["line_count"])) >= tail for i in items)
            return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=eids, query_description={"namespace": ns, "pods": pods, "tail_lines": tail, "previous": previous})
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"kubernetes adapter does not support query_type {qtype!r}")

    async def inspect_workload(self, ctx: OperationContext, kind: str, ns: str, name: str) -> dict[str, Any]:
        client = await self.client()
        wl = await client.get_workload(kind, ns, name)
        if wl is None:
            return {"found": False, "kind": kind, "namespace": ns, "name": name}
        pods = [p for p in await client.list_pods(ns) if _pod_belongs(p, wl)]
        rs = []
        if kind == "Deployment":
            rs = [r for r in await client.list_replicasets(ns) if any(o.get("uid") == wl["metadata"]["uid"] for o in (r["metadata"].get("owner_references") or r["metadata"].get("ownerReferences") or []))]
        eid = await ctx.store_evidence(self.provider_id, "workload_inspect", {"workload": wl, "pods": pods, "replicasets": rs}, summary=f"{kind}/{name} in {ns}")
        containers = wl.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        running = []
        restarts = 0
        for p in pods:
            for cs in (p.get("status", {}).get("container_statuses") or []):
                restarts += int(cs.get("restart_count", cs.get("restartCount", 0)) or 0)
                state = cs.get("state") or {}
                running.append({"pod": p["metadata"]["name"], "pod_uid": p["metadata"]["uid"], "node": p.get("spec", {}).get("node_name", p.get("spec", {}).get("nodeName")), "container": cs.get("name"), "image": cs.get("image"), "image_id": cs.get("image_id", cs.get("imageID")), "ready": cs.get("ready"), "restart_count": cs.get("restart_count", cs.get("restartCount")), "state": next(iter(state.keys()), None), "state_detail": next(iter(state.values()), None), "last_state": cs.get("last_state", cs.get("lastState"))})
        return {
            "found": True, "kind": kind, "namespace": ns, "name": name, "uid": wl["metadata"]["uid"], "resource_version": wl["metadata"].get("resource_version", wl["metadata"].get("resourceVersion")),
            "generation": wl["metadata"].get("generation"), "desired_images": [{"container": c["name"], "image": c.get("image"), **parse_image_ref(c.get("image", ""))} for c in containers],
            "running": running, "total_restarts": restarts, "rollout": rollout_state(wl), "ownership": detect_ownership(wl), "annotations": {k: v for k, v in (wl["metadata"].get("annotations") or {}).items() if len(str(v)) < 300},
            "template_annotations": (wl.get("spec", {}).get("template", {}).get("metadata", {}) or {}).get("annotations", {}), "replicasets": [{"name": r["metadata"]["name"], "revision": (r["metadata"].get("annotations") or {}).get("deployment.kubernetes.io/revision"), "replicas": r.get("status", {}).get("replicas"), "images": [c.get("image") for c in r.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])], "created": str(r["metadata"].get("creation_timestamp", r["metadata"].get("creationTimestamp")))} for r in rs],
            "evidence_id": eid,
        }


def _pod_belongs(pod: dict[str, Any], workload: dict[str, Any]) -> bool:
    sel = (workload.get("spec", {}).get("selector") or {}).get("match_labels") or (workload.get("spec", {}).get("selector") or {}).get("matchLabels") or {}
    labels = pod.get("metadata", {}).get("labels") or {}
    if sel and all(labels.get(k) == v for k, v in sel.items()):
        return True
    if pod.get("metadata", {}).get("owner_name") == workload.get("metadata", {}).get("name"):
        return True
    return False
