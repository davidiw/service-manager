"""In-memory fake Kubernetes cluster implementing the KubeClient boundary.

Behaves enough like a real cluster for executor and adapter tests: rollout restart annotation and image
patches bump generation, replicasets/pods converge after `converge()` or automatically with
`auto_converge`; failure modes simulate crash-looping pods and refused patches."""

from __future__ import annotations

import asyncio
import copy
import secrets
from datetime import datetime
from typing import Any

from local_ops.models import iso, utcnow
from local_ops.providers.kube_client import KubeConflict


def _uid() -> str:
    return "uid-" + secrets.token_hex(6)


class FakeKubeClient:
    def __init__(self, identity: dict[str, Any] | None = None, *, auto_converge: bool = True, converge_delay: float = 0.0):
        self.identity = identity or {"kube_system_uid": "fake-kube-system-uid", "server": "https://fake.invalid:6443", "git_version": "v1.fake", "context": "fake"}
        self.namespaces: dict[str, dict[str, Any]] = {"default": {"metadata": {"name": "default", "uid": _uid()}}, "kube-system": {"metadata": {"name": "kube-system", "uid": self.identity["kube_system_uid"]}}}
        self.workloads: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.pods: dict[str, list[dict[str, Any]]] = {}
        self.events: dict[str, list[dict[str, Any]]] = {}
        self.services: dict[str, list[dict[str, Any]]] = {}
        self.ingresses: dict[str, list[dict[str, Any]]] = {}
        self.pvcs: dict[str, list[dict[str, Any]]] = {}
        self.rolebindings: dict[str, list[dict[str, Any]]] = {}
        self.replicasets: dict[str, list[dict[str, Any]]] = {}
        self.logs: dict[tuple[str, str, bool], str] = {}
        self.auto_converge = auto_converge
        self.converge_delay = converge_delay
        self.fail_rollout_for_images: set[str] = set()
        self.refuse_patches = False
        self.patch_log: list[dict[str, Any]] = []
        self.crash_after_patch: bool = False
        self.crash_before_patch: bool = False
        self.closed = False
        self.calls: list[str] = []
        self._fail_after_patch: tuple[str, BaseException] | None = None
        self._armed: tuple[str, BaseException] | None = None

    def fail_once_after_next_patch(self, method: str, exc: BaseException) -> None:
        """Fault injection targeted at the first call to `method` (e.g. "get_workload", "list_pods")
        occurring after the *next* successful patch_workload -- i.e. a verification-stage failure after a
        mutation was already dispatched and accepted, regardless of how many pre-dispatch reads (prepare,
        the staleness re-read) already happened. Fires once, then behaves normally again."""
        self._fail_after_patch = (method, exc)

    def _maybe_raise(self, method: str) -> None:
        if self._armed is not None and self._armed[0] == method:
            exc = self._armed[1]
            self._armed = None
            raise exc

    # ------------------------------------------------------------- setup helpers
    def add_namespace(self, name: str) -> None:
        self.namespaces.setdefault(name, {"metadata": {"name": name, "uid": _uid()}})

    def add_deployment(self, namespace: str, name: str, image: str, *, container: str = "app", replicas: int = 1, labels: dict[str, str] | None = None, annotations: dict[str, str] | None = None, image_id: str | None = None) -> dict[str, Any]:
        self.add_namespace(namespace)
        labels = labels or {"app": name}
        wl = {
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace, "uid": _uid(), "generation": 1, "resource_version": "1", "labels": labels, "annotations": annotations or {}, "creation_timestamp": iso(utcnow())},
            "spec": {"replicas": replicas, "selector": {"match_labels": labels}, "template": {"metadata": {"labels": labels, "annotations": {}}, "spec": {"containers": [{"name": container, "image": image}]}}},
            "status": {"observed_generation": 1, "replicas": replicas, "ready_replicas": replicas, "updated_replicas": replicas, "available_replicas": replicas, "conditions": [{"type": "Available", "status": "True"}]},
        }
        self.workloads[("Deployment", namespace, name)] = wl
        self._materialize(wl, image_id=image_id)
        return wl

    def _materialize(self, wl: dict[str, Any], image_id: str | None = None) -> None:
        ns = wl["metadata"]["namespace"]
        name = wl["metadata"]["name"]
        labels = wl["spec"]["template"]["metadata"]["labels"]
        containers = wl["spec"]["template"]["spec"]["containers"]
        rs_hash = secrets.token_hex(3)
        self.pods[ns] = [p for p in self.pods.get(ns, []) if not (p["metadata"].get("labels") == labels and p["metadata"].get("owner_name") == name)]
        for i in range(wl["spec"]["replicas"]):
            pod = {
                "metadata": {"name": f"{name}-{rs_hash}-{secrets.token_hex(2)}", "namespace": ns, "uid": _uid(), "labels": labels, "owner_name": name, "owner_references": [{"kind": "ReplicaSet", "name": f"{name}-{rs_hash}", "uid": _uid()}], "creation_timestamp": iso(utcnow())},
                "spec": {"containers": [{"name": c["name"], "image": c["image"]} for c in containers], "node_name": f"node-{i}"},
                "status": {"phase": "Running", "container_statuses": [{"name": c["name"], "image": c["image"], "image_id": image_id or f"docker-pullable://{c['image'].split(':')[0]}@sha256:{secrets.token_hex(32)}", "ready": True, "restart_count": 0, "state": {"running": {"started_at": iso(utcnow())}}} for c in containers]},
            }
            self.pods[ns].append(pod)
        self.replicasets.setdefault(ns, []).append({"metadata": {"name": f"{name}-{rs_hash}", "namespace": ns, "uid": _uid(), "labels": labels, "owner_references": [{"kind": "Deployment", "name": name, "uid": wl["metadata"]["uid"]}], "annotations": {"deployment.kubernetes.io/revision": str(wl["metadata"]["generation"])}, "creation_timestamp": iso(utcnow())}, "spec": {"replicas": wl["spec"]["replicas"], "template": copy.deepcopy(wl["spec"]["template"])}, "status": {"replicas": wl["spec"]["replicas"], "ready_replicas": wl["spec"]["replicas"]}})
        wl["status"].update({"observed_generation": wl["metadata"]["generation"], "ready_replicas": wl["spec"]["replicas"], "updated_replicas": wl["spec"]["replicas"], "available_replicas": wl["spec"]["replicas"], "replicas": wl["spec"]["replicas"]})

    def set_logs(self, namespace: str, pod: str, text: str, previous: bool = False) -> None:
        self.logs[(namespace, pod, previous)] = text

    def add_event(self, namespace: str, reason: str, message: str, involved: str, kind: str = "Warning") -> None:
        self.events.setdefault(namespace, []).append({"metadata": {"name": f"ev-{secrets.token_hex(3)}", "namespace": namespace}, "reason": reason, "message": message, "type": kind, "involved_object": {"kind": "Pod", "name": involved, "namespace": namespace}, "last_timestamp": iso(utcnow()), "count": 1})

    def make_crashlooping(self, namespace: str, name: str) -> None:
        for p in self.pods.get(namespace, []):
            if p["metadata"].get("owner_name") == name:
                p["status"]["phase"] = "Running"
                for cs in p["status"]["container_statuses"]:
                    cs["ready"] = False
                    cs["restart_count"] = 7
                    cs["state"] = {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}}
                    cs["last_state"] = {"terminated": {"reason": "Error", "exit_code": 1}}
                self.add_event(namespace, "BackOff", "Back-off restarting failed container", p["metadata"]["name"])
        wl = self.workloads[("Deployment", namespace, name)]
        wl["status"]["ready_replicas"] = 0
        wl["status"]["available_replicas"] = 0

    # ------------------------------------------------------------- convergence
    async def converge(self, kind: str, namespace: str, name: str, *, fail: bool = False) -> None:
        wl = self.workloads[(kind, namespace, name)]
        if self.converge_delay:
            await asyncio.sleep(self.converge_delay)
        if fail:
            self._materialize(wl)
            self.make_crashlooping(namespace, name)
            wl["status"]["observed_generation"] = wl["metadata"]["generation"]
            wl["status"]["updated_replicas"] = wl["spec"]["replicas"]
            return
        self._materialize(wl)

    # ------------------------------------------------------------- KubeClient
    async def cluster_identity(self) -> dict[str, Any]:
        self.calls.append("cluster_identity")
        return dict(self.identity)

    async def list_namespaces(self) -> list[dict[str, Any]]:
        return [copy.deepcopy(v) for v in self.namespaces.values()]

    async def list_workloads(self, namespace: str) -> list[dict[str, Any]]:
        self.calls.append(f"list_workloads:{namespace}")
        return [copy.deepcopy(w) for (k, ns, n), w in self.workloads.items() if ns == namespace]

    async def get_workload(self, kind: str, namespace: str, name: str) -> dict[str, Any] | None:
        self._maybe_raise("get_workload")
        self.calls.append(f"get_workload:{kind}/{namespace}/{name}")
        w = self.workloads.get((kind, namespace, name))
        return copy.deepcopy(w) if w else None

    async def list_pods(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        self._maybe_raise("list_pods")
        pods = self.pods.get(namespace, [])
        if label_selector:
            want = dict(kv.split("=", 1) for kv in label_selector.split(","))
            pods = [p for p in pods if all(p["metadata"].get("labels", {}).get(k) == v for k, v in want.items())]
        return copy.deepcopy(pods)

    async def list_events(self, namespace: str, since: datetime | None = None, limit: int = 200) -> list[dict[str, Any]]:
        return copy.deepcopy(self.events.get(namespace, [])[-limit:])

    async def list_services(self, namespace: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.services.get(namespace, []))

    async def list_ingresses(self, namespace: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.ingresses.get(namespace, []))

    async def list_pvcs(self, namespace: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.pvcs.get(namespace, []))

    async def list_rolebindings(self, namespace: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self.rolebindings.get(namespace, []))

    async def list_replicasets(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        return copy.deepcopy(self.replicasets.get(namespace, []))

    async def pod_logs(self, namespace: str, pod: str, container: str | None, tail_lines: int, previous: bool = False, since_seconds: int | None = None) -> str:
        text = self.logs.get((namespace, pod, previous), "" if previous else f"{pod} log line 1\n{pod} log line 2\n")
        lines = text.splitlines()
        return "\n".join(lines[-tail_lines:])

    async def patch_workload(self, kind: str, namespace: str, name: str, patch: dict[str, Any], *, expected_uid: str, expected_resource_version: str | None) -> dict[str, Any]:
        self.calls.append(f"patch_workload:{kind}/{namespace}/{name}")
        wl = self.workloads.get((kind, namespace, name))
        if wl is None or wl["metadata"]["uid"] != expected_uid:
            raise KubeConflict("target workload was recreated or removed")
        if expected_resource_version and wl["metadata"]["resource_version"] != expected_resource_version:
            raise KubeConflict("resourceVersion conflict")
        if self.refuse_patches:
            raise RuntimeError("simulated API server failure")
        if self.crash_before_patch:
            # Connection dropped before the request reached (or was applied by) the server: whether it
            # was ever received is unknown, not "definitely not applied".
            raise ConnectionResetError("simulated connection loss before the patch was accepted")
        self.patch_log.append({"kind": kind, "namespace": namespace, "name": name, "patch": copy.deepcopy(patch)})
        if self._fail_after_patch is not None:
            self._armed, self._fail_after_patch = self._fail_after_patch, None
        tmpl = patch.get("spec", {}).get("template", {})
        ann = tmpl.get("metadata", {}).get("annotations")
        if ann:
            wl["spec"]["template"]["metadata"].setdefault("annotations", {}).update(ann)
        for c in tmpl.get("spec", {}).get("containers", []):
            for existing in wl["spec"]["template"]["spec"]["containers"]:
                if existing["name"] == c["name"] and "image" in c:
                    existing["image"] = c["image"]
        wl["metadata"]["generation"] += 1
        wl["metadata"]["resource_version"] = str(int(wl["metadata"]["resource_version"]) + 1)
        wl["status"]["observed_generation"] = wl["metadata"]["generation"] - 1
        wl["status"]["updated_replicas"] = 0
        if self.crash_after_patch:
            raise ConnectionResetError("simulated connection loss after patch was accepted")
        if self.auto_converge:
            images = [c["image"] for c in wl["spec"]["template"]["spec"]["containers"]]
            fail = any(img in self.fail_rollout_for_images for img in images)
            asyncio.get_running_loop().create_task(self.converge(kind, namespace, name, fail=fail))
        return copy.deepcopy(wl)

    async def close(self) -> None:
        self.closed = True
