"""Thin async Kubernetes client boundary.

`KubeClient` is the only surface the adapter and executors use, so tests can substitute `FakeKubeClient`
(see kube_fake.py). The real implementation wraps kubernetes_asyncio. Read surfaces never fetch Secret
data, never exec into pods and never port-forward. Mutations are limited to conditional strategic-merge
patches of a workload's pod template on an exact UID.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Protocol

from local_ops.models import ErrorCode, OpsError

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")


class KubeConflict(Exception):
    """Raised when a conditional patch is rejected because the target changed."""


class KubeClient(Protocol):
    async def cluster_identity(self) -> dict[str, Any]: ...
    async def list_namespaces(self) -> list[dict[str, Any]]: ...
    async def list_workloads(self, namespace: str) -> list[dict[str, Any]]: ...
    async def get_workload(self, kind: str, namespace: str, name: str) -> dict[str, Any] | None: ...
    async def list_pods(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]: ...
    async def list_events(self, namespace: str, since: datetime | None = None, limit: int = 200) -> list[dict[str, Any]]: ...
    async def list_services(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_ingresses(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_pvcs(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_rolebindings(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_replicasets(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]: ...
    async def pod_logs(self, namespace: str, pod: str, container: str | None, tail_lines: int, previous: bool = False, since_seconds: int | None = None) -> str: ...
    async def patch_workload(self, kind: str, namespace: str, name: str, patch: dict[str, Any], *, expected_uid: str, expected_resource_version: str | None) -> dict[str, Any]: ...
    async def close(self) -> None: ...


def _strip_managed_fields(obj: dict[str, Any]) -> dict[str, Any]:
    md = obj.get("metadata") or {}
    md.pop("managed_fields", None)
    md.pop("managedFields", None)
    return obj


def _to_dict(model: Any) -> dict[str, Any]:
    d = model.to_dict() if hasattr(model, "to_dict") else dict(model)
    return _strip_managed_fields(_drop_none(d))


def _drop_none(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _drop_none(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [_drop_none(x) for x in v]
    return v


class RealKubeClient:
    """kubernetes_asyncio-backed client bound to one kubeconfig context."""

    def __init__(self, kubeconfig: str | None, context: str, allow_exec_plugins: bool = False, allowed_exec_profiles: frozenset[str] = frozenset()):
        self.kubeconfig = kubeconfig
        self.context = context
        self.allow_exec_plugins = allow_exec_plugins
        self.allowed_exec_profiles = allowed_exec_profiles
        self._api: Any = None

    async def _ensure(self) -> Any:
        if self._api is not None:
            return self._api
        from kubernetes_asyncio import client
        from kubernetes_asyncio.config.kube_config import (
            KubeConfigLoader,
            _get_kube_config_loader_for_yaml_file,
        )

        from local_ops.providers.exec_policy import validate_exec_plugin

        loader: KubeConfigLoader = _get_kube_config_loader_for_yaml_file(self.kubeconfig, active_context=self.context)
        user = getattr(loader, "_user", None) or {}
        if "exec" in user:
            # The loader's user is a ConfigNode (supports `in` and indexing, not `.get`).
            exec_cfg = user["exec"]
            if not self.allow_exec_plugins:
                command = exec_cfg["command"] if "command" in exec_cfg else None
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {self.context!r} uses an exec credential plugin; enable allow_exec_plugins only for trusted helpers", private_detail=str(command))
            # Re-validated on every connect, not only at proposal time: the kubeconfig on disk could
            # have been swapped since, and this also applies to every human-configured context with
            # allow_exec_plugins set, not only ones a proposal added.
            validate_exec_plugin(exec_cfg, self.allowed_exec_profiles, context_name=self.context)
        if "auth-provider" in user:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {self.context!r} uses a legacy auth-provider; not supported")
        cfg = client.Configuration()
        # Configure from the same parsed loader that was validated above, never a second read of the file.
        await loader.load_and_set(cfg)
        self._api = client.ApiClient(configuration=cfg)
        return self._api

    async def close(self) -> None:
        if self._api is not None:
            await self._api.close()
            self._api = None

    async def cluster_identity(self) -> dict[str, Any]:
        from kubernetes_asyncio import client

        api = await self._ensure()
        core = client.CoreV1Api(api)
        ns = await core.read_namespace("kube-system")
        version = await client.VersionApi(api).get_code()
        return {"kube_system_uid": ns.metadata.uid, "server": api.configuration.host, "git_version": version.git_version, "context": self.context}

    async def list_namespaces(self) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        core = client.CoreV1Api(await self._ensure())
        res = await core.list_namespace()
        return [_to_dict(i) for i in res.items]

    async def list_workloads(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        api = await self._ensure()
        apps = client.AppsV1Api(api)
        batch = client.BatchV1Api(api)
        out: list[dict[str, Any]] = []
        for kind, call in (
            ("Deployment", apps.list_namespaced_deployment),
            ("StatefulSet", apps.list_namespaced_stateful_set),
            ("DaemonSet", apps.list_namespaced_daemon_set),
            ("Job", batch.list_namespaced_job),
            ("CronJob", batch.list_namespaced_cron_job),
        ):
            res = await call(namespace)
            for i in res.items:
                d = _to_dict(i)
                d["kind"] = kind
                out.append(d)
        return out

    async def get_workload(self, kind: str, namespace: str, name: str) -> dict[str, Any] | None:
        from kubernetes_asyncio import client
        from kubernetes_asyncio.client.exceptions import ApiException

        api = await self._ensure()
        apps = client.AppsV1Api(api)
        batch = client.BatchV1Api(api)
        readers = {
            "Deployment": apps.read_namespaced_deployment,
            "StatefulSet": apps.read_namespaced_stateful_set,
            "DaemonSet": apps.read_namespaced_daemon_set,
            "Job": batch.read_namespaced_job,
            "CronJob": batch.read_namespaced_cron_job,
        }
        try:
            obj = await readers[kind](name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise
        d = _to_dict(obj)
        d["kind"] = kind
        return d

    async def list_pods(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        core = client.CoreV1Api(await self._ensure())
        res = await (core.list_namespaced_pod(namespace, label_selector=label_selector) if label_selector else core.list_namespaced_pod(namespace))
        return [_to_dict(i) for i in res.items]

    async def list_events(self, namespace: str, since: datetime | None = None, limit: int = 200) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        core = client.CoreV1Api(await self._ensure())
        res = await core.list_namespaced_event(namespace, limit=limit)
        items = [_to_dict(i) for i in res.items]
        if since:
            def ts(e: dict[str, Any]) -> str:
                return str(e.get("last_timestamp") or e.get("event_time") or e.get("first_timestamp") or "")
            items = [e for e in items if ts(e) >= since.isoformat()]
        return items

    async def list_services(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        core = client.CoreV1Api(await self._ensure())
        return [_to_dict(i) for i in (await core.list_namespaced_service(namespace)).items]

    async def list_ingresses(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        net = client.NetworkingV1Api(await self._ensure())
        return [_to_dict(i) for i in (await net.list_namespaced_ingress(namespace)).items]

    async def list_pvcs(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        core = client.CoreV1Api(await self._ensure())
        return [_to_dict(i) for i in (await core.list_namespaced_persistent_volume_claim(namespace)).items]

    async def list_rolebindings(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        rbac = client.RbacAuthorizationV1Api(await self._ensure())
        return [_to_dict(i) for i in (await rbac.list_namespaced_role_binding(namespace)).items]

    async def list_replicasets(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        apps = client.AppsV1Api(await self._ensure())
        res = await (apps.list_namespaced_replica_set(namespace, label_selector=label_selector) if label_selector else apps.list_namespaced_replica_set(namespace))
        return [_to_dict(i) for i in res.items]

    async def pod_logs(self, namespace: str, pod: str, container: str | None, tail_lines: int, previous: bool = False, since_seconds: int | None = None) -> str:
        from kubernetes_asyncio import client
        from kubernetes_asyncio.client.exceptions import ApiException

        core = client.CoreV1Api(await self._ensure())
        kwargs: dict[str, Any] = {"tail_lines": tail_lines, "previous": previous}
        if container:
            kwargs["container"] = container
        if since_seconds:
            kwargs["since_seconds"] = since_seconds
        try:
            return await core.read_namespaced_pod_log(pod, namespace, **kwargs)
        except ApiException as e:
            if e.status == 400 and previous:
                return ""
            raise

    async def patch_workload(self, kind: str, namespace: str, name: str, patch: dict[str, Any], *, expected_uid: str, expected_resource_version: str | None) -> dict[str, Any]:
        from kubernetes_asyncio import client
        from kubernetes_asyncio.client.exceptions import ApiException

        current = await self.get_workload(kind, namespace, name)
        if current is None or current["metadata"]["uid"] != expected_uid:
            raise KubeConflict("target workload was recreated or removed")
        body = json.loads(json.dumps(patch))
        body.setdefault("metadata", {})
        if expected_resource_version:
            body["metadata"]["resourceVersion"] = expected_resource_version  # server rejects with 409 on mismatch
        body["metadata"]["uid"] = expected_uid
        api = await self._ensure()
        apps = client.AppsV1Api(api)
        patchers = {"Deployment": apps.patch_namespaced_deployment, "StatefulSet": apps.patch_namespaced_stateful_set, "DaemonSet": apps.patch_namespaced_daemon_set}
        if kind not in patchers:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"{kind} is not patchable by this executor")
        try:
            obj = await patchers[kind](name, namespace, body, _content_type="application/strategic-merge-patch+json")  # type: ignore[call-arg]
        except ApiException as e:
            if e.status == 409:
                raise KubeConflict(f"conflict patching {kind}/{name}: {e.reason}") from e
            raise
        d = _to_dict(obj)
        d["kind"] = kind
        return d
