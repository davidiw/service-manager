"""Thin async Kubernetes client boundary.

`KubeClient` is the only surface the adapter and executors use, so tests can substitute `FakeKubeClient`
(see kube_fake.py). The real implementation wraps kubernetes_asyncio. Read surfaces never fetch Secret
data, never exec into pods and never port-forward. Mutations are limited to conditional strategic-merge
patches of a workload's pod template on an exact UID.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, TypeVar

from local_ops.models import ErrorCode, OpsError

T = TypeVar("T")

# EKS (and comparable exec-plugin) bearer tokens expire; the server runs far longer than one token's
# lifetime. Rebuild the client ahead of a known expiry, or after a bounded age when no expiry was
# reported, rather than letting every call 401. A static (non-exec) credential never expires this way.
EXEC_TOKEN_EXPIRY_SKEW = timedelta(seconds=60)
EXEC_TOKEN_MAX_AGE_WITHOUT_EXPIRY = timedelta(seconds=600)

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


@dataclass
class _TrackedClient:
    """One built `ApiClient` plus the bookkeeping needed to close it safely. D30 review BLOCK 5: the
    previous `_ensure()`/`_reset()` closed `self._api` and replaced it in place, with no coordination
    against calls already in flight against that same object (`_with_api` had already read `self._api`
    into a local `api` variable before awaiting the real request) -- a concurrent rebuild or 401-reset
    could close the client out from under another coroutine's in-flight call, and two concurrent rebuilds
    could each build and leak their own replacement. `active` is the count of calls currently running
    against `.api`; a retired client is only actually closed once that count drops to zero."""

    api: Any
    active: int = field(default=0)
    retired: bool = field(default=False)
    closed: bool = field(default=False)


class RealKubeClient:
    """kubernetes_asyncio-backed client bound to one kubeconfig context."""

    def __init__(self, kubeconfig: str | None, context: str, allow_exec_plugins: bool = False, allowed_exec_profiles: frozenset[str] = frozenset()):
        self.kubeconfig = kubeconfig
        self.context = context
        self.allow_exec_plugins = allow_exec_plugins
        self.allowed_exec_profiles = allowed_exec_profiles
        self._current: _TrackedClient | None = None
        # Serializes every rebuild/reset decision and the active-count bookkeeping below, so "is a
        # rebuild needed", "build it" and "swap it in" happen as one step no concurrent caller can
        # observe half-done (e.g. acquiring a reference to a tracked client after it has been retired
        # and closed, but before its `active` count was incremented).
        self._lock = asyncio.Lock()
        # Set on every (re)build; drives the rebuild decision in `_needs_rebuild`. None/False until the
        # first successful build.
        self._configured_at: datetime | None = None
        self._has_exec: bool = False
        self._exec_expiry: datetime | None = None

    def _needs_rebuild(self, now: datetime) -> bool:
        if not self._has_exec:
            # A static (non-exec) credential does not expire on its own; only an explicit 401 forces a
            # rebuild for those contexts.
            return False
        if self._exec_expiry is not None:
            return now >= self._exec_expiry - EXEC_TOKEN_EXPIRY_SKEW
        if self._configured_at is not None:
            return now - self._configured_at >= EXEC_TOKEN_MAX_AGE_WITHOUT_EXPIRY
        return False

    async def _build_api(self) -> Any:
        """Parse and validate the kubeconfig context and build one new `ApiClient`. Raises before
        touching any existing client, so a failed rebuild never tears down a still-usable one."""
        from kubernetes_asyncio import client
        from kubernetes_asyncio.config.kube_config import (
            KubeConfigLoader,
            _get_kube_config_loader_for_yaml_file,
        )

        from local_ops.providers.exec_policy import validate_exec_plugin

        loader: KubeConfigLoader = _get_kube_config_loader_for_yaml_file(self.kubeconfig, active_context=self.context)
        user = getattr(loader, "_user", None) or {}
        has_exec = "exec" in user
        if has_exec:
            # The loader's user is a ConfigNode (supports `in` and indexing, not `.get`).
            exec_cfg = user["exec"]
            if not self.allow_exec_plugins:
                command = exec_cfg["command"] if "command" in exec_cfg else None
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {self.context!r} uses an exec credential plugin; enable allow_exec_plugins only for trusted helpers", private_detail=str(command))
            # Re-validated on every connect (including every rebuild caused by token expiry/age/401), not
            # only at proposal time: the kubeconfig on disk could have been swapped since, and this also
            # applies to every human-configured context with allow_exec_plugins set, not only ones a
            # proposal added.
            validate_exec_plugin(exec_cfg, self.allowed_exec_profiles, context_name=self.context)
        if "auth-provider" in user:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {self.context!r} uses a legacy auth-provider; not supported")
        cfg = client.Configuration()
        # Configure from the same parsed loader that was validated above, never a second read of the file.
        await loader.load_and_set(cfg)
        api = client.ApiClient(configuration=cfg)
        self._configured_at = datetime.now(UTC)
        self._has_exec = has_exec
        self._exec_expiry = getattr(loader, "exec_plugin_expiry", None)
        return api

    async def _retire_locked(self, tracked: _TrackedClient) -> None:
        """Mark a tracked client retired and close it immediately if nothing is using it, under
        `self._lock`. Called both when swapping in a fresh client and from `_reset`."""
        tracked.retired = True
        if tracked.active == 0 and not tracked.closed:
            tracked.closed = True
            await tracked.api.close()

    async def _acquire(self) -> _TrackedClient:
        """Return the current tracked client with its active-call count already incremented, rebuilding
        first if needed. Deciding "needs rebuild", building, swapping in and incrementing all happen
        under one lock acquisition so no other coroutine can see (or close) the client in between."""
        async with self._lock:
            now = datetime.now(UTC)
            current = self._current
            if current is None or self._needs_rebuild(now):
                new_api = await self._build_api()
                current = _TrackedClient(new_api)
                old = self._current
                self._current = current
                if old is not None:
                    await self._retire_locked(old)
            current.active += 1
            return current

    async def _release(self, tracked: _TrackedClient) -> None:
        async with self._lock:
            tracked.active -= 1
            if tracked.retired and tracked.active == 0 and not tracked.closed:
                tracked.closed = True
                await tracked.api.close()

    async def _reset(self, tracked: _TrackedClient) -> None:
        """Retire a client that just produced a 401, so the next `_acquire()` is forced to rebuild from a
        fresh kubeconfig parse (re-validating the exec block). Used by the one-shot 401 retry in
        `_with_api`. Does not close `tracked` itself if it is still active (this very call) -- `_release`
        does that once the active count actually reaches zero."""
        async with self._lock:
            if self._current is tracked:
                self._current = None
            await self._retire_locked(tracked)

    async def _with_api(self, fn: Callable[[Any], Awaitable[T]]) -> T:
        """The one choke point for every real call: obtain a tracked client (rebuilding first if the
        exec token is near/past expiry or, lacking a reported expiry, old), and on an ApiException 401
        reset and retry the same call exactly once against a freshly rebuilt client. A second 401
        propagates -- never an unbounded retry loop."""
        from kubernetes_asyncio.client.exceptions import ApiException

        tracked = await self._acquire()
        try:
            return await fn(tracked.api)
        except ApiException as e:
            if e.status != 401:
                raise
            await self._reset(tracked)
        finally:
            await self._release(tracked)

        tracked2 = await self._acquire()
        try:
            return await fn(tracked2.api)
        finally:
            await self._release(tracked2)

    async def close(self) -> None:
        async with self._lock:
            if self._current is not None:
                await self._retire_locked(self._current)
                self._current = None

    async def cluster_identity(self) -> dict[str, Any]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> dict[str, Any]:
            core = client.CoreV1Api(api)
            ns = await core.read_namespace("kube-system")
            version = await client.VersionApi(api).get_code()
            return {"kube_system_uid": ns.metadata.uid, "server": api.configuration.host, "git_version": version.git_version, "context": self.context}

        return await self._with_api(call)

    async def list_namespaces(self) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            core = client.CoreV1Api(api)
            res = await core.list_namespace()
            return [_to_dict(i) for i in res.items]

        return await self._with_api(call)

    async def list_workloads(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            apps = client.AppsV1Api(api)
            batch = client.BatchV1Api(api)
            out: list[dict[str, Any]] = []
            for kind, fn in (
                ("Deployment", apps.list_namespaced_deployment),
                ("StatefulSet", apps.list_namespaced_stateful_set),
                ("DaemonSet", apps.list_namespaced_daemon_set),
                ("Job", batch.list_namespaced_job),
                ("CronJob", batch.list_namespaced_cron_job),
            ):
                res = await fn(namespace)
                for i in res.items:
                    d = _to_dict(i)
                    d["kind"] = kind
                    out.append(d)
            return out

        return await self._with_api(call)

    async def get_workload(self, kind: str, namespace: str, name: str) -> dict[str, Any] | None:
        from kubernetes_asyncio import client
        from kubernetes_asyncio.client.exceptions import ApiException

        async def call(api: Any) -> dict[str, Any] | None:
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

        return await self._with_api(call)

    async def list_pods(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            core = client.CoreV1Api(api)
            res = await (core.list_namespaced_pod(namespace, label_selector=label_selector) if label_selector else core.list_namespaced_pod(namespace))
            return [_to_dict(i) for i in res.items]

        return await self._with_api(call)

    async def list_events(self, namespace: str, since: datetime | None = None, limit: int = 200) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            core = client.CoreV1Api(api)
            res = await core.list_namespaced_event(namespace, limit=limit)
            return [_to_dict(i) for i in res.items]

        items = await self._with_api(call)
        if since:
            def ts(e: dict[str, Any]) -> str:
                return str(e.get("last_timestamp") or e.get("event_time") or e.get("first_timestamp") or "")
            items = [e for e in items if ts(e) >= since.isoformat()]
        return items

    async def list_services(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            core = client.CoreV1Api(api)
            return [_to_dict(i) for i in (await core.list_namespaced_service(namespace)).items]

        return await self._with_api(call)

    async def list_ingresses(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            net = client.NetworkingV1Api(api)
            return [_to_dict(i) for i in (await net.list_namespaced_ingress(namespace)).items]

        return await self._with_api(call)

    async def list_pvcs(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            core = client.CoreV1Api(api)
            return [_to_dict(i) for i in (await core.list_namespaced_persistent_volume_claim(namespace)).items]

        return await self._with_api(call)

    async def list_rolebindings(self, namespace: str) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            rbac = client.RbacAuthorizationV1Api(api)
            return [_to_dict(i) for i in (await rbac.list_namespaced_role_binding(namespace)).items]

        return await self._with_api(call)

    async def list_replicasets(self, namespace: str, label_selector: str | None = None) -> list[dict[str, Any]]:
        from kubernetes_asyncio import client

        async def call(api: Any) -> list[dict[str, Any]]:
            apps = client.AppsV1Api(api)
            res = await (apps.list_namespaced_replica_set(namespace, label_selector=label_selector) if label_selector else apps.list_namespaced_replica_set(namespace))
            return [_to_dict(i) for i in res.items]

        return await self._with_api(call)

    async def pod_logs(self, namespace: str, pod: str, container: str | None, tail_lines: int, previous: bool = False, since_seconds: int | None = None) -> str:
        from kubernetes_asyncio import client
        from kubernetes_asyncio.client.exceptions import ApiException

        async def call(api: Any) -> str:
            core = client.CoreV1Api(api)
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

        return await self._with_api(call)

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

        async def call(api: Any) -> dict[str, Any]:
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

        return await self._with_api(call)
