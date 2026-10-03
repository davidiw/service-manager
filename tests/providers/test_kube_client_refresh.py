"""RealKubeClient's exec-token refresh and 401-retry choke point (`_ensure`/`_with_api`). All
kubernetes_asyncio symbols are monkeypatched; no network, no real cluster. See
`tests/providers/test_kubernetes.py` for the FakeKubeClient-level adapter tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from local_ops.models import ErrorCode, OpsError
from local_ops.providers.kube_client import RealKubeClient

VALID_EXEC_USER = {
    "exec": {
        "command": "aws",
        "args": ["eks", "get-token", "--cluster-name", "demo"],
        "env": [{"name": "AWS_PROFILE", "value": "mi-mainnet-ro"}],
    }
}
INVALID_EXEC_USER = {
    "exec": {
        "command": "aws",
        "args": ["eks", "get-token", "--cluster-name", "demo", "--role-arn", "arn:aws:iam::1:role/x"],
        "env": [{"name": "AWS_PROFILE", "value": "mi-mainnet-ro"}],
    }
}
ALLOWED_PROFILES = frozenset({"mi-mainnet-ro"})


class _FakeConfiguration:
    def __init__(self) -> None:
        self.host: str | None = None
        self.api_key: dict[str, str] = {}


class _FakeApiClient:
    def __init__(self, configuration: Any) -> None:
        self.configuration = configuration
        self.closed = False
        self.close_calls = 0

    async def close(self) -> None:
        self.closed = True
        self.close_calls += 1


class _FakeLoader:
    def __init__(self, user: dict[str, Any], expiry: datetime | None) -> None:
        self._user = user
        self._expiry = expiry

    async def load_and_set(self, cfg: Any) -> None:
        cfg.host = "https://fake.invalid"
        if self._expiry is not None:
            self.exec_plugin_expiry = self._expiry


def _install_fakes(monkeypatch: pytest.MonkeyPatch, *, users: list[dict[str, Any]], expiries: list[datetime | None], built_apis: list[_FakeApiClient], built_loaders: list[_FakeLoader]) -> None:
    """`users`/`expiries` are consumed one per loader build (last value repeats once exhausted), so a
    test can simulate a kubeconfig that changes across rebuilds."""

    def loader_factory(kubeconfig: str | None, active_context: str) -> _FakeLoader:
        idx = len(built_loaders)
        user = users[min(idx, len(users) - 1)]
        expiry = expiries[min(idx, len(expiries) - 1)]
        loader = _FakeLoader(user, expiry)
        built_loaders.append(loader)
        return loader

    def api_client_factory(configuration: Any) -> _FakeApiClient:
        api = _FakeApiClient(configuration)
        built_apis.append(api)
        return api

    monkeypatch.setattr("kubernetes_asyncio.config.kube_config._get_kube_config_loader_for_yaml_file", loader_factory)
    monkeypatch.setattr("kubernetes_asyncio.client.Configuration", _FakeConfiguration)
    monkeypatch.setattr("kubernetes_asyncio.client.ApiClient", api_client_factory)


def _install_core_v1_api(monkeypatch: pytest.MonkeyPatch, list_namespace_impl: Any) -> None:
    class _FakeCoreV1Api:
        def __init__(self, api: Any) -> None:
            self.api = api

        async def list_namespace(self) -> Any:
            return await list_namespace_impl()

    monkeypatch.setattr("kubernetes_asyncio.client.CoreV1Api", _FakeCoreV1Api)


class _Items:
    def __init__(self, items: list[Any]) -> None:
        self.items = items


async def _empty_namespaces() -> Any:
    return _Items([])


async def test_rebuilds_when_exec_token_is_already_past_its_reported_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    expired = datetime.now(UTC) - timedelta(seconds=5)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER], expiries=[expired], built_apis=built_apis, built_loaders=built_loaders)
    _install_core_v1_api(monkeypatch, _empty_namespaces)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    await kube.list_namespaces()
    assert len(built_loaders) == 1
    assert len(built_apis) == 1

    await kube.list_namespaces()
    # The reported expiry was already in the past (within the 60s skew), so the second call must
    # close the first client and rebuild through a fresh kubeconfig parse before issuing the request.
    assert len(built_loaders) == 2
    assert len(built_apis) == 2
    assert built_apis[0].closed is True


async def test_no_rebuild_when_exec_token_is_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    far_future = datetime.now(UTC) + timedelta(hours=1)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER], expiries=[far_future], built_apis=built_apis, built_loaders=built_loaders)
    _install_core_v1_api(monkeypatch, _empty_namespaces)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    await kube.list_namespaces()
    await kube.list_namespaces()
    assert len(built_loaders) == 1
    assert len(built_apis) == 1
    assert built_apis[0].closed is False


async def test_static_token_context_never_rebuilds_on_age(monkeypatch: pytest.MonkeyPatch) -> None:
    """A context with no exec plugin has no expiry to track; only an explicit 401 should force a
    rebuild, never the age rule."""
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    _install_fakes(monkeypatch, users=[{}], expiries=[None], built_apis=built_apis, built_loaders=built_loaders)
    _install_core_v1_api(monkeypatch, _empty_namespaces)

    kube = RealKubeClient(None, "c")
    # Pretend the client was configured long ago; with no exec plugin this must not matter.
    await kube.list_namespaces()
    kube._configured_at = datetime.now(UTC) - timedelta(hours=10)
    await kube.list_namespaces()
    assert len(built_loaders) == 1
    assert len(built_apis) == 1


async def test_401_is_retried_exactly_once_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    from kubernetes_asyncio.client.exceptions import ApiException

    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    far_future = datetime.now(UTC) + timedelta(hours=1)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER], expiries=[far_future], built_apis=built_apis, built_loaders=built_loaders)

    calls = {"count": 0}

    async def list_namespace() -> Any:
        calls["count"] += 1
        if calls["count"] == 1:
            raise ApiException(status=401, reason="Unauthorized")
        return _Items([])

    _install_core_v1_api(monkeypatch, list_namespace)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    result = await kube.list_namespaces()
    assert result == []
    assert calls["count"] == 2
    assert len(built_loaders) == 2  # one reset-and-rebuild after the 401
    assert built_apis[0].closed is True


async def test_401_does_not_retry_more_than_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second consecutive 401 (after the one allowed reset) propagates rather than looping forever."""
    from kubernetes_asyncio.client.exceptions import ApiException

    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    far_future = datetime.now(UTC) + timedelta(hours=1)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER], expiries=[far_future], built_apis=built_apis, built_loaders=built_loaders)

    calls = {"count": 0}

    async def list_namespace() -> Any:
        calls["count"] += 1
        raise ApiException(status=401, reason="Unauthorized")

    _install_core_v1_api(monkeypatch, list_namespace)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    with pytest.raises(ApiException):
        await kube.list_namespaces()
    assert calls["count"] == 2
    assert len(built_loaders) == 2


async def test_exec_shape_is_revalidated_on_a_token_driven_rebuild(monkeypatch: pytest.MonkeyPatch) -> None:
    """The kubeconfig on disk could have been swapped between the original connect and a later
    rebuild; the exec allowlist must still be enforced then, not only on the very first connect."""
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    already_expired = datetime.now(UTC) - timedelta(seconds=5)
    _install_fakes(
        monkeypatch,
        users=[VALID_EXEC_USER, INVALID_EXEC_USER],
        expiries=[already_expired, already_expired],
        built_apis=built_apis,
        built_loaders=built_loaders,
    )
    _install_core_v1_api(monkeypatch, _empty_namespaces)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    await kube.list_namespaces()  # first connect: valid exec shape, succeeds
    assert len(built_loaders) == 1

    with pytest.raises(OpsError) as e:
        await kube.list_namespaces()  # token already expired -> rebuild -> re-parses the (now invalid) kubeconfig
    assert e.value.code is ErrorCode.AUTH_REQUIRED
    assert "role-arn" in e.value.message


# ---------------------------------------------------------------- D30 review BLOCK 5: concurrent rebuild/reset


async def test_concurrent_call_during_a_rebuild_does_not_hit_a_closed_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rebuild triggered by one call must not close the client a different, still in-flight call is
    using; the retired client is only closed once that other call releases it."""
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    already_expired = datetime.now(UTC) - timedelta(seconds=5)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER, VALID_EXEC_USER], expiries=[already_expired, already_expired], built_apis=built_apis, built_loaders=built_loaders)

    in_flight = asyncio.Event()
    release = asyncio.Event()
    calls = {"n": 0}

    async def list_namespace() -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            in_flight.set()
            await release.wait()
        return _Items([])

    _install_core_v1_api(monkeypatch, list_namespace)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    task_a = asyncio.create_task(kube.list_namespaces())
    await in_flight.wait()
    assert len(built_apis) == 1  # client 1 built for call A, still in flight

    # Call A's token was already expired on build, so this second call must rebuild -- while call A is
    # still running against client 1.
    await kube.list_namespaces()
    assert len(built_apis) == 2
    assert built_apis[0].closed is False, "client 1 was closed while call A was still using it"

    release.set()
    await task_a
    assert built_apis[0].closed is True
    assert built_apis[0].close_calls == 1


async def test_concurrent_rebuild_requests_build_exactly_one_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two callers racing into `_acquire()` when a client must be built (no client yet, same as when a
    rebuild is due for an existing one) must not each build their own; the lock serializes the decision
    so only one new client is built."""
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    far_future = datetime.now(UTC) + timedelta(hours=1)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER], expiries=[far_future], built_apis=built_apis, built_loaders=built_loaders)
    _install_core_v1_api(monkeypatch, _empty_namespaces)

    # Give the build an actual suspension point so two concurrent `_acquire()` calls can genuinely
    # interleave instead of one running the whole build to completion before the other is scheduled.
    orig_load_and_set = _FakeLoader.load_and_set

    async def slow_load_and_set(self: _FakeLoader, cfg: Any) -> None:
        await asyncio.sleep(0)
        await orig_load_and_set(self, cfg)

    monkeypatch.setattr(_FakeLoader, "load_and_set", slow_load_and_set)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    await asyncio.gather(kube.list_namespaces(), kube.list_namespaces())
    assert len(built_loaders) == 1
    assert len(built_apis) == 1


async def test_retired_client_is_closed_exactly_once_under_concurrent_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two calls sharing a retired client must not each close it; the active count must reach zero
    exactly once, and `close()` must run exactly once even so."""
    built_apis: list[_FakeApiClient] = []
    built_loaders: list[_FakeLoader] = []
    far_future = datetime.now(UTC) + timedelta(hours=1)
    _install_fakes(monkeypatch, users=[VALID_EXEC_USER, VALID_EXEC_USER], expiries=[far_future, far_future], built_apis=built_apis, built_loaders=built_loaders)

    gate = asyncio.Event()
    both_in = asyncio.Event()
    calls = {"n": 0}

    async def list_namespace() -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            both_in.set()
        if calls["n"] <= 2:
            await gate.wait()
        return _Items([])

    _install_core_v1_api(monkeypatch, list_namespace)

    kube = RealKubeClient(None, "c", allow_exec_plugins=True, allowed_exec_profiles=ALLOWED_PROFILES)
    task1 = asyncio.create_task(kube.list_namespaces())
    task2 = asyncio.create_task(kube.list_namespaces())
    await both_in.wait()
    assert len(built_apis) == 1  # both calls share the one, still-fresh client

    # Force the next acquire to rebuild and retire client 1 while both calls above are still active
    # against it (active == 2).
    kube._exec_expiry = datetime.now(UTC) - timedelta(seconds=5)
    await kube.list_namespaces()
    assert len(built_apis) == 2
    assert built_apis[0].closed is False, "client 1 was closed while still active"

    gate.set()
    await asyncio.gather(task1, task2)
    assert built_apis[0].closed is True
    assert built_apis[0].close_calls == 1
