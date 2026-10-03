"""Kubernetes adapter tests against the in-memory FakeKubeClient. No network, no real cluster."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.kube_fake import FakeKubeClient
from local_ops.providers.kubernetes import KubernetesAdapter
from local_ops.release import Sanitizer
from local_ops.storage import Database

UID = "fake-kube-system-uid-0001"


def make_config(**over: Any) -> ProviderConfig:
    base: dict[str, Any] = {"id": "kube-a", "kind": "kubernetes", "context": "fake", "credential": None}
    base.update(over)
    return ProviderConfig.model_validate(base)


def adapter(client: FakeKubeClient, **over: Any) -> KubernetesAdapter:
    return KubernetesAdapter(make_config(**over), ServerConfig(), None, client=client)


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[OperationContext]:
    db = Database(tmp_path / "state" / "db.sqlite", tmp_path / "state" / "evidence")
    await db.open()
    cat = tmp_path / "catalog"
    (cat / "services").mkdir(parents=True)
    (cat / "catalog.yaml").write_text("name: t\n", encoding="utf-8")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    c = OperationContext(db=db, config=ServerConfig(), catalog=load_catalog(cat), providers=ProviderRegistry(), sanitizer=Sanitizer(), principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)
    yield c
    await db.close()


def _client() -> FakeKubeClient:
    return FakeKubeClient(identity={"kube_system_uid": UID, "server": "https://fake.invalid", "git_version": "v1.fake", "context": "fake"})


async def test_scope_key_includes_cluster_identity(ctx: OperationContext) -> None:
    client = _client()
    client.add_deployment("demo", "app", "repo:v1")
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo"])
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.completed_scopes == [f"kube-a/{UID}/demo", f"kube-a/{UID}/demo/rolebindings"]
    wl = next(o for o in report.observations if o.resource_type == "k8s/Deployment")
    assert wl.scope_key == f"kube-a/{UID}/demo"


async def test_cluster_identity_change_yields_different_scope_key(ctx: OperationContext) -> None:
    client = _client()
    client.add_deployment("demo", "app", "repo:v1")
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo"])
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)

    other_uid = "fake-kube-system-uid-0002"
    client2 = FakeKubeClient(identity={"kube_system_uid": other_uid, "server": "https://fake.invalid", "git_version": "v1.fake", "context": "fake"})
    client2.add_deployment("demo", "app", "repo:v1")
    ad2 = adapter(client2, cluster_identity={"kube_system_uid": other_uid}, namespaces=["demo"])
    report2 = await ad2.discover(ctx, DiscoveryScope(), ctx.budget)

    assert set(report.completed_scopes).isdisjoint(report2.completed_scopes)


async def test_unverified_identity_completes_no_scope(ctx: OperationContext) -> None:
    client = _client()
    client.add_deployment("demo", "app", "repo:v1")
    ad = adapter(client, namespaces=["demo"])  # no cluster_identity/cluster_identity_file configured
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.completed_scopes == []
    assert report.partial_scopes
    assert any("unverified" in n for n in report.notes)


async def test_namespace_outside_configured_scope_is_refused(ctx: OperationContext) -> None:
    client = _client()
    client.add_deployment("demo", "app", "repo:v1")
    client.add_deployment("other", "app2", "repo:v1")
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo"])
    report = await ad.discover(ctx, DiscoveryScope(namespaces=["demo", "other"]), ctx.budget)
    assert not any(o.identity.get("namespace") == "other" for o in report.observations)
    refused = [u for u in report.unavailable if u["reason"] == "namespace_outside_configured_scope"]
    assert refused and refused[0]["source"] == f"kube-a/{UID}/other"


async def test_requested_namespace_within_configured_scope_is_honored(ctx: OperationContext) -> None:
    client = _client()
    client.add_deployment("demo", "app", "repo:v1")
    client.add_deployment("staging", "app2", "repo:v1")
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo", "staging"])
    report = await ad.discover(ctx, DiscoveryScope(namespaces=["demo"]), ctx.budget)
    namespaces_seen = {o.identity.get("namespace") for o in report.observations if o.resource_type == "k8s/Deployment"}
    assert namespaces_seen == {"demo"}


async def test_approved_identity_without_uid_verifies_nothing(ctx: OperationContext) -> None:
    """An approved identity with no kube_system_uid compares nothing, so it must not count as verified."""
    from local_ops.models import OpsError

    ad = adapter(_client(), cluster_identity={"server": "https://fake.invalid"}, namespaces=["demo"])
    with pytest.raises(OpsError):
        await ad.verified_identity()


async def test_forbidden_rolebindings_do_not_discard_namespace_workloads(ctx: OperationContext) -> None:
    from kubernetes_asyncio.client.exceptions import ApiException

    client = _client()
    client.add_deployment("demo", "app", "repo:v1")

    async def forbidden(namespace: str) -> list[dict[str, Any]]:
        raise ApiException(status=403, reason="Forbidden")

    client.list_rolebindings = forbidden  # type: ignore[method-assign]
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo"])
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert f"kube-a/{UID}/demo" in report.completed_scopes
    assert f"kube-a/{UID}/demo/rolebindings" in report.partial_scopes
    assert [o.resource_type for o in report.observations] == ["k8s/Deployment"]
    assert report.unavailable == [{"source": f"kube-a/{UID}/demo/rolebindings", "reason": "permission_denied", "detail": "ApiException 403 Forbidden"}]


async def test_container_logs_honor_public_max_events_limit(ctx: OperationContext) -> None:
    client = _client()
    client.set_logs("demo", "app-0", "\n".join(f"line {i}" for i in range(100)))
    ad = adapter(client, cluster_identity={"kube_system_uid": UID}, namespaces=["demo"])
    res = await ad.query(ctx, {"query_type": "container_logs", "scope": {"namespace": "demo", "pod": "app-0"}, "filters": {}, "limits": {"max_events": 20, "max_pages": 20, "max_duration_seconds": 120, "max_bytes": 2_000_000}}, ctx.budget)
    assert res.query_description["tail_lines"] == 20
    assert res.items[0]["lines"] == [f"line {i}" for i in range(80, 100)]


async def test_exec_plugin_context_without_opt_in_is_auth_required_not_a_crash(tmp_path: Path) -> None:
    from local_ops.models import ErrorCode, OpsError
    from local_ops.providers.kube_client import RealKubeClient

    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: c\n"
        "clusters: [{name: k, cluster: {server: 'https://127.0.0.1:1'}}]\n"
        "contexts: [{name: c, context: {cluster: k, user: u}}]\n"
        "users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1beta1, command: aws, args: [eks, get-token]}}}]\n",
        encoding="utf-8",
    )
    client = RealKubeClient(str(kubeconfig), "c", allow_exec_plugins=False)
    with pytest.raises(OpsError) as e:
        await client.cluster_identity()
    assert e.value.code is ErrorCode.AUTH_REQUIRED
    assert "allow_exec_plugins" in e.value.message


async def test_exec_plugin_shape_is_enforced_on_every_connect_not_only_at_propose(tmp_path: Path) -> None:
    """Runtime enforcement (not only the config_proposals static check): a kubeconfig whose exec block
    tries to smuggle a PATH override, or uses --role-arn, is refused on every connect attempt, even for
    a context allow_exec_plugins already trusts -- a swapped file on disk must still fail closed."""
    from local_ops.models import ErrorCode, OpsError
    from local_ops.providers.kube_client import RealKubeClient

    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: c\n"
        "clusters: [{name: k, cluster: {server: 'https://127.0.0.1:1'}}]\n"
        "contexts: [{name: c, context: {cluster: k, user: u}}]\n"
        "users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1beta1, command: aws, "
        "args: [eks, get-token, --cluster-name, demo], env: [{name: AWS_PROFILE, value: mi-mainnet-ro}, {name: PATH, value: /tmp/evil}]}}}]\n",
        encoding="utf-8",
    )
    client = RealKubeClient(str(kubeconfig), "c", allow_exec_plugins=True, allowed_exec_profiles=frozenset({"mi-mainnet-ro"}))
    with pytest.raises(OpsError) as e:
        await client.cluster_identity()
    assert e.value.code is ErrorCode.AUTH_REQUIRED
    assert "PATH" in e.value.message

    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: c\n"
        "clusters: [{name: k, cluster: {server: 'https://127.0.0.1:1'}}]\n"
        "contexts: [{name: c, context: {cluster: k, user: u}}]\n"
        "users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1beta1, command: aws, "
        "args: [eks, get-token, --cluster-name, demo, --role-arn, 'arn:aws:iam::1:role/x'], env: [{name: AWS_PROFILE, value: mi-mainnet-ro}]}}}]\n",
        encoding="utf-8",
    )
    client2 = RealKubeClient(str(kubeconfig), "c", allow_exec_plugins=True, allowed_exec_profiles=frozenset({"mi-mainnet-ro"}))
    with pytest.raises(OpsError) as e2:
        await client2.cluster_identity()
    assert e2.value.code is ErrorCode.AUTH_REQUIRED
    assert "role-arn" in e2.value.message


async def test_exec_plugin_matching_real_update_kubeconfig_shape_passes_runtime_validation(tmp_path: Path) -> None:
    """The exact shape `aws eks update-kubeconfig` writes must pass, or every real onboarding breaks."""
    from local_ops.models import ErrorCode, OpsError
    from local_ops.providers.kube_client import RealKubeClient

    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(
        "apiVersion: v1\nkind: Config\ncurrent-context: c\n"
        "clusters: [{name: k, cluster: {server: 'https://127.0.0.1:1'}}]\n"
        "contexts: [{name: c, context: {cluster: k, user: u}}]\n"
        "users: [{name: u, user: {exec: {apiVersion: client.authentication.k8s.io/v1beta1, command: aws, "
        "args: [--region, us-east-1, eks, get-token, --cluster-name, foo, --output, json], "
        "env: [{name: AWS_PROFILE, value: mi-mainnet-ro}]}}}]\n",
        encoding="utf-8",
    )
    client = RealKubeClient(str(kubeconfig), "c", allow_exec_plugins=True, allowed_exec_profiles=frozenset({"mi-mainnet-ro"}))
    try:
        await client.cluster_identity()
    except OpsError as e:
        # Must not fail at our own validation step; a real network/exec failure past that point is fine
        # (there is no real cluster here).
        assert e.code is not ErrorCode.AUTH_REQUIRED, e.message
    except Exception:  # noqa: BLE001
        pass  # any non-OpsError failure means validation already let it through
    finally:
        await client.close()
