"""Registry adapter tests against an httpx.MockTransport fake of the OCI distribution API. No network,
no layer pulls -- only manifest(s) and the small image-config blob."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import ErrorCode, OpsError, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import ProviderRegistry
from local_ops.providers.registry import RegistryAdapter
from local_ops.release import Sanitizer
from local_ops.storage import Database

REGISTRY = "registry.example.test"
AMD64_MANIFEST_DIGEST = "sha256:" + "a" * 64
ARM64_MANIFEST_DIGEST = "sha256:" + "b" * 64
INDEX_DIGEST = "sha256:" + "c" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64

_open_dbs: list[Database] = []


async def make_ctx(tmp_path: Path, config: ServerConfig) -> OperationContext:
    db = Database(tmp_path / "s.db", tmp_path / "ev")
    await db.open()
    _open_dbs.append(db)
    cat_dir = tmp_path / "catalog"
    (cat_dir / "services").mkdir(parents=True, exist_ok=True)
    (cat_dir / "catalog.yaml").write_text("name: t\n", encoding="utf-8")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    return OperationContext(db=db, config=config, catalog=load_catalog(cat_dir), providers=ProviderRegistry(), sanitizer=Sanitizer(), principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)


@pytest.fixture(autouse=True)
async def _close_dbs() -> Any:
    yield
    while _open_dbs:
        await _open_dbs.pop().close()


def reg_config(**over: Any) -> ServerConfig:
    base: dict[str, Any] = {"id": "reg", "kind": "registry", "registries": [REGISTRY]}
    base.update(over)
    return ServerConfig(providers=[ProviderConfig.model_validate(base)])


class FakeRegistry:
    """Minimal OCI distribution API fake: an index referencing two per-platform manifests, each with
    its own config blob and OCI labels."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/v2/team/app/manifests/v1" or path == f"/v2/team/app/manifests/{INDEX_DIGEST}":
            body = {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"digest": AMD64_MANIFEST_DIGEST, "platform": {"os": "linux", "architecture": "amd64"}},
                    {"digest": ARM64_MANIFEST_DIGEST, "platform": {"os": "linux", "architecture": "arm64"}},
                ],
            }
            return httpx.Response(200, headers={"docker-content-digest": INDEX_DIGEST}, json=body)
        if path == f"/v2/team/app/manifests/{AMD64_MANIFEST_DIGEST}":
            return httpx.Response(200, headers={"docker-content-digest": AMD64_MANIFEST_DIGEST}, json={"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": CONFIG_DIGEST}})
        if path == f"/v2/team/app/blobs/{CONFIG_DIGEST}":
            return httpx.Response(200, json={"config": {"Labels": {
                "org.opencontainers.image.source": "https://github.com/example/app",
                "org.opencontainers.image.revision": "a" * 40,
                "org.opencontainers.image.version": "1.2.3",
                "org.opencontainers.image.created": "2026-09-30T10:00:00Z",
                "some.other.label": "irrelevant",
            }}})
        if path == "/v2/team/single/manifests/v2":
            return httpx.Response(200, headers={"docker-content-digest": "sha256:" + "e" * 64}, json={"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": CONFIG_DIGEST}})
        if path == f"/v2/team/single/blobs/{CONFIG_DIGEST}":
            return httpx.Response(200, json={"config": {"Labels": {"org.opencontainers.image.version": "9.9.9"}}})
        if path == "/v2/team/missing/manifests/v1":
            return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})
        return httpx.Response(500, json={"message": f"unexpected {path}"})


def adapter_for(fake: FakeRegistry, cfg: ServerConfig) -> RegistryAdapter:
    return RegistryAdapter(cfg.providers[0], cfg, None, http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))


async def test_registry_manifest_reports_index_and_per_platform_digests_and_labels(tmp_path: Path) -> None:
    cfg = reg_config()
    fake = FakeRegistry()
    ctx = await make_ctx(tmp_path, cfg)
    a = adapter_for(fake, cfg)
    res = await a.query(ctx, {"query_type": "registry_manifest", "scope": {"image": f"{REGISTRY}/team/app:v1"}}, ctx.budget)
    item = res.items[0]
    assert item["digest"] == INDEX_DIGEST and item["digest_kind"] == "index"
    assert item["platform_digests"] == {"linux/amd64": AMD64_MANIFEST_DIGEST, "linux/arm64": ARM64_MANIFEST_DIGEST}
    assert item["labels"] == {
        "org.opencontainers.image.source": "https://github.com/example/app",
        "org.opencontainers.image.revision": "a" * 40,
        "org.opencontainers.image.version": "1.2.3",
        "org.opencontainers.image.created": "2026-09-30T10:00:00Z",
    }
    assert "some.other.label" not in item["labels"]
    assert res.coverage.completed_scopes == ["reg"]
    # Only manifests and the small config blob are read; no layer blob is ever requested.
    assert all("/blobs/" not in str(r.url) or str(r.url).endswith(CONFIG_DIGEST) for r in fake.requests)


async def test_registry_manifest_single_platform_has_no_platform_digests(tmp_path: Path) -> None:
    cfg = reg_config()
    fake = FakeRegistry()
    ctx = await make_ctx(tmp_path, cfg)
    a = adapter_for(fake, cfg)
    res = await a.query(ctx, {"query_type": "registry_manifest", "scope": {"image": f"{REGISTRY}/team/single:v2"}}, ctx.budget)
    item = res.items[0]
    assert item["digest_kind"] == "manifest" and item["platform_digests"] == {}
    assert item["labels"] == {"org.opencontainers.image.version": "9.9.9"}


async def test_registry_manifest_not_found(tmp_path: Path) -> None:
    cfg = reg_config()
    fake = FakeRegistry()
    ctx = await make_ctx(tmp_path, cfg)
    a = adapter_for(fake, cfg)
    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "registry_manifest", "scope": {"image": f"{REGISTRY}/team/missing:v1"}}, ctx.budget)
    assert ei.value.code == ErrorCode.SCOPE_UNRESOLVED


async def test_registry_manifest_refuses_registry_outside_configured_allow_list(tmp_path: Path) -> None:
    cfg = reg_config(registries=["other.example.test"])
    fake = FakeRegistry()
    ctx = await make_ctx(tmp_path, cfg)
    a = adapter_for(fake, cfg)
    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "registry_manifest", "scope": {"image": f"{REGISTRY}/team/app:v1"}}, ctx.budget)
    assert ei.value.code == ErrorCode.AUTHORIZATION_DENIED
    assert not fake.requests


async def test_registry_adapter_rejects_unsupported_query_type(tmp_path: Path) -> None:
    cfg = reg_config()
    fake = FakeRegistry()
    ctx = await make_ctx(tmp_path, cfg)
    a = adapter_for(fake, cfg)
    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "something_else", "scope": {"image": "x"}}, ctx.budget)
    assert ei.value.code == ErrorCode.UNSUPPORTED_OPERATION


def test_describe_lists_registry_manifest_only() -> None:
    cfg = reg_config()
    d = RegistryAdapter(cfg.providers[0], cfg, None).describe()
    assert [op.name for op in d.operations] == ["registry_manifest"]


async def test_resolve_still_returns_artifact_ref_for_the_digest_pinning_executor(tmp_path: Path) -> None:
    """D3/D19: the executor path (`resolve`) must keep its existing ArtifactRef shape even though it now
    shares `_inspect` with `registry_manifest`."""
    cfg = reg_config()
    fake = FakeRegistry()
    a = adapter_for(fake, cfg)
    ref = await a.resolve(f"{REGISTRY}/team/single:v2")
    assert ref.repository == f"{REGISTRY}/team/single" and ref.tag == "v2" and ref.digest == "sha256:" + "e" * 64
    assert ref.digest_kind == "manifest" and ref.version_label == "9.9.9"
