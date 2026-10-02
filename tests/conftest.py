"""Shared fixtures: a real loopback uvicorn server running the full app with fake providers,
MCP clients per capability, and a logged-in reviewer HTTP client."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import socket
import textwrap
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest
import uvicorn
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from local_ops.app import create_app
from local_ops.config import ServerConfig, load_server_config
from local_ops.models import ArtifactRef, Capability, Coverage
from local_ops.providers.base import DiscoveryReport, EvidenceResult
from local_ops.providers.kube_fake import FakeKubeClient
from local_ops.providers.kubernetes import KubernetesAdapter

FAKE_UID = "fake-kube-system-uid-0001"
REPO = "registry.test/team/demo-app"
DIGESTS = {
    "v1": "sha256:" + "a1" * 32,
    "v2": "sha256:" + "b2" * 32,
    "v2-broken": "sha256:" + "c3" * 32,
}
VERSIONS = {"v1": "1.0.0", "v2": "2.0.0", "v2-broken": "2.0.0-broken"}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeRegistryAdapter:
    kind = "registry"

    def __init__(self, config: Any, server: Any):
        self.config = config
        self.provider_id = config.id
        self.resolved: list[str] = []

    def describe(self) -> Any:
        from local_ops.providers.base import AdapterDescription

        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, operations=[], required_credentials=[], credential_configured=True)

    async def check_availability(self, *, live: bool = False) -> Any:
        from local_ops.providers.base import Availability

        return Availability(available=True)

    def allowed(self, repository: str) -> bool:
        return repository == REPO

    async def resolve(self, image: str) -> ArtifactRef:
        self.resolved.append(image)
        if "@" in image:
            repo, digest = image.split("@", 1)
            tag = next((t for t, d in DIGESTS.items() if d == digest), None)
            return ArtifactRef(reference=image, repository=repo, tag=None, digest=digest, digest_kind="manifest", version_label=VERSIONS.get(tag or "", None))
        repo, tag = image.rsplit(":", 1)
        if tag not in DIGESTS:
            from local_ops.models import ErrorCode, OpsError

            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"tag {tag} not found")
        return ArtifactRef(reference=f"{repo}@{DIGESTS[tag]}", repository=repo, tag=tag, digest=DIGESTS[tag], digest_kind="manifest", version_label=VERSIONS[tag])

    async def discover(self, ctx: Any, scope: Any, budget: Any) -> DiscoveryReport:
        return DiscoveryReport(provider_id=self.provider_id)

    async def query(self, ctx: Any, query: dict[str, Any], budget: Any) -> EvidenceResult:
        return EvidenceResult(coverage=Coverage())


class FakeAppState:
    """State for the tiny HTTP app that stands in for the demo service's /health and /version."""

    def __init__(self) -> None:
        self.version = "1.0.0"
        self.healthy = True


def make_fake_app(state: FakeAppState) -> Any:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    a = FastAPI()

    @a.get("/health")
    async def health() -> Any:
        return JSONResponse({"status": "ok" if state.healthy else "failing"}, status_code=200 if state.healthy else 500)

    @a.get("/version")
    async def version() -> Any:
        return {"version": state.version}

    return a


async def run_uvicorn(app: Any, port: int) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False, lifespan="on")
    server = uvicorn.Server(cfg)
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.05)
    if not server.started:
        raise RuntimeError("uvicorn did not start")
    return server, task


def write_catalog(root: Path, *, execution_allowed: bool = True, health_port: int = 0, extra_services: str = "") -> None:
    (root / "services").mkdir(parents=True, exist_ok=True)
    (root / "catalog.yaml").write_text(f"name: test-demo\nexecution_allowed: {'true' if execution_allowed else 'false'}\ndescription: test catalog\n", encoding="utf-8")
    (root / "identities.yaml").write_text(textwrap.dedent("""
        identities:
          - id: carol-departed
            display_name: Carol
            kind: human
            status: departed
            departed_at: "2026-08-01T00:00:00Z"
            aliases: ["carol-departed", "carol@example.invalid"]
          - id: alice
            kind: human
            status: current
            aliases: ["alice"]
          - id: eks-admin
            kind: shared_role
            status: current
            aliases: ["eks-admin"]
    """).strip() + "\n", encoding="utf-8")
    base = f"http://127.0.0.1:{health_port}"
    (root / "services" / "demo-app.md").write_text(textwrap.dedent(f"""
        ---
        schema_version: 1
        id: demo-app
        name: Demo application
        purpose: Tiny HTTP service used to exercise the stack.
        why_it_matters: It is the executable demo target.
        owner: local developer
        disposition: keep
        environments: [demo]
        depends_on: [demo-db]
        used_by: []
        knowledge_holders:
          - name: local developer
            status: current
        bindings:
          - id: demo-deployment
            environment: demo
            provider_id: kube-demo
            namespace: demo
            workload_kind: Deployment
            workload_name: demo-app
            container_name: app
            cluster_identity: kube-demo
            execution_enabled: true
            source_state: verified
        source_repositories:
          - url: file://demo/app
            deployment_mechanism: kubernetes_native
        credential_refs: []
        observability:
          - kind: logs
            provider_id: kube-demo
          - kind: alerts
            provider_id: pagerduty-main
        audit_sources: [demo-fake]
        health_checks:
          - id: demo_http_health
            kind: http_status
            url: {base}/health
          - id: demo_http_version
            kind: http_json
            url: {base}/version
            json_field: version
            equals_artifact_version: true
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: demo-deployment
            readiness_timeout_seconds: 20
            health_checks: [ready_replicas, demo_http_health]
          update:
            executor: kubernetes_native
            kind: image_update
            binding_id: demo-deployment
            container: app
            allowed_image_repositories: [{REPO}]
            require_digest: true
            readiness_timeout_seconds: 20
            health_checks: [ready_replicas, demo_http_health, demo_http_version]
            rollback_policy: explicit_only
          rollback:
            executor: kubernetes_native
            kind: rollback
            binding_id: demo-deployment
            container: app
            allowed_image_repositories: [{REPO}]
            readiness_timeout_seconds: 20
            health_checks: [ready_replicas, demo_http_health]
        facts:
          - topic: runtime
            statement: Runs on the fake cluster in tests.
            confidence: verified
        unknowns: []
        next_expiry: null
        ---
        ## Purpose and dependencies
        Test service.
    """).strip() + "\n", encoding="utf-8")
    (root / "services" / "demo-db.md").write_text(textwrap.dedent("""
        ---
        schema_version: 1
        id: demo-db
        name: Demo database
        purpose: Fixture dependency.
        environments: [demo]
        bindings:
          - id: db-doc
            environment: demo
            provider_id: demo-fake
            region: local-1
            source_state: documentary
            execution_enabled: false
        unknowns: ["backup recoverability unverified"]
        contradictions:
          - topic: region
            claims:
              - statement: runs in local-1
                source: doc A
              - statement: runs in local-2
                source: doc B
        ---
        ## Notes
        documentary
    """).strip() + "\n", encoding="utf-8")
    (root / "services" / "demo-app-alias.md").write_text(textwrap.dedent(f"""
        ---
        schema_version: 1
        id: demo-app-alias
        name: Second catalog entry pointing at the same workload
        environments: [demo]
        bindings:
          - id: alias-binding
            environment: demo
            provider_id: kube-demo
            namespace: demo
            workload_kind: Deployment
            workload_name: demo-app
            container_name: app
            cluster_identity: kube-demo
            execution_enabled: true
            source_state: verified
        health_checks:
          - id: demo_http_health
            kind: http_status
            url: {base}/health
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: alias-binding
            readiness_timeout_seconds: 20
            health_checks: [ready_replicas, demo_http_health]
        ---
        alias
    """).strip() + "\n", encoding="utf-8")
    (root / "services" / "gitops-app.md").write_text(textwrap.dedent(f"""
        ---
        schema_version: 1
        id: gitops-app
        name: Argo-managed app
        environments: [demo]
        bindings:
          - id: gitops-binding
            environment: demo
            provider_id: kube-demo
            namespace: demo
            workload_kind: Deployment
            workload_name: gitops-app
            container_name: app
            cluster_identity: kube-demo
            execution_enabled: true
            source_state: verified
        health_checks:
          - id: demo_http_health
            kind: http_status
            url: {base}/health
        operations:
          update:
            executor: kubernetes_native
            kind: image_update
            binding_id: gitops-binding
            container: app
            allowed_image_repositories: [{REPO}]
            health_checks: [ready_replicas, demo_http_health]
        ---
        gitops
    """).strip() + "\n", encoding="utf-8")
    (root / "services" / "doc-only.md").write_text(textwrap.dedent("""
        ---
        schema_version: 1
        id: doc-only
        name: Documentary only service
        environments: [prod]
        bindings:
          - id: prod-doc
            environment: prod
            provider_id: aws-prod
            region: us-east-1
            cluster_name: prod-cluster
            source_state: documentary
            execution_enabled: false
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: prod-doc
            health_checks: [ready_replicas]
        ---
        doc
    """).strip() + "\n", encoding="utf-8")
    if extra_services:
        (root / "services" / "extra.md").write_text(extra_services, encoding="utf-8")


def write_server_config(path: Path, state_dir: Path, port: int) -> ServerConfig:
    path.write_text(textwrap.dedent(f"""
        schema_version: 1
        server:
          bind_host: 127.0.0.1
          port: {port}
          state_dir: {state_dir}
        limits:
          provider_concurrency_global: 4
          provider_concurrency_per_provider: 2
          http_timeout_seconds: 5
          interactive_query_budget_seconds: 30
        review:
          default_mode: review_both
          approval_ttl_minutes: 60
          plan_ttl_minutes: 30
        credentials: []
        providers:
          - id: demo-fake
            kind: demo
          - id: kube-demo
            kind: kubernetes
            context: fake
            cluster_identity:
              kube_system_uid: {FAKE_UID}
            namespaces: [demo]
          - id: demo-registry
            kind: registry
            registries: ["registry.test"]
    """).strip() + "\n", encoding="utf-8")
    return load_server_config(path)


class Env:
    def __init__(self) -> None:
        self.base_url = ""
        self.core: Any = None
        self.keys: dict[str, str] = {}
        self.kube: FakeKubeClient | None = None
        self.registry: FakeRegistryAdapter | None = None
        self.demo: Any = None
        self.app_state = FakeAppState()
        self.config: ServerConfig | None = None
        self.catalog_dir: Path | None = None
        self.state_dir: Path | None = None
        self.config_path: Path | None = None
        self.reviewer_password = "reviewer-password-123"
        self.holder: dict[str, Any] = {}
        self.port = 0
        self.health_port = 0
        self._servers: list[tuple[uvicorn.Server, asyncio.Task[None]]] = []

    def mcp(self, capability: str, key: str | None = None) -> Client:
        key = key or self.keys[capability]
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=httpx2.Timeout(30, read=60))
        return Client(streamable_http_client(f"{self.base_url}/mcp/{capability}", http_client=http))

    async def call(self, capability: str, tool: str, args: dict[str, Any], key: str | None = None) -> dict[str, Any]:
        async with self.mcp(capability, key) as c:
            res = await c.call_tool(tool, args)
        if res.is_error:
            text = res.content[0].text if res.content else ""
            start = text.find("{")
            try:
                return {"__error__": json.loads(text[start:] if start >= 0 else text)}
            except json.JSONDecodeError:
                return {"__error__": {"error": "unknown", "message": text}}
        return res.structured_content or json.loads(res.content[0].text)  # type: ignore[union-attr]

    async def wait(self, capability: str, request_id: str, *, until: tuple[str, ...] = ("pending_request_review", "pending_response_review", "released", "withheld", "rejected", "failed", "cancelled", "expired", "outcome_unknown"), timeout: float = 30, key: str | None = None) -> dict[str, Any]:  # noqa: ASYNC109
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            st = await self.call(capability, "request_status", {"request_id": request_id}, key)
            if "__error__" in st:
                return st
            es, rs = st["execution_status"], st["response_status"]
            if rs in until or es in until or (es in ("succeeded", "partial") and rs in ("released", "withheld", "pending_response_review")):
                return st
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError(f"request {request_id} stuck at {es}/{rs}")
            await asyncio.sleep(0.1)

    # reviewer helpers -------------------------------------------------
    async def reviewer(self) -> httpx.AsyncClient:
        c = httpx.AsyncClient(base_url=self.base_url, follow_redirects=False, timeout=30)
        r = await c.post("/login", data={"username": "reviewer", "password": self.reviewer_password, "next": "/review"})
        assert r.status_code == 303, r.text
        return c

    async def csrf(self, c: httpx.AsyncClient) -> str:
        r = await c.get("/review")
        m = re.search(r'name="csrf" value="([^"]+)"', r.text)
        assert m, "csrf token not found"
        return m.group(1)

    async def approve(self, request_id: str, c: httpx.AsyncClient | None = None, edited_args: dict[str, Any] | None = None) -> httpx.Response:
        c = c or await self.reviewer()
        data = {"csrf": await self.csrf(c), "note": "ok"}
        if edited_args is not None:
            data["edited_args"] = json.dumps(edited_args)
        return await c.post(f"/review/{request_id}/approve", data=data)

    async def release(self, request_id: str, c: httpx.AsyncClient | None = None, redact_paths: str = "", exclude_evidence: str = "") -> httpx.Response:
        c = c or await self.reviewer()
        return await c.post(f"/review/{request_id}/release", data={"csrf": await self.csrf(c), "redact_paths": redact_paths, "exclude_evidence": exclude_evidence, "note": ""})

    async def withhold(self, request_id: str, c: httpx.AsyncClient | None = None) -> httpx.Response:
        c = c or await self.reviewer()
        return await c.post(f"/review/{request_id}/withhold", data={"csrf": await self.csrf(c), "reason": "test withhold"})

    async def reject(self, request_id: str, c: httpx.AsyncClient | None = None) -> httpx.Response:
        c = c or await self.reviewer()
        return await c.post(f"/review/{request_id}/reject", data={"csrf": await self.csrf(c), "reason": "test reject"})

    async def set_mode(self, principal_name: str, data_class: str, mode: str, c: httpx.AsyncClient | None = None) -> httpx.Response:
        c = c or await self.reviewer()
        p = await self.core.db.principal_by_name(principal_name)
        return await c.post("/settings/mode", data={"csrf": await self.csrf(c), "principal_id": p["id"], "data_class": data_class, "mode": mode})

    async def run_until(self, request_id: str, *, timeout: float = 30) -> dict[str, Any]:  # noqa: ASYNC109
        """Wait directly on the DB for a request to leave queued/running."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            req = await self.core.db.request(request_id)
            assert req is not None
            if req["execution_status"] not in ("queued", "running"):
                return req
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError(f"{request_id} still {req['execution_status']} phase {req.get('phase')}")
            await asyncio.sleep(0.1)


@contextlib.asynccontextmanager
async def make_env(tmp_path: Path, *, execution_allowed: bool = True, start_worker: bool = True) -> AsyncIterator[Env]:
    env = Env()
    env.port = free_port()
    env.health_port = free_port()
    env.catalog_dir = tmp_path / "catalog"
    env.state_dir = tmp_path / "state"
    env.config_path = tmp_path / "server.yaml"
    write_catalog(env.catalog_dir, execution_allowed=execution_allowed, health_port=env.health_port)
    env.config = write_server_config(env.config_path, env.state_dir, env.port)
    env.base_url = f"http://127.0.0.1:{env.port}"
    kube = FakeKubeClient(identity={"kube_system_uid": FAKE_UID, "server": "https://fake.invalid", "git_version": "v1.fake", "context": "fake"})
    kube.add_namespace("demo")
    kube.add_deployment("demo", "demo-app", f"{REPO}@{DIGESTS['v1']}", replicas=2)
    kube.add_deployment("demo", "gitops-app", f"{REPO}@{DIGESTS['v1']}", labels={"app": "gitops-app", "argocd.argoproj.io/instance": "gitops-app"})
    kube.add_deployment("demo", "orphan-app", "registry.test/team/orphan:latest", labels={"app": "orphan-app"})
    kube.fail_rollout_for_images.add(f"{REPO}@{DIGESTS['v2-broken']}")
    env.kube = kube
    kube_provider = next(p for p in env.config.providers if p.id == "kube-demo")
    reg_provider = next(p for p in env.config.providers if p.id == "demo-registry")
    env.registry = FakeRegistryAdapter(reg_provider, env.config)
    overrides = {"kube-demo": KubernetesAdapter(kube_provider, env.config, None, client=kube), "demo-registry": env.registry}
    app = create_app(env.config, env.catalog_dir, provider_overrides=overrides, core_holder=env.holder)
    fake_app = make_fake_app(env.app_state)
    s1, t1 = await run_uvicorn(fake_app, env.health_port)
    env._servers.append((s1, t1))
    s2, t2 = await run_uvicorn(app, env.port)
    env._servers.append((s2, t2))
    env.core = env.holder["core"]
    env.demo = env.core.providers.get("demo-fake")
    await env.core.auth.set_reviewer_password("reviewer", env.reviewer_password)
    for cap in Capability:
        _, secret = await env.core.auth.create_key(f"{cap.value}-default", [cap])
        env.keys[cap.value] = secret
    _, secret = await env.core.auth.create_key("multi", [Capability.READ, Capability.READ, Capability.WRITE])
    env.keys["multi"] = secret
    try:
        yield env
    finally:
        for s, t in reversed(env._servers):
            s.should_exit = True
            with contextlib.suppress(Exception):
                await asyncio.wait_for(t, timeout=10)


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    async with make_env(tmp_path) as e:
        yield e


@pytest.fixture
def integration_enabled() -> bool:
    return os.environ.get("LOCAL_OPS_INTEGRATION") == "1"
