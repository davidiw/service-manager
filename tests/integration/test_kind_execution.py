"""Opt-in end-to-end suite against the disposable kind cluster (scripts/demo-cluster.sh up).

Runs the real server with the real Kubernetes adapter, real registry adapter and helm executor:
MCP client -> authorization -> (review website or YOLO) -> operation -> health verification -> result.
Requires LOCAL_OPS_INTEGRATION=1. Verifies the cluster identity recorded at creation before mutating."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import textwrap
import uuid
from pathlib import Path

import pytest

from local_ops.app import create_app
from local_ops.config import load_server_config
from local_ops.models import Capability
from tests.conftest import Env, free_port, run_uvicorn

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]
ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "local-state"
CONTEXT = "kind-local-ops-demo"

if os.environ.get("LOCAL_OPS_INTEGRATION") != "1":
    pytest.skip("set LOCAL_OPS_INTEGRATION=1 and run scripts/demo-cluster.sh up", allow_module_level=True)


def _kubectl(*args: str) -> str:
    return subprocess.run(["kubectl", "--context", CONTEXT, *args], check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def _guard() -> dict:  # type: ignore[type-arg]
    ident = json.loads((STATE / "demo-cluster.json").read_text())
    ctx = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True, timeout=20).stdout.strip()
    assert ctx == CONTEXT, f"refusing: current context {ctx!r} is not the disposable demo cluster"
    assert not any(x in ctx for x in ("eks", "prod", "mainnet"))
    live = _kubectl("get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}")
    assert live == ident["kube_system_uid"], "refusing: live cluster identity differs from the recorded disposable cluster"
    return ident


def _reset_cluster(images: dict[str, str]) -> None:
    """Return both demo workloads to the v1 artifact so every test starts from a known state. This is an
    out-of-band change by design (the harness, not the server, owns the disposable cluster)."""
    _kubectl("-n", "demo", "set", "image", "deploy/demo-app", f"app={images['v1']}")
    _kubectl("-n", "demo", "rollout", "status", "deploy/demo-app", "--timeout=180s")
    subprocess.run(["helm", "upgrade", "demo-helm", str(ROOT / "catalog/demo/charts/demo-helm"), "-n", "demo", "--reuse-values", "--set-string", f"image.ref={images['v1']}", "--wait", "--timeout", "180s", "--kube-context", CONTEXT], check=True, capture_output=True, text=True, timeout=240)
    _kubectl("-n", "demo", "rollout", "status", "deploy/demo-helm", "--timeout=180s")


@pytest.fixture
async def kenv(tmp_path: Path):  # type: ignore[no-untyped-def]
    ident = _guard()
    images = json.loads((STATE / "demo-images.json").read_text())
    _reset_cluster(images)
    port = free_port()
    state_dir = tmp_path / "state"
    cfg_path = tmp_path / "server.yaml"
    cfg_path.write_text(textwrap.dedent(f"""
        schema_version: 1
        server:
          bind_host: 127.0.0.1
          port: {port}
          state_dir: {state_dir}
        limits:
          interactive_query_budget_seconds: 120
          deployment_budget_seconds: 600
        review:
          default_mode: review_both
        credentials:
          - id: kubeconfig-demo
            kind: kubeconfig_context
            context: {CONTEXT}
            purpose: execute
        providers:
          - id: demo-fake
            kind: demo
          - id: kube-demo
            kind: kubernetes
            credential: kubeconfig-demo
            context: {CONTEXT}
            cluster_identity_file: {STATE / 'demo-cluster.json'}
            namespaces: [demo]
          - id: demo-registry
            kind: registry
            registries: ["localhost:5001"]
    """).strip() + "\n")
    cfg = load_server_config(cfg_path)
    env = Env()
    env.port = port
    env.base_url = f"http://127.0.0.1:{port}"
    env.config = cfg
    env.catalog_dir = ROOT / "catalog" / "demo"
    app = create_app(cfg, env.catalog_dir, core_holder=env.holder)
    server, task = await run_uvicorn(app, port)
    env._servers.append((server, task))
    env.core = env.holder["core"]
    await env.core.auth.set_reviewer_password("reviewer", env.reviewer_password)
    for cap in Capability:
        _, secret = await env.core.auth.create_key(f"{cap.value}-default", [cap])
        env.keys[cap.value] = secret
    env.images = images  # type: ignore[attr-defined]
    env.ident = ident  # type: ignore[attr-defined]
    try:
        yield env
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=15)


async def _served_version(expected: str, port: int = 30080, settle: float = 60.0) -> str:
    """Poll the NodePort until it serves `expected` (old pods may still be terminating behind it)."""
    import urllib.request

    loop = asyncio.get_running_loop()
    deadline = loop.time() + settle
    got = ""
    while loop.time() < deadline:
        body = await asyncio.to_thread(lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/version", timeout=5).read())
        got = json.loads(body)["version"]
        if got == expected:
            return got
        await asyncio.sleep(2)
    return got


def _helm_revision() -> int:
    out = subprocess.run(["helm", "status", "demo-helm", "-n", "demo", "-o", "json", "--kube-context", CONTEXT], check=True, capture_output=True, text=True, timeout=60).stdout
    return int(json.loads(out)["version"])


def _current_image(deploy: str) -> str:
    return _kubectl("-n", "demo", "get", "deploy", deploy, "-o", "jsonpath={.spec.template.spec.containers[0].image}")


async def _prepare(env: Env, service: str, binding: str, action: str, artifact: str | None = None) -> dict:  # type: ignore[type-arg]
    args = {"service_id": service, "binding_id": binding, "action": action}
    if artifact:
        args["desired_artifact"] = artifact
    sub = await env.call("write", "action_prepare", args)
    st = await env.wait("write", sub["request_id"], timeout=120)
    assert st["execution_status"] == "succeeded", st
    return await env.call("write", "request_result", {"request_id": sub["request_id"]})


async def _submit_and_finish(env: Env, plan: dict, *, review: bool = False) -> dict:  # type: ignore[type-arg]
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": str(uuid.uuid4())})
    if review:
        assert sub["execution_status"] == "pending_request_review"
        await env.approve(sub["request_id"])
    st = await env.wait("write", sub["request_id"], timeout=600)
    if st["response_status"] == "pending_response_review":
        await env.release(sub["request_id"])
        st = await env.wait("write", sub["request_id"], timeout=30)
    res = await env.call("write", "request_result", {"request_id": sub["request_id"]})
    res["_status"] = st
    if "receipt" in res:
        res["_checks"] = [(c["check_id"], c["passed"], c["detail"], str(c.get("observed"))[:200]) for c in res["receipt"]["health_checks"]]
    return res


async def test_discovery_and_inspection_against_kind(kenv: Env) -> None:
    env = kenv
    await env.set_mode("read-default", "inventory", "yolo")
    await env.set_mode("read-default", "content", "yolo")
    sub = await env.call("read", "discovery_scan", {"providers": ["kube-demo"], "scope": {"namespaces": ["demo"]}})
    st = await env.wait("read", sub["request_id"], timeout=120)
    assert st["execution_status"] == "succeeded", st
    res = await env.call("read", "request_result", {"request_id": sub["request_id"]})
    assert res["summary"]["identities"]["kube-demo"]["kube_system_uid"] == env.ident["kube_system_uid"]  # type: ignore[attr-defined]
    kinds = {(i["resource_type"], i["identity"].get("name")) for i in res["items"]}
    assert ("k8s/Deployment", "demo-app") in kinds and ("k8s/Deployment", "demo-helm") in kinds and ("k8s/Service", "demo-app") in kinds
    matched = {i["identity"]["name"]: i["match_service_id"] for i in res["items"] if i["resource_type"] == "k8s/Deployment"}
    assert matched["demo-app"] == "demo-app" and matched["demo-helm"] == "demo-helm"
    cat = await env.call("read", "catalog_read", {"service_id": "demo-app"})
    wl = cat["services"][0]["observed"]["workloads"][0]
    assert wl["desired_images"][0]["image"] == env.images["v1"]  # type: ignore[attr-defined]
    assert wl["running"][0]["image_id"].startswith("localhost:5001/local-ops/demo-app@sha256:")
    ins = await env.call("read", "service_inspect", {"service_id": "demo-app"})
    st = await env.wait("read", ins["request_id"], timeout=120)
    assert st["execution_status"] == "succeeded"
    r = await env.call("read", "request_result", {"request_id": ins["request_id"]})
    assert r["items"][0]["inspectable"] and r["items"][0]["workload"]["rollout"]["converged"]
    assert any("log line" in ln or "demo-app" in ln or "GET" in ln for p in r["items"][0]["logs"] for ln in p["lines"])


async def test_update_restart_rollback_through_review_website(kenv: Env) -> None:
    env = kenv
    images = env.images  # type: ignore[attr-defined]
    assert _current_image("demo-app") == images["v1"]
    await env.set_mode("write-default", "mutation", "yolo")  # read-only prepare without stops
    plan = (await _prepare(env, "demo-app", "demo-deployment", "update", "localhost:5001/local-ops/demo-app:v2"))["plan"]
    assert plan["requested_artifact"]["reference"] == images["v2"] and plan["requested_artifact"]["version_label"] == "2.0.0"
    assert plan["current_artifact"]["reference"] == images["v1"]
    assert plan["target"]["cluster_identity"] == env.ident["kube_system_uid"]  # type: ignore[attr-defined]
    await env.set_mode("write-default", "mutation", "review_both")
    out = await _submit_and_finish(env, plan, review=True)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    rc = out["receipt"]
    assert rc["after_artifact"]["reference"] == images["v2"] and all(c["passed"] for c in rc["health_checks"])
    assert {c["check_id"] for c in rc["health_checks"]} == {"ready_replicas", "demo_http_health", "demo_http_version"}
    assert _current_image("demo-app") == images["v2"]

    assert await _served_version("2.0.0") == "2.0.0"
    # restart (yolo)
    await env.set_mode("write-default", "mutation", "yolo")
    rplan = (await _prepare(env, "demo-app", "demo-deployment", "restart"))["plan"]
    out = await _submit_and_finish(env, rplan)
    assert out["_status"]["execution_status"] == "succeeded"
    assert _kubectl("-n", "demo", "get", "deploy", "demo-app", "-o", "jsonpath={.spec.template.metadata.annotations.local-ops\\.dev/restart-plan}").startswith("req:")
    # explicit rollback to v1
    rb = (await _prepare(env, "demo-app", "demo-deployment", "rollback"))["plan"]
    assert rb["requested_artifact"]["reference"] == images["v1"]
    out = await _submit_and_finish(env, rb)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    assert _current_image("demo-app") == images["v1"]
    assert await _served_version("1.0.0") == "1.0.0"


async def test_broken_image_fails_health_without_auto_rollback(kenv: Env) -> None:
    env = kenv
    images = env.images  # type: ignore[attr-defined]
    await env.set_mode("write-default", "mutation", "yolo")
    plan = (await _prepare(env, "demo-app", "demo-deployment", "update", "localhost:5001/local-ops/demo-app:v2-broken"))["plan"]
    out = await _submit_and_finish(env, plan)
    assert out["_status"]["execution_status"] == "failed", out
    rc = out["receipt"]
    assert rc["ran"] == "ran" and rc["rollback_result"] is None
    assert next(c for c in rc["health_checks"] if c["check_id"] == "ready_replicas")["passed"] is False
    assert _current_image("demo-app") == images["v2-broken"]
    # the old ReplicaSet keeps serving while the new one crash-loops; explicit rollback restores v1
    rb = (await _prepare(env, "demo-app", "demo-deployment", "rollback"))["plan"]
    assert rb["requested_artifact"]["reference"] == images["v1"]
    out = await _submit_and_finish(env, rb)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    assert _current_image("demo-app") == images["v1"]


async def test_helm_upgrade_and_rollback(kenv: Env) -> None:
    env = kenv
    images = env.images  # type: ignore[attr-defined]
    await env.set_mode("write-default", "mutation", "yolo")
    rev_before = _helm_revision()
    plan = (await _prepare(env, "demo-helm", "demo-helm-release", "update", "localhost:5001/local-ops/demo-app:v2"))["plan"]
    assert plan["executor"] == "helm" and plan["target"]["release"] == "demo-helm"
    assert any("post-upgrade" in h for h in plan["hooks_or_auxiliary_work"])
    out = await _submit_and_finish(env, plan)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    rc = out["receipt"]
    assert _current_image("demo-helm") == images["v2"]
    assert next(c for c in rc["health_checks"] if c["check_id"] == "helm_release_deployed")["passed"]
    assert any(p.startswith("helm-revision:") for p in rc["provider_operation_ids"])
    rb = (await _prepare(env, "demo-helm", "demo-helm-release", "rollback"))["plan"]
    assert rb["provider_mutations"][0]["op"] == "helm_rollback"
    out = await _submit_and_finish(env, rb)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    assert _current_image("demo-helm") == images["v1"]
    rev_after = _helm_revision()
    assert rev_after == rev_before + 2  # upgrade + rollback each add a revision
    # helm-owned workload restart uses the registered restart mechanism, never an unmanaged image change
    rp = (await _prepare(env, "demo-helm", "demo-helm-release", "restart"))["plan"]
    assert rp["executor"] == "helm" and "registered restart" in rp["mechanism"]
    out = await _submit_and_finish(env, rp)
    assert out["_status"]["execution_status"] == "succeeded", (out.get("_checks"), out.get("error"), out.get("summary"))
    assert _current_image("demo-helm") == images["v1"]


async def test_duplicate_submit_and_stale_plan_on_kind(kenv: Env) -> None:
    env = kenv
    await env.set_mode("write-default", "mutation", "yolo")
    plan = (await _prepare(env, "demo-app", "demo-deployment", "restart"))["plan"]
    key = str(uuid.uuid4())
    s1 = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": key})
    s2 = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": key})
    assert s1["request_id"] == s2["request_id"]
    st = await env.wait("write", s1["request_id"], timeout=300)
    assert st["execution_status"] == "succeeded"
    s3 = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": str(uuid.uuid4())})
    assert s3["__error__"]["error"] == "conflict"
    plan2 = (await _prepare(env, "demo-app", "demo-deployment", "restart"))["plan"]
    # out-of-band change (kubectl) makes the plan stale
    marker = uuid.uuid4().hex  # unique per run so the template really changes even if a previous run left a marker
    _kubectl("-n", "demo", "patch", "deploy", "demo-app", "-p", json.dumps({"spec": {"template": {"metadata": {"annotations": {"out-of-band": marker}}}}}))
    s4 = await env.call("write", "action_submit", {"plan_id": plan2["plan_id"], "plan_hash": plan2["plan_hash"], "idempotency_key": str(uuid.uuid4())})
    st = await env.wait("write", s4["request_id"], timeout=300)
    assert st["execution_status"] == "rejected"
    res = await env.call("write", "request_result", {"request_id": s4["request_id"]})
    assert res["error"]["error"] == "plan_stale"
    _kubectl("-n", "demo", "rollout", "status", "deploy/demo-app", "--timeout=120s")
