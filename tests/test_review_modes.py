"""Both review gates work independently; defaults hold; narrowed edits change the approval hash; mode
changes do not drain old queues; YOLO bypasses human review but not policy."""

from __future__ import annotations

import pytest

from tests.conftest import Env

pytestmark = pytest.mark.asyncio


async def test_review_both_gates_control_provider_calls_and_disclosure(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"], "reason": "map the fixture account"})
    assert sub["execution_status"] == "pending_request_review" and sub["response_status"] == "unavailable"
    rid = sub["request_id"]
    assert sub["review_url"].endswith(f"/review/{rid}")
    assert env.demo.calls == []  # reviewer approval controls whether the provider is called
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert res["__error__"]["error"] == "review_required"
    r = await env.approve(rid)
    assert r.status_code == 303
    st = await env.wait("discovery", rid)
    assert st["execution_status"] == "succeeded" and st["response_status"] == "pending_response_review"
    assert len(env.demo.calls) == 1
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert res["__error__"]["error"] == "review_required"
    r = await env.release(rid)
    assert r.status_code == 303
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert res["execution_status"] == "succeeded" and res["summary"]["observations"] > 0
    assert res["page"]["total"] == res["summary"]["observations"]
    assert all(it["resource_type"].startswith("demo/") for it in res["items"])
    cov = res["coverage"]
    assert cov["completed_scopes"] == ["demo-fake/local-1"]


async def test_review_requests_only_releases_automatically(env: Env) -> None:
    await env.set_mode("discovery-default", "discovery", "review_requests")
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    assert sub["execution_status"] == "pending_request_review"
    await env.approve(sub["request_id"])
    st = await env.wait("discovery", sub["request_id"])
    assert st["response_status"] == "released"
    res = await env.call("discovery", "request_result", {"request_id": sub["request_id"]})
    assert res["summary"]["observations"] > 0


async def test_review_responses_only_runs_immediately_but_withholds_until_release(env: Env) -> None:
    await env.set_mode("diagnosis-default", "diagnosis", "review_responses")
    sub = await env.call("diagnosis", "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "benign"}})
    assert sub["execution_status"] in ("queued", "running")
    st = await env.wait("diagnosis", sub["request_id"])
    assert st["execution_status"] == "succeeded" and st["response_status"] == "pending_response_review"
    assert (await env.call("diagnosis", "request_result", {"request_id": sub["request_id"]}))["__error__"]["error"] == "review_required"
    await env.release(sub["request_id"])
    res = await env.call("diagnosis", "request_result", {"request_id": sub["request_id"]})
    assert res["event_count"] == 7


async def test_review_responses_invalid_for_execution(env: Env) -> None:
    c = await env.reviewer()
    r = await env.set_mode("execution-default", "execution", "review_responses", c)
    assert r.status_code == 200 and "read-only" in r.text
    mode, _, _ = await env.core.auth.effective_mode((await env.core.db.principal_by_name("execution-default"))["id"], __import__("local_ops.models", fromlist=["Capability"]).Capability.EXECUTION)
    assert mode.value == "review_both"
    await c.aclose()


async def test_yolo_skips_human_review_but_not_policy(env: Env) -> None:
    await env.set_mode("discovery-default", "discovery", "yolo")
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    assert sub["execution_status"] in ("queued", "running")
    st = await env.wait("discovery", sub["request_id"])
    assert st["execution_status"] == "succeeded" and st["response_status"] == "released"
    # YOLO on a discovery credential does not grant diagnosis/execution
    with pytest.raises(Exception):  # noqa: B017
        async with env.mcp("execution", env.keys["discovery"]) as c:
            await c.list_tools()
    # YOLO does not bypass target authorization: documentary binding cannot be prepared even by a YOLO execution key
    await env.set_mode("execution-default", "execution", "yolo")
    sub = await env.call("execution", "action_prepare", {"service_id": "doc-only", "binding_id": "prod-doc", "action": "restart"})
    st = await env.wait("execution", sub["request_id"])
    assert st["execution_status"] == "failed"
    res = await env.call("execution", "request_result", {"request_id": sub["request_id"]})
    assert res["error"]["error"] == "authorization_denied"


async def test_narrowed_edit_changes_hash_and_revision(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake", "kube-demo"], "scope": {"regions": ["local-1", "local-2"]}})
    rid = sub["request_id"]
    rev1 = await env.core.db.revision(rid)
    r = await env.approve(rid, edited_args={"providers": ["demo-fake"], "scope": {"regions": ["local-1"]}, "reason": None})
    assert r.status_code == 303
    rev2 = await env.core.db.revision(rid)
    assert rev2["revision"] == 2 and rev2["args_hash"] != rev1["args_hash"]
    ap = await env.core.db.active_approval(rid)
    assert ap["args_hash"] == rev2["args_hash"] and ap["revision"] == 2
    st = await env.wait("discovery", rid)
    assert st["execution_status"] == "succeeded" and st["revision"] == 2
    assert env.demo.calls[-1]["scope"]["regions"] == ["local-1"]
    # the narrowed request only touched demo-fake
    assert not any("list_workloads" in c for c in env.kube.calls)


async def test_mode_change_does_not_drain_queue(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    assert sub["execution_status"] == "pending_request_review"
    await env.set_mode("discovery-default", "discovery", "yolo")
    st = await env.call("discovery", "request_status", {"request_id": sub["request_id"]})
    assert st["execution_status"] == "pending_request_review"  # existing request keeps its obligations
    sub2 = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"], "reason": "second"})
    assert sub2["execution_status"] in ("queued", "running")
    await env.wait("discovery", sub2["request_id"])
    assert (await env.call("discovery", "request_status", {"request_id": sub["request_id"]}))["execution_status"] == "pending_request_review"


async def test_reject_and_cancel(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    await env.reject(sub["request_id"])
    st = await env.call("discovery", "request_status", {"request_id": sub["request_id"]})
    assert st["execution_status"] == "rejected" and st["public_error"] == {"error": "review_required"}
    sub2 = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    st2 = await env.call("discovery", "request_cancel", {"request_id": sub2["request_id"]})
    assert st2["execution_status"] == "cancelled"
    assert env.demo.calls == []


async def test_yolo_override_expires_and_banner_visible(env: Env) -> None:
    c = await env.reviewer()
    p = await env.core.db.principal_by_name("discovery-default")
    r = await c.post("/settings/yolo", data={"csrf": await env.csrf(c), "principal_id": p["id"], "capability": "discovery", "minutes": "5"})
    assert r.status_code == 303
    page = await c.get("/review")
    assert "YOLO active" in page.text
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    assert sub["execution_status"] in ("queued", "running")
    ov = (await env.core.db.active_overrides())[0]
    r = await c.post(f"/settings/yolo/{ov['id']}/revoke", data={"csrf": await env.csrf(c)})
    assert r.status_code == 303
    sub2 = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"], "reason": "after revoke"})
    assert sub2["execution_status"] == "pending_request_review"
    await c.aclose()


async def test_persisted_pending_work_survives_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from tests.conftest import make_env

    async with make_env(tmp_path) as e1:
        sub = await e1.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
        rid = sub["request_id"]
        keys = dict(e1.keys)
        port = e1.port
    # second process-equivalent: new app instance on the same state dir
    from local_ops.app import create_app
    from local_ops.config import load_server_config
    from local_ops.providers.kube_fake import FakeKubeClient
    from local_ops.providers.kubernetes import KubernetesAdapter
    from tests.conftest import FakeRegistryAdapter, run_uvicorn
    cfg = load_server_config(tmp_path / "server.yaml")
    holder: dict = {}
    kube_provider = next(p for p in cfg.providers if p.id == "kube-demo")
    reg_provider = next(p for p in cfg.providers if p.id == "demo-registry")
    app = create_app(cfg, tmp_path / "catalog", provider_overrides={"kube-demo": KubernetesAdapter(kube_provider, cfg, None, client=FakeKubeClient()), "demo-registry": FakeRegistryAdapter(reg_provider, cfg)}, core_holder=holder)
    server, task = await run_uvicorn(app, port)
    try:
        core = holder["core"]
        req = await core.db.request(rid)
        assert req["execution_status"] == "pending_request_review"
        await core.requests.approve(rid, "reviewer")
        for _ in range(100):
            req = await core.db.request(rid)
            if req["execution_status"] == "succeeded":
                break
            await __import__("asyncio").sleep(0.1)
        assert req["execution_status"] == "succeeded"
        assert keys["discovery"]
    finally:
        server.should_exit = True
        await task
