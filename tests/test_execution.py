"""Execution acceptance: digest pinning, stale/recreated target, idempotency conflicts, plan replay,
two services on one workload, lock contention, GitOps refusal, failed health checks, unapproved rollback,
unauthorized targets and capability escalation."""

from __future__ import annotations

import asyncio
import uuid

import pytest

from tests.conftest import DIGESTS, REPO, Env

pytestmark = pytest.mark.asyncio


async def prepare(env: Env, service: str = "demo-app", binding: str = "demo-deployment", action: str = "update", artifact: str | None = f"{REPO}:v2", *, key: str | None = None) -> dict:  # type: ignore[type-arg]
    args = {"service_id": service, "binding_id": binding, "action": action}
    if artifact:
        args["desired_artifact"] = artifact
    sub = await env.call("write", "action_prepare", args, key)
    if "__error__" in sub:
        return sub
    st = await env.wait("write", sub["request_id"], key=key)
    res = await env.call("write", "request_result", {"request_id": sub["request_id"]}, key)
    res["_status"] = st
    return res


async def submit(env: Env, plan: dict, idem: str | None = None, *, key: str | None = None) -> dict:  # type: ignore[type-arg]
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": idem or str(uuid.uuid4())}, key)
    return sub


async def finish(env: Env, rid: str, *, key: str | None = None) -> dict:  # type: ignore[type-arg]
    st = await env.wait("write", rid, timeout=60, key=key)
    if st["response_status"] == "released":
        res = await env.call("write", "request_result", {"request_id": rid}, key)
        res["_status"] = st
        return res
    return {"_status": st}


@pytest.fixture
async def yolo(env: Env) -> Env:
    await env.set_mode("write-default", "mutation", "yolo")
    return env


async def test_update_pins_digest_and_verifies_health(yolo: Env) -> None:
    env = yolo
    res = await prepare(env)
    plan = res["plan"]
    assert plan["requested_artifact"]["digest"] == DIGESTS["v2"] and plan["requested_artifact"]["reference"] == f"{REPO}@{DIGESTS['v2']}"
    assert plan["requested_artifact"]["version_label"] == "2.0.0"
    assert plan["current_artifact"]["reference"] == f"{REPO}@{DIGESTS['v1']}"
    assert plan["target"]["uid"] == env.kube.workloads[("Deployment", "demo", "demo-app")]["metadata"]["uid"]
    assert plan["provider_mutations"][0]["patch"]["spec"]["template"]["spec"]["containers"][0]["image"] == f"{REPO}@{DIGESTS['v2']}"
    assert plan["health_checks"] == ["ready_replicas", "demo_http_health", "demo_http_version"]
    assert env.registry.resolved == [f"{REPO}:v2"]
    env.app_state.version = "2.0.0"  # the fake app will report the new version after rollout
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "succeeded", out
    rc = out["receipt"]
    assert rc["ran"] == "ran" and rc["after_artifact"]["reference"] == f"{REPO}@{DIGESTS['v2']}"
    assert all(c["passed"] for c in rc["health_checks"]) and {c["check_id"] for c in rc["health_checks"]} == {"ready_replicas", "demo_http_health", "demo_http_version"}
    assert rc["before_state"]["images"][0][1] == f"{REPO}@{DIGESTS['v1']}" and rc["after_state"]["images"][0][1] == f"{REPO}@{DIGESTS['v2']}"
    assert out["verified_health"] is True
    assert env.kube.patch_log[-1]["patch"]["spec"]["template"]["spec"]["containers"][0]["image"].endswith(DIGESTS["v2"])
    assert (await env.core.db.plan(plan["plan_id"]))["consumed_by_request_id"] == sub["request_id"]


async def test_restart_uses_request_specific_annotation(yolo: Env) -> None:
    env = yolo
    res = await prepare(env, action="restart", artifact=None)
    plan = res["plan"]
    assert plan["action"] == "restart" and plan["requested_artifact"]["reference"] == plan["current_artifact"]["reference"]
    ann = plan["provider_mutations"][0]["patch"]["spec"]["template"]["metadata"]["annotations"]
    assert ann["local-ops.dev/restart-plan"].startswith("req:")
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "succeeded"
    wl = env.kube.workloads[("Deployment", "demo", "demo-app")]
    assert wl["spec"]["template"]["metadata"]["annotations"]["local-ops.dev/restart-plan"] == ann["local-ops.dev/restart-plan"]
    assert wl["spec"]["template"]["spec"]["containers"][0]["image"].endswith(DIGESTS["v1"])  # restart never changes the image


async def test_tag_without_registry_coverage_is_refused(yolo: Env) -> None:
    res = await prepare(yolo, artifact="registry.other/x/y:v9")
    assert res["error"]["error"] == "authorization_denied"  # repo not in allowed_image_repositories


async def test_stale_target_rejected_before_dispatch(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env))["plan"]
    # someone else changes the image between prepare and submit
    wl = env.kube.workloads[("Deployment", "demo", "demo-app")]
    wl["spec"]["template"]["spec"]["containers"][0]["image"] = f"{REPO}@sha256:{'ff' * 32}"
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "rejected"
    assert out["error"]["error"] == "plan_stale"
    assert env.kube.patch_log == []


async def test_recreated_target_rejected(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env))["plan"]
    del env.kube.workloads[("Deployment", "demo", "demo-app")]
    env.kube.add_deployment("demo", "demo-app", f"{REPO}@{DIGESTS['v1']}", replicas=2)
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "rejected" and out["error"]["error"] == "plan_stale"
    assert env.kube.patch_log == []


async def test_idempotency_key_same_payload_returns_same_request_and_conflict_on_different(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env))["plan"]
    env.app_state.version = "2.0.0"
    s1 = await submit(env, plan, "key-1")
    s2 = await submit(env, plan, "key-1")
    assert s1["request_id"] == s2["request_id"] and s2["existing"] is True
    await finish(env, s1["request_id"])
    plan2 = (await prepare(env, action="restart", artifact=None))["plan"]
    s3 = await submit(env, plan2, "key-1")
    assert s3["__error__"]["error"] == "conflict"
    assert len(env.kube.patch_log) == 1


async def test_plan_replay_with_another_key_does_not_execute_again(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env))["plan"]
    env.app_state.version = "2.0.0"
    s1 = await submit(env, plan, "k-a")
    await finish(env, s1["request_id"])
    s2 = await submit(env, plan, "k-b")
    assert s2["__error__"]["error"] == "conflict" and "already submitted" in s2["__error__"]["message"]
    assert len(env.kube.patch_log) == 1


async def test_plan_only_submittable_by_preparing_principal_and_after_release(env: Env) -> None:
    # execution-default prepares under review_both; before release the multi key cannot submit it, and even
    # after release only the preparing principal may submit.
    sub = await env.call("write", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("write", rid)
    priv = await env.core.db.result(rid)
    plan = priv["candidate"]["plan"]
    s = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "x1"})
    assert s["__error__"]["error"] == "not_found"  # not released to the principal yet
    await env.release(rid)
    s = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "x2"}, key=env.keys["multi"])
    assert s["__error__"]["error"] in ("not_found", "authorization_denied")
    s = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": "deadbeef", "idempotency_key": "x3"})
    assert s["__error__"]["error"] == "plan_stale"
    s = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "x4"})
    assert s["execution_status"] == "pending_request_review"
    # mutation plans cannot be edited at approval time
    r = await env.approve(s["request_id"], edited_args={"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "reason": "edited"})
    assert r.status_code == 200 and "cannot be edited" in r.text
    await env.approve(s["request_id"])
    out = await finish(env, s["request_id"])
    assert out["_status"]["execution_status"] == "succeeded" and out["_status"]["response_status"] == "pending_response_review"


async def test_two_services_on_one_workload_serialize_on_shared_boundary(yolo: Env) -> None:
    env = yolo
    env.kube.converge_delay = 2.0
    p1 = (await prepare(env, action="restart", artifact=None))["plan"]
    p2 = (await prepare(env, service="demo-app-alias", binding="alias-binding", action="restart", artifact=None))["plan"]
    assert p1["locks"] == p2["locks"]  # same workload UID -> same lock key regardless of service name
    s1 = await submit(env, p1)
    s2 = await submit(env, p2)
    await asyncio.sleep(0.5)
    rows = {r["id"]: r for r in await env.core.db.requests_list(limit=10)}
    states = {rows[s1["request_id"]]["execution_status"], rows[s2["request_id"]]["execution_status"]}
    assert "running" in states and ("queued" in states)
    waiting = [r for r in rows.values() if r["execution_status"] == "queued"]
    assert waiting and str(waiting[0]["phase"]).startswith("waiting_for_lock")
    o1 = await finish(env, s1["request_id"])
    o2 = await finish(env, s2["request_id"])
    assert o1["_status"]["execution_status"] == "succeeded"
    # The second plan was prepared against the pre-restart template; once the first restart changed the
    # target, the second is detected stale at dispatch rather than applied blindly.
    assert o2["_status"]["execution_status"] == "rejected" and o2["error"]["error"] == "plan_stale"
    assert len(env.kube.patch_log) == 1
    assert await env.core.db.locks() == []
    # Prepared after the first completes, the alias service's restart applies normally.
    p3 = (await prepare(env, service="demo-app-alias", binding="alias-binding", action="restart", artifact=None))["plan"]
    o3 = await finish(env, (await submit(env, p3))["request_id"])
    assert o3["_status"]["execution_status"] == "succeeded" and len(env.kube.patch_log) == 2


async def test_gitops_ownership_refused(yolo: Env) -> None:
    res = await prepare(yolo, service="gitops-app", binding="gitops-binding")
    assert res["error"]["error"] == "unsupported_deployment_mechanism"
    assert "argocd" in res["error"]["message"]
    assert yolo.kube.patch_log == []


async def test_failed_health_checks_do_not_auto_rollback(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env, artifact=f"{REPO}:v2-broken"))["plan"]
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "failed"
    rc = out["receipt"]
    assert rc["ran"] == "ran"
    ready = next(c for c in rc["health_checks"] if c["check_id"] == "ready_replicas")
    assert ready["passed"] is False and ("crash" in ready["detail"] or "converge" in ready["detail"])
    assert rc["rollback_result"] is None
    assert env.kube.workloads[("Deployment", "demo", "demo-app")]["spec"]["template"]["spec"]["containers"][0]["image"].endswith(DIGESTS["v2-broken"])
    assert len(env.kube.patch_log) == 1
    assert out["verified_health"] is False


async def test_explicit_rollback_to_previous_replicaset(yolo: Env) -> None:
    env = yolo
    env.app_state.version = "2.0.0"
    plan = (await prepare(env))["plan"]
    await finish(env, (await submit(env, plan))["request_id"])
    rb = (await prepare(env, action="rollback", artifact=None))["plan"]
    assert rb["action"] == "rollback" and rb["requested_artifact"]["reference"] == f"{REPO}@{DIGESTS['v1']}"
    env.app_state.version = "1.0.0"
    out = await finish(env, (await submit(env, rb))["request_id"])
    assert out["_status"]["execution_status"] == "succeeded"
    assert env.kube.workloads[("Deployment", "demo", "demo-app")]["spec"]["template"]["spec"]["containers"][0]["image"].endswith(DIGESTS["v1"])


async def test_rollback_refused_when_not_declared(yolo: Env) -> None:
    res = await prepare(yolo, service="demo-app-alias", binding="alias-binding", action="rollback", artifact=None)
    assert res["error"]["error"] == "unsupported_operation"


async def test_unauthorized_targets_and_escalation(env: Env) -> None:
    await env.set_mode("write-default", "mutation", "yolo")
    # documentary binding on the seed-like service
    res = await prepare(env, service="doc-only", binding="prod-doc", action="restart", artifact=None)
    assert res["error"]["error"] == "authorization_denied"
    # unknown service / binding
    res = await prepare(env, service="nope", binding="x", action="restart", artifact=None)
    assert res["error"]["error"] == "not_found"
    # update on a service whose binding only declares restart
    res = await prepare(env, service="demo-app-alias", binding="alias-binding", action="update")
    assert res["error"]["error"] == "unsupported_operation"
    # read credentials cannot prepare or submit at all (transport-level 403 and tool-level denial)
    for k in ("read",):
        with pytest.raises(Exception):  # noqa: B017
            async with env.mcp("write", env.keys[k]) as c:
                await c.list_tools()
    # execution credential cannot run diagnosis queries
    with pytest.raises(Exception):  # noqa: B017
        async with env.mcp("read", env.keys["write"]) as c:
            await c.list_tools()
    # the multi key can prepare but YOLO for execution-default does not extend to it
    sub = await env.call("write", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"}, key=env.keys["multi"])
    assert sub["execution_status"] == "pending_request_review"


async def test_catalog_revision_change_invalidates_plan(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env))["plan"]
    (env.catalog_dir / "services" / "demo-db.md").write_text((env.catalog_dir / "services" / "demo-db.md").read_text() + "\nchanged\n")
    env.core.reload_catalog()
    s = await submit(env, plan)
    assert s["__error__"]["error"] == "plan_stale"
    assert env.kube.patch_log == []


async def test_execution_disabled_catalog_refuses_mutations(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from tests.conftest import make_env

    async with make_env(tmp_path, execution_allowed=False) as env:
        await env.set_mode("write-default", "mutation", "yolo")
        res = await prepare(env, action="restart", artifact=None)
        assert res["error"]["error"] == "authorization_denied"


async def test_statefulset_requires_enrollment(yolo: Env) -> None:
    env = yolo
    wl = env.kube.workloads[("Deployment", "demo", "demo-app")]
    ss = dict(wl)
    ss["kind"] = "StatefulSet"
    ss["spec"] = {**wl["spec"], "update_strategy": {"type": "OnDelete"}}
    env.kube.workloads[("StatefulSet", "demo", "demo-ss")] = ss
    (env.catalog_dir / "services" / "ss.md").write_text("""---
schema_version: 1
id: demo-ss
name: statefulset
environments: [demo]
bindings:
  - id: ss
    environment: demo
    provider_id: kube-demo
    namespace: demo
    workload_kind: StatefulSet
    workload_name: demo-ss
    container_name: app
    cluster_identity: kube-demo
    execution_enabled: true
    source_state: verified
operations:
  restart:
    executor: kubernetes_native
    kind: rollout_restart
    binding_id: ss
    health_checks: [ready_replicas]
---
x
""")
    env.core.reload_catalog()
    res = await prepare(env, service="demo-ss", binding="ss", action="restart", artifact=None)
    assert res["error"]["error"] == "unsupported_operation" and "enrollment" in res["error"]["message"]
