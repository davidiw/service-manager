"""Recovery: crash after dispatch, restart reconciliation without duplicate mutation, stop switch,
cancellation after dispatch, revocation blocking pending dispatch and result retrieval."""

from __future__ import annotations

import asyncio

import pytest

from local_ops.models import Capability, ExecutionStatus
from local_ops.operations.base import Budget
from local_ops.worker import Worker
from tests.conftest import DIGESTS, REPO, Env
from tests.test_execution import finish, prepare, submit

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def yolo(env: Env) -> Env:
    await env.set_mode("write-default", "mutation", "yolo")
    return env


async def test_connection_loss_after_dispatch_reconciles_without_resend(yolo: Env) -> None:
    env = yolo
    env.app_state.version = "2.0.0"
    plan = (await prepare(env))["plan"]
    env.kube.crash_after_patch = True  # patch is applied server-side but the client connection drops
    sub = await submit(env, plan)

    async def later_converge() -> None:
        for _ in range(100):
            if env.kube.patch_log:
                break
            await asyncio.sleep(0.1)
        env.kube.crash_after_patch = False
        await asyncio.sleep(1.0)
        await env.kube.converge("Deployment", "demo", "demo-app")

    task = asyncio.create_task(later_converge())
    out = await finish(env, sub["request_id"])
    await task
    assert len(env.kube.patch_log) == 1
    rc = out["receipt"]
    assert "reconciled" in rc["outcome"] or "reconciled" in " ".join(rc["notes"])
    assert out["_status"]["execution_status"] in ("succeeded", "partial", "outcome_unknown")
    intents = await env.core.db.intents(sub["request_id"])
    assert intents and intents[0]["result"]["status"] == "uncertain"
    # the applied mutation is visible on the target; converge then confirm no second patch happened
    await env.kube.converge("Deployment", "demo", "demo-app")
    assert len(env.kube.patch_log) == 1


async def test_process_restart_mid_dispatch_reconciles(yolo: Env) -> None:
    """Simulate a crash between recording the dispatch intent and recording completion, then run a fresh
    worker's recovery against the same state. The mutation must not be re-sent."""
    env = yolo
    env.app_state.version = "2.0.0"
    plan = (await prepare(env))["plan"]
    # Stop the live worker so we can craft the mid-flight state deterministically.
    await env.core.worker.stop()
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "crash-1"})
    rid = sub["request_id"]
    # emulate: claimed, intent recorded, patch sent, then process died
    await env.core.db.update_request(rid, execution_status=ExecutionStatus.RUNNING.value, phase="dispatching")
    await env.core.db.consume_plan(plan["plan_id"], rid)
    async with env.core.db.tx() as c:
        await c.execute("UPDATE plans SET consumed_by_request_id=? WHERE plan_id=?", (rid, plan["plan_id"]))
    mutation = plan["provider_mutations"][0]
    await env.core.db.record_intent(rid, "dispatching", plan["locks"][0], "update demo-app", {"plan_id": plan["plan_id"], "mutation": mutation})
    await env.kube.patch_workload("Deployment", "demo", "demo-app", mutation["patch"], expected_uid=plan["target"]["uid"], expected_resource_version=None)
    assert len(env.kube.patch_log) == 1
    # fresh worker (as after restart) recovers
    w2 = Worker(env.core.db, env.core.config_ref, env.core.auth, env.core.registry, env.core.providers_ref, env.core.sanitizer, env.core.requests, env.core.catalog_ref)
    await w2.recover()
    assert w2.recovery_report and w2.recovery_report[0]["action"] == "reconciled"
    req = await env.core.db.request(rid)
    assert req["execution_status"] in ("succeeded", "partial")
    assert len(env.kube.patch_log) == 1  # never blindly retried
    rc = await env.core.db.receipt_for_request(rid)
    assert "no mutation was re-sent" in " ".join(rc["body"]["notes"])
    assert await env.core.db.locks() == []
    # a read-only request found running is simply requeued
    sub2 = await env.call("read", "discovery_scan", {"providers": ["demo-fake"]}, key=env.keys["read"])
    await env.core.db.update_request(sub2["request_id"], execution_status=ExecutionStatus.RUNNING.value, phase="running")
    w3 = Worker(env.core.db, env.core.config_ref, env.core.auth, env.core.registry, env.core.providers_ref, env.core.sanitizer, env.core.requests, env.core.catalog_ref)
    await w3.recover()
    assert (await env.core.db.request(sub2["request_id"]))["execution_status"] == "queued"
    # mutation found running with no recorded intent -> safe to requeue
    sub3 = await env.call("write", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    await env.core.db.update_request(sub3["request_id"], execution_status=ExecutionStatus.RUNNING.value, phase="preparing")
    await w3.recover()
    assert (await env.core.db.request(sub3["request_id"]))["execution_status"] == "queued"


async def test_target_gone_after_dispatch_is_outcome_unknown(yolo: Env) -> None:
    env = yolo
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    await env.core.worker.stop()
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "gone-1"})
    rid = sub["request_id"]
    await env.core.db.update_request(rid, execution_status=ExecutionStatus.RUNNING.value, phase="dispatching")
    await env.core.db.record_intent(rid, "dispatching", plan["locks"][0], "restart", {"plan_id": plan["plan_id"], "mutation": plan["provider_mutations"][0]})
    del env.kube.workloads[("Deployment", "demo", "demo-app")]
    w2 = Worker(env.core.db, env.core.config_ref, env.core.auth, env.core.registry, env.core.providers_ref, env.core.sanitizer, env.core.requests, env.core.catalog_ref)
    await w2.recover()
    req = await env.core.db.request(rid)
    assert req["execution_status"] == "outcome_unknown" and req["public_error"]["error"] == "outcome_unknown"


async def test_stop_switch_blocks_dispatch_but_not_diagnosis(yolo: Env) -> None:
    env = yolo
    c = await env.reviewer()
    r = await c.post("/settings/stop", data={"csrf": await env.csrf(c), "stopped": "1"})
    assert r.status_code == 303
    plan = (await prepare(env, action="restart", artifact=None))["plan"]  # read-only prepare still runs
    sub = await submit(env, plan)
    await asyncio.sleep(1.5)
    st = await env.call("write", "request_status", {"request_id": sub["request_id"]})
    assert st["execution_status"] == "queued"
    assert (await env.core.db.request(sub["request_id"]))["phase"] == "blocked_by_stop_switch"
    assert env.kube.patch_log == []
    await env.set_mode("read-default", "content", "yolo")
    d = await env.call("read", "service_inspect", {"service_id": "demo-app"})
    assert (await env.wait("read", d["request_id"]))["execution_status"] == "succeeded"
    r = await c.post("/settings/stop", data={"csrf": await env.csrf(c), "stopped": "0"})
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "succeeded"
    await c.aclose()


async def test_cancel_after_dispatch_records_observed_state(yolo: Env) -> None:
    env = yolo
    env.kube.auto_converge = False  # rollout never converges on its own
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    sub = await submit(env, plan)
    for _ in range(50):
        req = await env.core.db.request(sub["request_id"])
        if req["phase"] == "verifying":
            break
        await asyncio.sleep(0.1)
    assert req["phase"] == "verifying"
    st = await env.call("write", "request_cancel", {"request_id": sub["request_id"]})
    assert st["execution_status"] == "running"
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] in ("partial", "failed")
    rc = out["receipt"]
    assert rc["ran"] == "ran" and len(env.kube.patch_log) == 1
    assert any("cancelled" in c["detail"] for c in rc["health_checks"])


async def test_revocation_blocks_pending_dispatch_and_result_retrieval(env: Env) -> None:
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    await env.core.auth.revoke_key("read-default")
    c = await env.reviewer()
    r = await c.post(f"/review/{rid}/approve", data={"csrf": await env.csrf(c), "note": ""})
    assert r.status_code == 200 and "revoked" in r.text
    assert (await env.core.db.request(rid))["execution_status"] == "rejected"
    assert env.demo.calls == []
    # a released result of another request becomes unreadable after revocation
    _, k2 = await env.core.auth.create_key("tmp-disc", [Capability.READ])
    await env.set_mode("tmp-disc", "inventory", "yolo")
    s2 = await env.call("read", "discovery_scan", {"providers": ["demo-fake"]}, key=k2)
    await env.wait("read", s2["request_id"], key=k2)
    assert (await env.call("read", "request_result", {"request_id": s2["request_id"]}, key=k2))["summary"]
    await env.core.auth.revoke_key("tmp-disc")
    with pytest.raises(Exception):  # noqa: B017
        await env.call("read", "request_result", {"request_id": s2["request_id"]}, key=k2)
    await c.aclose()


async def test_disconnect_is_not_cancellation(yolo: Env) -> None:
    env = yolo
    env.demo.simulate_delay = 1.0
    await env.set_mode("read-default", "inventory", "yolo")
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"]}, key=env.keys["read"])
    # the MCP session used for submission is already closed (env.call closes it); the work continues
    st = await env.wait("read", sub["request_id"], key=env.keys["read"])
    assert st["execution_status"] == "succeeded"


def _unused() -> None:
    _ = (Budget, DIGESTS, REPO)
