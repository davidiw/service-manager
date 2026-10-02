"""Regressions for the lifecycle-transition review findings: lost-update races on approve/reject/cancel,
withhold not revoking derived grants, cross-principal receipts in service_inspect, and plan consumption
not being atomic with the owning request's insert."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from local_ops.models import ErrorCode, ExecutionStatus, OpsError, utcnow
from tests.conftest import Env

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------- approve vs reject race
async def test_approve_reject_race_leaves_request_rejected(env: Env) -> None:
    """A reject that completes during approve()'s awaits must not be clobbered by a stale approval."""
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    svc = env.core.requests
    orig_principal = env.core.auth.principal
    reject_ran = False

    async def racing_principal(pid: str):  # type: ignore[no-untyped-def]
        nonlocal reject_ran
        if not reject_ran:
            reject_ran = True
            await svc.reject(rid, "reviewer", "race")
        return await orig_principal(pid)

    env.core.auth.principal = racing_principal  # type: ignore[method-assign]
    try:
        with pytest.raises(OpsError) as exc:
            await svc.approve(rid, "reviewer")
        assert exc.value.code == ErrorCode.CONFLICT
    finally:
        env.core.auth.principal = orig_principal  # type: ignore[method-assign]

    req = await env.core.db.request(rid)
    assert req is not None and req["execution_status"] == "rejected"
    assert await env.core.db.active_approval(rid) is None
    assert env.demo.calls == []  # never queued/dispatched


# ---------------------------------------------------------------------------- cancel vs worker-claim race
async def test_cancel_loses_race_to_worker_claim_falls_through_to_running(env: Env) -> None:
    """If the worker claims a request for dispatch during cancel()'s awaits, cancel must not report
    'cancelled before dispatch' for a request that is actually running; it must fall through to the
    running-cancellation behaviour instead."""
    await env.core.worker.stop()  # take manual control of dispatch so the race is deterministic
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    await env.approve(rid)
    req = await env.core.db.request(rid)
    assert req is not None and req["execution_status"] == "queued"
    principal = await env.core.auth.principal(req["principal_id"])
    assert principal is not None

    db = env.core.requests.db
    orig_transition = db.transition_request
    triggered = False

    async def racing_transition(request_id: str, expected, **fields):  # type: ignore[no-untyped-def]
        nonlocal triggered
        if not triggered and ExecutionStatus.QUEUED.value in expected:
            triggered = True
            await db.claim_queued("race-worker", limit=10)  # simulate the worker winning the race
        return await orig_transition(request_id, expected, **fields)

    db.transition_request = racing_transition  # type: ignore[method-assign]
    try:
        status = await env.core.requests.cancel(principal, rid)
    finally:
        db.transition_request = orig_transition  # type: ignore[method-assign]

    assert status.execution_status == ExecutionStatus.RUNNING
    req = await env.core.db.request(rid)
    assert req is not None
    assert req["execution_status"] == "running"  # never clobbered to "cancelled"
    assert req["cancel_requested_at"] is not None
    assert req["finished_at"] is None


# ---------------------------------------------------------------------------- withhold revokes derived grants
async def test_withhold_revokes_previously_released_derived_grants(env: Env) -> None:
    sub = await env.call("diagnosis", "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("diagnosis", rid)
    priv = await env.core.db.result(rid)
    ev_ids = [e["evidence_id"] for e in priv["candidate"]["evidence"]]
    assert ev_ids
    await env.release(rid)

    assert (await env.call("diagnosis", "evidence_get", {"evidence_id": ev_ids[0]}))["evidence_id"] == ev_ids[0]
    assert (await env.call("diagnosis", "findings_read", {}))["count"] > 0

    await env.withhold(rid)

    assert (await env.call("diagnosis", "evidence_get", {"evidence_id": ev_ids[0]}))["__error__"]["error"] == "not_found"
    assert (await env.call("diagnosis", "findings_read", {}))["count"] == 0
    # request-scoped findings_read also refuses: the response itself is withheld again
    assert (await env.call("diagnosis", "findings_read", {"request_id": rid}))["__error__"]["error"] == "authorization_denied"


async def test_withheld_plan_cannot_be_submitted(env: Env) -> None:
    sub = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("execution", rid)
    await env.release(rid)
    priv = await env.core.db.result(rid)
    plan = priv["released"]["plan"]
    plan_row = await env.core.db.plan(plan["plan_id"])
    assert plan_row is not None and plan_row["released_to"]  # sanity: released

    await env.withhold(rid)
    plan_row = await env.core.db.plan(plan["plan_id"])
    assert plan_row is not None and plan_row["released_to"] == []

    s = await env.call("execution", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "wh-1"})
    assert s["__error__"]["error"] == "not_found"


async def test_redacted_rerelease_after_withhold_leaves_derived_rows_unreleased(env: Env) -> None:
    """release -> withhold -> redacted re-release must leave raw evidence unreadable: withhold revokes
    the first (unredacted) grant, and the redacted re-release deliberately grants none of the rows."""
    sub = await env.call("diagnosis", "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("diagnosis", rid)
    priv = await env.core.db.result(rid)
    ev_ids = [e["evidence_id"] for e in priv["candidate"]["evidence"]]
    assert ev_ids
    await env.release(rid)
    assert (await env.call("diagnosis", "evidence_get", {"evidence_id": ev_ids[0]}))["evidence_id"] == ev_ids[0]

    await env.withhold(rid)
    await env.release(rid, redact_paths="timeline.0.actor")

    assert (await env.call("diagnosis", "evidence_get", {"evidence_id": ev_ids[0]}))["__error__"]["error"] == "not_found"
    assert (await env.call("diagnosis", "findings_read", {"request_id": rid}))["count"] == 0


# ---------------------------------------------------------------------------- cross-principal receipts
async def test_service_inspect_omits_receipts_not_released_to_the_caller(env: Env) -> None:
    await env.set_mode("multi", "execution", "yolo")
    await env.set_mode("multi", "diagnosis", "yolo")
    await env.set_mode("diagnosis-default", "diagnosis", "yolo")

    sub = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"}, key=env.keys["multi"])
    await env.wait("execution", sub["request_id"], key=env.keys["multi"])
    res = await env.call("execution", "request_result", {"request_id": sub["request_id"]}, key=env.keys["multi"])
    plan = res["plan"]
    s = await env.call("execution", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "rcpt-1"}, key=env.keys["multi"])
    await env.wait("execution", s["request_id"], key=env.keys["multi"])

    def recent_ops(result: dict) -> list:  # type: ignore[type-arg]
        item = next(r for r in result["runtime"] if r["binding_id"] == "demo-deployment")
        return [op["request_id"] for op in item["recent_operations"]]

    owner_sub = await env.call("diagnosis", "service_inspect", {"service_id": "demo-app", "binding_id": "demo-deployment"}, key=env.keys["multi"])
    owner_res = await env.wait("diagnosis", owner_sub["request_id"], key=env.keys["multi"])
    assert owner_res["response_status"] == "released"
    owner_result = await env.call("diagnosis", "request_result", {"request_id": owner_sub["request_id"]}, key=env.keys["multi"])
    assert s["request_id"] in recent_ops(owner_result)  # the owning principal sees its own receipt

    other_sub = await env.call("diagnosis", "service_inspect", {"service_id": "demo-app", "binding_id": "demo-deployment"}, key=env.keys["diagnosis"])
    other_res = await env.wait("diagnosis", other_sub["request_id"], key=env.keys["diagnosis"])
    assert other_res["response_status"] == "released"
    other_result = await env.call("diagnosis", "request_result", {"request_id": other_sub["request_id"]}, key=env.keys["diagnosis"])
    assert s["request_id"] not in recent_ops(other_result)  # a different principal never sees it


# ---------------------------------------------------------------------------- plan consumption atomicity
async def test_concurrent_identical_submission_is_idempotent_not_conflict(env: Env) -> None:
    await env.set_mode("execution-default", "execution", "yolo")
    psub = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    await env.wait("execution", psub["request_id"])
    res = await env.call("execution", "request_result", {"request_id": psub["request_id"]})
    plan = res["plan"]

    args = {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": "race-key-1"}
    r1, r2 = await asyncio.gather(
        env.call("execution", "action_submit", args),
        env.call("execution", "action_submit", args),
    )
    assert "__error__" not in r1, r1
    assert "__error__" not in r2, r2
    assert r1["request_id"] == r2["request_id"]
    assert r1.get("existing") or r2.get("existing")
    await env.wait("execution", r1["request_id"])
    assert len(env.kube.patch_log) == 1  # the plan was only ever executed once, not once per racer
    assert (await env.core.db.plan(plan["plan_id"]))["consumed_by_request_id"] == r1["request_id"]


async def test_plan_consumption_rolled_back_when_request_insert_fails(env: Env) -> None:
    """insert_request_with_plan must be all-or-nothing: if the request insert fails, the plan's
    consumption in the same attempt is rolled back with it rather than left stranded."""
    db = env.core.db
    pid = (await db.principal_by_name("execution-default"))["id"]
    existing = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    dup_id = existing["request_id"]  # id already present in `requests`, so re-inserting it fails
    plan_id = "plan_collision_test"
    await db.insert_plan(plan_id, dup_id, pid, "hashX", {"plan_id": plan_id}, "service:demo-app", utcnow() + timedelta(minutes=5))
    row = {
        "id": dup_id, "principal_id": pid, "capability": "execution", "operation": "action_submit", "reason": None,
        "execution_status": "queued", "response_status": "unavailable", "phase": None, "idempotency_key": None, "idempotency_hash": None,
        "review_request": 0, "review_response": 0, "review_mode": "yolo", "catalog_revision": "r1", "target_key": None, "plan_id": plan_id, "audience": [pid],
    }
    with pytest.raises(Exception):  # noqa: B017 - sqlite's own IntegrityError, not an OpsError
        await db.insert_request_with_plan(row, "{}", "hashY", idempotency_key=None, consume_plan_id=plan_id)
    plan_row = await db.plan(plan_id)
    assert plan_row is not None and plan_row["consumed_at"] is None  # not stranded by the failed insert
