"""Investigation and evidence pipeline through the live server: findings, timeline, coverage, dedup and
late arrival, event-time versus collection-time, cursor persistence ordering, unsupported queries,
unconfigured sources, and service inspection (live and documentary bindings)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tests.conftest import DIGESTS, Env

pytestmark = pytest.mark.asyncio


async def _yolo(env: Env) -> None:
    r = await env.set_mode("read-default", "content", "yolo")
    assert r.status_code == 303, r.text


async def _run(env: Env, tool: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    sub = await env.call("read", tool, args)
    assert "__error__" not in sub, sub
    rid = sub["request_id"]
    st = await env.wait("read", rid, timeout=60)
    assert st["response_status"] == "released", st
    res = await env.call("read", "request_result", {"request_id": rid, "limit": 500})
    assert "__error__" not in res, res
    return rid, res


# ----------------------------------------------------------------------- (a) suspicious investigation


async def test_investigation_suspicious_result_shape(env: Env) -> None:
    await _yolo(env)
    rid, res = await _run(env, "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    assert res["execution_status"] == "succeeded"
    assert res["finding_count"] >= 6
    assert res["finding_count"] == len(res["findings"])
    rules = {f["rule_id"].split(".")[0] for f in res["findings"]}
    assert {"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"} <= rules
    times = [t["time"] for t in res["timeline"]]
    assert times == sorted(times) and len(times) >= 20
    assert {t["provider"] for t in res["timeline"]} == {"aws", "kubernetes", "github"}
    cov = res["coverage"]
    assert "demo-fake/local-1" in cov["completed_scopes"]
    assert cov["conclusion_scope"]
    assert cov["time_range_requested"]["start"] < cov["time_range_requested"]["end"]
    assert res["hypotheses"] and any("suspected intrusion" in h["statement"] for h in res["hypotheses"])
    assert any(a["action"] == "preserve_evidence" and a["executable"] is False for a in res["possible_actions"])
    assert res["negative_result_statement"] is None
    assert res["next_queries"]
    assert all(e["evidence_id"] for e in res["evidence"])
    # findings persisted and readable once released
    fr = await env.call("read", "findings_read", {"request_id": rid})
    assert fr["count"] == res["finding_count"]


# ----------------------------------------------------------------------- (b) benign investigation


async def test_investigation_benign_has_no_unsupported_conclusion(env: Env) -> None:
    await _yolo(env)
    _, res = await _run(env, "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "benign"}})
    assert res["execution_status"] == "succeeded"
    rules = {f["rule_id"].split(".")[0] for f in res["findings"]}
    assert not rules & {"R1", "R4", "R5", "R7", "R8"}
    assert not any(f["severity"] == "critical" for f in res["findings"])
    for f in res["findings"]:
        if f["rule_id"].startswith("R2"):
            assert f["title"].endswith("CreateAccessKey") and any("ci-deployer" in x for x in f["observed_facts"])
    if res["findings"]:
        assert res["negative_result_statement"] is None
        assert res["finding_count"] == len(res["findings"]) > 0
    else:
        assert res["finding_count"] == 0
        assert "not a claim that no intrusion occurred" in res["negative_result_statement"]
    # whatever the finding list, the coverage statement never claims more than the completed scopes
    assert "no conclusion about unavailable" in res["coverage"]["conclusion_scope"]
    assert not any(a["action"] == "preserve_evidence" for a in res["possible_actions"]) or any(f["severity"] in ("critical", "high") for f in res["findings"])


# ----------------------------------------------------------------------- (c) dedup / late arrival / event time


async def test_dedup_late_arrival_and_event_time_preserved(env: Env) -> None:
    await _yolo(env)
    q = {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "benign"}}
    _, first = await _run(env, "evidence_query", q)
    assert first["event_count"] == 7
    assert first["events_new"] == 7 and first["events_duplicate"] == 0
    await asyncio.sleep(0.05)
    _, second = await _run(env, "evidence_query", q)
    assert second["event_count"] == 7
    assert second["events_duplicate"] == 7 and second["events_new"] == 0
    rows = await env.core.db.audit_events(source_ids=["demo-fake"])
    assert len(rows) == 7
    assert len({r["event_key"] for r in rows}) == 7
    for r in rows:
        assert r["occurred_at"].startswith("2026-09-30T1")  # fixture event time (10:00..11:00)
        assert r["collected_at"] != r["occurred_at"]
        assert r["collected_at"] > r["occurred_at"]  # collected now, long after it occurred
    # late arrival of an already-seen subset only counts duplicates
    late = {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "benign", "event_names": ["UpdateTrail"]}}
    _, third = await _run(env, "evidence_query", late)
    assert third["event_count"] == 1 and third["events_duplicate"] == 1 and third["events_new"] == 0
    assert "event_names" in third["coverage"]["filters_local"]
    # genuinely new events (other scenario) are inserted without touching the earlier rows
    _, sus = await _run(env, "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "suspicious"}})
    assert sus["events_new"] == 14 and sus["events_duplicate"] == 0
    after = await env.core.db.audit_events(source_ids=["demo-fake"])
    assert len(after) == 21
    assert {r["event_key"]: r["collected_at"] for r in rows}.items() <= {r["event_key"]: r["collected_at"] for r in after}.items()


# ----------------------------------------------------------------------- (d) cursor checkpoint


async def test_cursor_saved_only_after_events_are_persisted(env: Env) -> None:
    await _yolo(env)
    await _run(env, "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "benign"}})
    # the demo provider returns no cursor: nothing is checkpointed
    assert await env.core.db.cursors() == []
    assert await env.core.db.cursor("demo-fake", "{}") is None
    db = env.core.db
    events = [{
        "event_key": f"cloudtrail:acct:page-{i}", "provider": "aws", "source_id": "aws-x", "account": "acct", "region": "r1", "event_id": f"page-{i}",
        "occurred_at": f"2026-09-30T11:00:0{i}Z", "collected_at": "2026-09-30T12:00:00Z", "actor": "a", "actor_type": "IAMUser", "session": None,
        "action": "DescribeInstances", "resource": None, "resource_type": None, "source_ip": "203.0.113.1", "user_agent": "x", "outcome": "success",
        "category": "management", "evidence_ref": None, "fields": {},
    } for i in range(3)]
    # persistence-after-page ordering: events first, cursor only once they exist
    inserted, dups = await db.upsert_audit_events(None, events)
    assert (inserted, dups) == (3, 0)
    assert await db.cursor("aws-x", "scope-a") is None
    stored = await db.audit_events(source_ids=["aws-x"])
    assert len(stored) == 3
    await db.save_cursor("aws-x", "scope-a", "tok-1", stored[-1]["occurred_at"])
    cur = await db.cursor("aws-x", "scope-a")
    assert cur and cur["cursor"] == "tok-1" and cur["last_event_at"] == "2026-09-30T11:00:02Z"
    # replaying the same page after a crash is a no-op and the checkpoint advances monotonically
    assert await db.upsert_audit_events(None, events) == (0, 3)
    await db.save_cursor("aws-x", "scope-a", "tok-2", "2026-09-30T11:00:05Z", note="resumed")
    cur2 = await db.cursor("aws-x", "scope-a")
    assert cur2["cursor"] == "tok-2" and cur2["note"] == "resumed" and cur2["updated_at"] >= cur["updated_at"]
    assert len(await db.cursors()) == 1


# ----------------------------------------------------------------------- (e) unsupported query type


async def test_unsupported_query_type_is_reported_in_coverage(env: Env) -> None:
    await _yolo(env)
    sub = await env.call("read", "evidence_query", {"source_id": "demo-fake", "query_type": "pagerduty_incidents"})
    rid = sub["request_id"]
    st = await env.wait("read", rid)
    # the demo adapter still lists its fixture scope as completed, so the outcome is partial (not failed)
    assert st["execution_status"] == "partial"
    res = await env.call("read", "request_result", {"request_id": rid})
    cov = res["coverage"]
    assert [(u["source"], u["reason"]) for u in cov["unavailable_scopes"]] == [("demo-fake", "unsupported_query_type")]
    assert cov["unavailable_scopes"][0]["detail"] == "pagerduty_incidents"
    assert res["event_count"] == 0 and res["items"] == []
    assert "no evidence collected" in cov["conclusion_scope"].lower()


# ----------------------------------------------------------------------- (f) unconfigured source


async def test_unconfigured_source_fails_with_provider_unavailable(env: Env) -> None:
    await _yolo(env)
    sub = await env.call("read", "evidence_query", {"source_id": "aws-nowhere", "query_type": "cloudtrail_events"})
    st = await env.wait("read", sub["request_id"])
    assert st["execution_status"] == "failed"
    assert st["public_error"]["error"] == "provider_unavailable"
    res = await env.call("read", "request_result", {"request_id": sub["request_id"]})
    assert res["error"]["error"] == "provider_unavailable"
    assert env.demo.calls == []


# ----------------------------------------------------------------------- (g) service_inspect


async def test_service_inspect_live_binding(env: Env) -> None:
    await _yolo(env)
    _, res = await _run(env, "service_inspect", {"service_id": "demo-app"})
    assert res["execution_status"] == "succeeded"
    rt = res["items"][0]
    assert rt["binding_id"] == "demo-deployment" and rt["inspectable"] is True
    wl = rt["workload"]
    assert wl["found"] is True
    assert any(DIGESTS["v1"] in d["image"] for d in wl["desired_images"])
    assert wl["rollout"]["converged"] is True
    assert res["hypotheses"] and any("converged" in h["statement"] for h in res["hypotheses"])
    assert any(q["tool"] == "evidence_query" and q["arguments"]["query_type"] == "container_logs" for q in res["next_queries"])
    assert any(q["tool"] == "investigation_run" and q["arguments"]["sources"] == ["demo-fake"] for q in res["next_queries"])
    assert "kube-demo/demo" in res["coverage"]["completed_scopes"]
    assert res["dependencies"][0]["service_id"] == "demo-db" and res["dependencies"][0]["known"] is True
    assert res["possible_actions"] == []


async def test_service_inspect_documentary_binding_is_not_inspectable(env: Env) -> None:
    await _yolo(env)
    sub = await env.call("read", "service_inspect", {"service_id": "demo-db"})
    st = await env.wait("read", sub["request_id"])
    assert st["execution_status"] == "partial"
    res = await env.call("read", "request_result", {"request_id": sub["request_id"]})
    rt = res["items"][0]
    assert rt["inspectable"] is False and rt["source_state"] == "documentary"
    assert rt["documentary"]["region"] == "local-1"
    cov = res["coverage"]
    assert [(u["source"], u["reason"]) for u in cov["unavailable_scopes"]] == [("demo-fake", "binding_not_inspectable")]
    assert cov["completed_scopes"] == []
    assert any(q["tool"] == "discovery_scan" for q in res["next_queries"])
    assert res["service"]["contradictions"] and res["service"]["contradictions"][0]["topic"] == "region"
    assert res["hypotheses"] == []


async def test_service_inspect_crashloop_hypothesis_and_restart_caveats(env: Env) -> None:
    await _yolo(env)
    env.kube.make_crashlooping("demo", "demo-app")
    _, res = await _run(env, "service_inspect", {"service_id": "demo-app"})
    crash = [h for h in res["hypotheses"] if "crash-looping" in h["statement"]]
    assert crash and crash[0]["support"] in ("weak", "moderate")
    assert any("crash-looping/restarting" in o for o in crash[0]["supporting_observations"])
    restart = [a for a in res["possible_actions"] if a["action"] == "restart"]
    assert len(restart) == 1
    assert restart[0]["service_id"] == "demo-app" and restart[0]["binding_id"] == "demo-deployment"
    assert restart[0]["executable"] is True
    assert any("intrusion" in w for w in restart[0]["inappropriate_when"])
    assert any("credentials" in w for w in restart[0]["inappropriate_when"])
    assert any("CrashLoopBackOff" in o or "ready=False" in o for o in res["observations"])


# ----------------------------------------------------------------------- (h) generic_workload recipe


async def test_investigation_generic_workload_includes_workload_section(env: Env) -> None:
    await _yolo(env)
    _, res = await _run(env, "investigation_run", {"recipe": "generic_workload", "service_id": "demo-app", "filters": {"scenario": "benign"}})
    assert res["recipe"] == "generic_workload" and res["service_id"] == "demo-app"
    wl = res["workload"]
    assert set(wl) == {"observations", "hypotheses", "next_queries", "possible_actions", "runtime"}
    assert wl["runtime"][0]["inspectable"] is True
    assert any(DIGESTS["v1"] in d["image"] for d in wl["runtime"][0]["workload"]["desired_images"])
    # the service's audit source (demo-fake) was consulted and the inspection scope merged into coverage
    assert "demo-fake/local-1" in res["coverage"]["completed_scopes"]
    assert "kube-demo/demo" in res["coverage"]["completed_scopes"]
    assert any("Deployment/demo-app" in o for o in res["observations"])
    assert res["hypotheses"]


async def test_service_inspect_resolves_resource_key_bindings_through_released_observations(env: Env) -> None:
    # Operational-map bindings (D25) name workloads by exact resource key; inspect resolves each to its
    # name through an observation released to the caller, and skips keys that were never released.
    await _yolo(env)
    assert (await env.set_mode("read-default", "inventory", "yolo")).status_code == 303
    await _run(env, "discovery_scan", {"providers": ["kube-demo"]})
    obs = (await env.call("read", "observations_query", {"provider_id": "kube-demo", "resource_type": "k8s/Deployment"}))["items"]
    key = next(o["resource_key"] for o in obs if o["identity"]["name"] == "demo-app")
    unreleased = "k8s:kube-demo:demo:Deployment:00000000-never-observed"
    assert env.catalog_dir is not None
    (env.catalog_dir / "services" / "demo-keys.md").write_text(
        "---\nschema_version: 1\nid: demo-keys\nname: Demo by resource key\nenvironments: [demo]\nbindings:\n"
        f"  - id: by-key\n    environment: demo\n    provider_id: kube-demo\n    resource_keys: ['{key}', '{unreleased}']\n---\n",
        encoding="utf-8",
    )
    env.core.reload_catalog()
    _, res = await _run(env, "service_inspect", {"service_id": "demo-keys", "include_dependencies": False})
    assert res["execution_status"] == "succeeded"
    [rt] = res["items"]
    assert rt["inspectable"] is True and rt["target"]["workload_name"] == "demo-app" and rt["target"]["resource_key"] == key
    assert rt["workload"]["found"] is True and rt["workload"]["rollout"]["converged"] is True
    logs_q = next(q for q in res["next_queries"] if q["arguments"].get("query_type") == "container_logs")
    assert logs_q["arguments"]["scope"]["workload_name"] == "demo-app"
    assert "runtime" not in res  # items is the only (paged) copy of the per-workload detail
    gaps = [g for g in env.core.catalog.gaps() if g["service_id"] == "demo-keys"]
    assert not any(g["kind"] == "documentary_binding" for g in gaps)


def _container(restarts: int, finished_at: str | None) -> dict[str, Any]:
    last = {"terminated": {"exit_code": 0, "reason": "Completed", "finished_at": finished_at}} if finished_at else {}
    return {"pod": "p-0", "container": "c", "state": "running", "ready": True, "restart_count": restarts, "last_state": last}


async def test_crash_loop_needs_a_recent_termination_and_hypotheses_name_workloads(env: Env) -> None:
    from datetime import timedelta

    from local_ops.models import iso, utcnow
    from local_ops.operations.diagnosis import ServiceInspectArgs, _generic_workload_reasoning

    spec = env.core.catalog.service("demo-app").spec
    args = ServiceInspectArgs(service_id="demo-app", lookback_minutes=60)

    def rt(name: str, container: dict[str, Any]) -> dict[str, Any]:
        return {"binding_id": "demo-deployment", "target": {"namespace": "demo", "workload_kind": "Deployment", "workload_name": name}, "inspectable": True, "workload": {"rollout": {"ready": 1, "desired": 1, "converged": True}, "running": [container], "total_restarts": container["restart_count"]}, "events": [], "logs": [], "previous_logs": []}

    old = rt("old-restarts", _container(4, "2026-05-26 06:11:43+00:00"))
    fresh = rt("fresh-restarts", _container(4, iso(utcnow() - timedelta(minutes=5))))
    quiet = rt("quiet", _container(0, None))
    hyps, _, _ = _generic_workload_reasoning(spec, [old, fresh, quiet], args)
    crash = [h.statement for h in hyps if "crash-looping" in h.statement]
    assert crash == [crash[0]] and "Deployment/fresh-restarts" in crash[0]
    [ready] = [h for h in hyps if "converged and ready" in h.statement]
    assert "2 of 3 inspected workload(s)" in ready.statement
    assert any("Deployment/old-restarts" in o for o in ready.supporting_observations)
