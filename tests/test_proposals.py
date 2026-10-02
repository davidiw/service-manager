"""Catalog knowledge and agent proposals (DECISIONS D24): assistants propose, reviewers accept into a
patch, humans commit; saved queries run as ordinary reviewed evidence queries."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from local_ops.catalog import load_catalog
from local_ops.operations.diagnosis import expand_saved_query
from tests.conftest import Env

ROOT = Path(__file__).resolve().parent.parent

QUERY = {"id": "recent_errors", "description": "Recent error lines", "source_id": "kube-demo", "query_type": "container_logs", "scope": {"namespace": "demo", "workload_kind": "Deployment", "workload_name": "demo-app"}, "filters": {"grep": "error"}, "limits": {"max_events": 200}, "lookback_minutes": 30}
SIGNATURE = {"id": "redis_unreachable", "match": {"source": "container_logs", "contains": "ECONNREFUSED 6379"}, "meaning": "Redis is down; the app is healthy.", "first_steps": ["service_inspect demo-db"]}


async def _revision(env: Env) -> str:
    return str((await env.call("read", "catalog_read", {"service_id": "demo-app", "include_observed": False}))["catalog"]["revision"])


async def _propose(env: Env, changes: list[dict[str, Any]], *, service_id: str = "demo-app", revision: str | None = None, cap: str = "read", key: str | None = None) -> dict[str, Any]:
    return await env.call(cap, "catalog_propose", {"service_id": service_id, "base_revision": revision or await _revision(env), "changes": changes, "reason": "learned during a test"}, key)


async def _reviewer_post(env: Env, path: str, note: str = "") -> Any:
    c = await env.reviewer()
    csrf = await env.csrf(c)
    return await c.post(path, data={"csrf": csrf, "note": note})


def _git_apply(env: Env, patch: str) -> None:
    assert env.catalog_dir is not None and Path(patch).exists()
    subprocess.run(["git", "apply", patch], cwd=env.catalog_dir, check=True, capture_output=True)
    env.core.reload_catalog()


async def test_knowledge_proposal_round_trip(env: Env) -> None:
    changes = [
        {"op": "add", "path": "/knowledge/queries/-", "value": QUERY},
        {"op": "add", "path": "/knowledge/failure_signatures/-", "value": SIGNATURE},
        {"op": "add", "path": "/unknowns/-", "value": "who rotates the Redis password"},
    ]
    res = await _propose(env, changes)
    assert res["status"] == "pending_review" and res["existing"] is False and res["changes"] == 3
    again = await _propose(env, changes)
    assert again["proposal_id"] == res["proposal_id"] and again["existing"] is True

    listed = await env.call("read", "catalog_proposals", {})
    assert [p["proposal_id"] for p in listed["proposals"]] == [res["proposal_id"]]
    assert listed["proposals"][0]["status"] == "pending_review"

    c = await env.reviewer()
    page = await c.get(f"/proposals/{res['proposal_id']}")
    assert page.status_code == 200 and "recent_errors" in page.text and "+knowledge:" in page.text
    r = await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept", "looks right")
    assert r.status_code == 303
    row = await env.core.db.proposal(res["proposal_id"])
    assert row["status"] == "accepted" and row["patch_path"].endswith(f"{res['proposal_id']}.patch")

    _git_apply(env, row["patch_path"])
    spec = env.core.catalog.service("demo-app").spec
    assert [q.id for q in spec.knowledge.queries] == ["recent_errors"]
    assert spec.knowledge.failure_signatures[0].match.contains == "ECONNREFUSED 6379"
    listed = await env.call("read", "catalog_proposals", {})
    assert listed["proposals"][0]["status"] == "applied" and listed["proposals"][0]["decision_note"] == "looks right"

    # the applied saved query now runs as an ordinary, reviewed evidence_query
    sub = await env.call("read", "saved_query_run", {"service_id": "demo-app", "query_id": "recent_errors"})
    st = await env.wait("read", sub["request_id"])
    assert st["execution_status"] == "pending_request_review"
    rev = await env.core.db.revision(sub["request_id"])
    assert rev["args"]["saved_query"].startswith("demo-app/recent_errors@") and rev["args"]["query_type"] == "container_logs"
    inspect = await env.call("read", "catalog_read", {"service_id": "demo-app"})
    assert inspect["services"][0]["spec"]["knowledge"]["queries"][0]["id"] == "recent_errors"


async def test_unknown_saved_query_is_not_found(env: Env) -> None:
    res = await env.call("read", "saved_query_run", {"service_id": "demo-app", "query_id": "nope"})
    assert res["__error__"]["error"] == "not_found"


async def test_authority_fields_are_not_proposable(env: Env) -> None:
    for change in (
        {"op": "replace", "path": "/operations/restart/readiness_timeout_seconds", "value": 5},
        {"op": "add", "path": "/credential_refs/-", "value": {"id": "x", "kind": "k8s_secret", "held_in": "cluster"}},
        {"op": "replace", "path": "/bindings/0/namespace", "value": "prod"},
        {"op": "add", "path": "/bindings/-", "value": {"id": "b2", "environment": "demo", "provider_id": "kube-demo", "execution_enabled": True}},
        {"op": "replace", "path": "/approved_by", "value": "an assistant"},
        {"op": "replace", "path": "/disposition", "value": "retire"},
        {"op": "add", "path": "/health_checks/-", "value": {"id": "h", "kind": "http_status", "url": "http://x"}},
        {"op": "replace", "path": "/id", "value": "other"},
    ):
        res = await _propose(env, [change])
        assert res["__error__"]["error"] == "authorization_denied", change
    assert await env.core.db.proposals() == []


async def test_new_service_with_non_executable_binding(env: Env) -> None:
    binding = {"id": "cache", "environment": "demo", "provider_id": "kube-demo", "namespace": "demo", "workload_kind": "StatefulSet", "workload_name": "redis", "source_state": "observed"}
    res = await _propose(env, [
        {"op": "replace", "path": "/name", "value": "Demo Redis"},
        {"op": "add", "path": "/purpose", "value": "Session cache for demo-app."},
        {"op": "add", "path": "/environments", "value": ["demo"]},
        {"op": "add", "path": "/bindings/-", "value": binding},
    ], service_id="demo-redis")
    assert res["new_service"] is True, res
    row = await env.core.db.proposal(res["proposal_id"])
    assert row["diff"].startswith("--- /dev/null") and row["target_path"] == "services/demo-redis.md"
    await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept")
    _git_apply(env, (await env.core.db.proposal(res["proposal_id"]))["patch_path"])
    doc = env.core.catalog.service("demo-redis")
    assert doc is not None and doc.spec.bindings[0].execution_enabled is False and not env.core.catalog.errors


async def test_stale_revision_secret_content_and_invalid_queries_are_refused(env: Env) -> None:
    stale = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "x"}], revision="not-the-revision")
    assert stale["__error__"]["error"] == "plan_stale"
    secret = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "token ghp_" + "a" * 36}])
    assert secret["__error__"]["error"] == "invalid_argument" and "credential-shaped" in secret["__error__"]["message"]
    bad_type = await _propose(env, [{"op": "add", "path": "/knowledge/queries/-", "value": {**QUERY, "query_type": "shell"}}])
    assert bad_type["__error__"]["error"] == "invalid_argument"
    bad_source = await _propose(env, [{"op": "add", "path": "/knowledge/queries/-", "value": {**QUERY, "source_id": "nowhere"}}])
    assert bad_source["__error__"]["error"] == "invalid_argument" and "not a configured provider" in bad_source["__error__"]["message"]
    invalid_spec = await _propose(env, [{"op": "replace", "path": "/environments", "value": ["prod"]}])
    assert invalid_spec["__error__"]["error"] == "invalid_argument"  # existing binding's environment no longer listed
    assert await env.core.db.proposals() == []


async def test_citations_must_be_released_to_the_proposer(env: Env) -> None:
    eid = "evd_" + "c" * 20
    await env.core.db.insert_evidence(eid, None, "kube-demo", "container_logs", b'{"lines": ["ECONNREFUSED 6379"]}', "logs", None, None)
    change = {"op": "add", "path": "/knowledge/failure_signatures/-", "value": SIGNATURE, "evidence": [eid]}
    denied = await _propose(env, [change])
    assert denied["__error__"]["error"] == "authorization_denied"
    principal = await env.core.db.principal_by_name("read-default")
    async with env.core.db.tx() as c:
        await c.execute("UPDATE evidence SET released_to=? WHERE id=?", (f'["{principal["id"]}"]', eid))
    ok = await _propose(env, [change])
    assert ok["status"] == "pending_review"
    assert (await env.core.db.proposal(ok["proposal_id"]))["citations"] == [eid]
    # another principal cannot cite it
    from local_ops.models import Capability

    _, other_key = await env.core.auth.create_key("other-read", [Capability.READ])
    other = await _propose(env, [change], key=other_key)
    assert other["__error__"]["error"] == "authorization_denied"


async def test_proposal_goes_stale_when_the_file_changes_and_cannot_be_accepted(env: Env) -> None:
    res = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "backup schedule"}])
    assert env.catalog_dir is not None
    f = env.catalog_dir / "services" / "demo-app.md"
    f.write_text(f.read_text(encoding="utf-8").replace("Tiny HTTP service", "Small HTTP service"), encoding="utf-8")
    env.core.reload_catalog()
    assert (await env.call("read", "catalog_proposals", {}))["proposals"][0]["status"] == "stale"
    r = await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept")
    assert "stale" in r.text
    assert (await env.core.db.proposal(res["proposal_id"]))["status"] == "pending_review"
    r = await _reviewer_post(env, f"/proposals/{res['proposal_id']}/reject", "stale")
    assert r.status_code == 303 and (await env.core.db.proposal(res["proposal_id"]))["status"] == "rejected"


async def test_reviewer_proposal_pages_require_session_and_csrf(env: Env) -> None:
    res = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "x"}])
    import httpx

    async with httpx.AsyncClient(base_url=env.base_url, follow_redirects=False) as anon:
        assert (await anon.get("/proposals")).status_code in (302, 303, 401)
    c = await env.reviewer()
    r = await c.post(f"/proposals/{res['proposal_id']}/accept", data={"csrf": "wrong"})
    assert r.status_code == 403
    assert (await env.core.db.proposal(res["proposal_id"]))["status"] == "pending_review"
    listing = await c.get("/proposals")
    assert re.search(res["proposal_id"], listing.text)


def test_demo_catalog_knowledge_expands_to_a_valid_query() -> None:
    cat = load_catalog(ROOT / "catalog" / "demo")
    assert not cat.errors
    args = expand_saved_query(cat, "demo-app", "recent_errors")
    assert args.query_type == "container_logs" and args.saved_query == f"demo-app/recent_errors@{cat.revision}"
    assert args.time_range is not None and (args.time_range.end - args.time_range.start).total_seconds() == 30 * 60


async def test_line_separators_and_missing_final_newline_still_apply(env: Env) -> None:
    """git splits lines on \\n only; the diff must agree, including a file with no final newline."""
    assert env.catalog_dir is not None
    f = env.catalog_dir / "services" / "demo-app.md"
    f.write_text(f.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8")
    env.core.reload_catalog()
    folded = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "odd\u0085here"}])
    assert folded["__error__"]["error"] == "invalid_argument" and "round-trip" in folded["__error__"]["message"]
    res = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "odd\u2028separator here"}])
    await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept")
    _git_apply(env, (await env.core.db.proposal(res["proposal_id"]))["patch_path"])
    assert "odd\u2028separator here" in env.core.catalog.service("demo-app").spec.unknowns


async def test_reproposal_reports_the_real_status_and_bindings_cannot_claim_identity(env: Env) -> None:
    change = [{"op": "add", "path": "/unknowns/-", "value": "who owns backups"}]
    first = await _propose(env, change)
    await _reviewer_post(env, f"/proposals/{first['proposal_id']}/reject", "not useful")
    again = await _propose(env, change)
    assert again["proposal_id"] == first["proposal_id"] and again["existing"] is True and again["status"] == "rejected"
    for extra in ({"source_state": "verified"}, {"cluster_identity": "kube-demo"}, {"workload_uid": "u-1"}):
        binding = {"id": "b9", "environment": "demo", "provider_id": "kube-demo", **extra}
        res = await _propose(env, [{"op": "add", "path": "/bindings/-", "value": binding}])
        assert res["__error__"]["error"] == "authorization_denied", extra


async def test_reviewer_edit_drops_saved_query_provenance(env: Env) -> None:
    res = await _propose(env, [{"op": "add", "path": "/knowledge/queries/-", "value": QUERY}])
    await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept")
    _git_apply(env, (await env.core.db.proposal(res["proposal_id"]))["patch_path"])
    sub = await env.call("read", "saved_query_run", {"service_id": "demo-app", "query_id": "recent_errors"})
    await env.wait("read", sub["request_id"])
    args = dict((await env.core.db.revision(sub["request_id"]))["args"])
    args["filters"] = {"grep": "panic"}
    r = await env.approve(sub["request_id"], edited_args=args)
    assert r.status_code == 303, r.text
    assert (await env.core.db.revision(sub["request_id"]))["args"]["saved_query"] is None


async def test_proposals_stack_per_service_and_reject_superseded(env: Env) -> None:
    old = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "first draft"}])
    new = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "second draft"}])
    c = await env.reviewer()
    page = (await c.get("/proposals")).text
    assert page.index(new["proposal_id"]) < page.index(old["proposal_id"])  # newest heads the stack
    assert "1 superseded by the one above" in page and "Reject 1 superseded" in page
    state = (await c.get("/api/ui/queue")).json()
    assert state["pending_proposals"] == 2 and state["fingerprint"]

    r = await _reviewer_post(env, f"/proposals/{new['proposal_id']}/reject-superseded")
    assert r.status_code == 303 and r.headers["location"] == "/proposals"
    assert (await env.core.db.proposal(old["proposal_id"]))["decision_note"] == f"superseded by {new['proposal_id']}"
    assert (await env.core.db.proposal(new["proposal_id"]))["status"] == "pending_review"
    after = (await c.get("/api/ui/queue")).json()
    assert after["pending_proposals"] == 1 and after["fingerprint"] != state["fingerprint"]


async def test_proposal_decision_returns_to_the_list_and_filter_hides_decided(env: Env) -> None:
    res = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "who owns backups"}])
    c = await env.reviewer()
    csrf = await env.csrf(c)
    r = await c.post(f"/proposals/{res['proposal_id']}/reject", data={"csrf": csrf, "next": "/proposals"})
    assert r.headers["location"] == "/proposals"
    bad = await c.post(f"/proposals/{res['proposal_id']}/accept", data={"csrf": csrf, "next": "//evil.example"})
    assert "evil" not in bad.headers.get("location", "")
    assert res["proposal_id"] not in (await c.get("/proposals")).text
    assert res["proposal_id"] in (await c.get("/proposals?show=all")).text


async def test_applied_new_service_file_is_canonical(env: Env) -> None:
    res = await _propose(env, [{"op": "replace", "path": "/name", "value": "Fresh service"}], service_id="fresh-svc")
    await _reviewer_post(env, f"/proposals/{res['proposal_id']}/accept")
    _git_apply(env, (await env.core.db.proposal(res["proposal_id"]))["patch_path"])
    assert env.core.catalog.service("fresh-svc") is not None
    follow = await _propose(env, [{"op": "add", "path": "/unknowns/-", "value": "who owns it"}], service_id="fresh-svc")
    assert follow["status"] == "pending_review"
    assert not any("canonical" in w for w in follow.get("warnings", [])), follow
