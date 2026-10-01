"""Withheld or redacted evidence must not leak through IDs, catalog/search/export, errors, derived
findings, another principal or a redacted result's original. Secrets and malicious strings are
scrubbed/escaped."""

from __future__ import annotations

import pytest

from tests.conftest import Env

pytestmark = pytest.mark.asyncio


async def _run_released(env: Env, cap: str, tool: str, args: dict, *, release: bool = True) -> str:  # type: ignore[type-arg]
    sub = await env.call(cap, tool, args)
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait(cap, rid)
    if release:
        await env.release(rid)
    return rid


async def test_withheld_result_does_not_leak_anywhere(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    await env.approve(rid)
    st = await env.wait("discovery", rid)
    assert st["response_status"] == "pending_response_review"
    await env.withhold(rid)
    st = await env.call("discovery", "request_status", {"request_id": rid})
    assert st["response_status"] == "withheld" and st["public_error"] is None
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert res["__error__"]["error"] == "authorization_denied" and "demo" not in str(res).lower().replace("demo-fake", "")
    # evidence ids from the private result are not readable
    priv = await env.core.db.result(rid)
    for e in priv["candidate"].get("evidence", []):
        r = await env.call("discovery", "evidence_get", {"evidence_id": e["evidence_id"]})
        assert r["__error__"]["error"] == "not_found"
    # catalog read shows no observations from the withheld scan
    cat = await env.call("discovery", "catalog_read", {})
    assert cat["unresolved_observations"] == []
    assert all(s["observed"]["observation_count"] == 0 for s in cat["services"])
    gaps = await env.call("discovery", "catalog_gaps", {})
    assert not any(g["kind"] in ("unresolved_workload", "unexplained_resource") for g in gaps["gaps"])
    exp = await env.call("discovery", "catalog_export", {"format": "markdown"})
    assert "Observed runtime state" not in "".join(exp["files"].values())
    # another principal cannot read it either, nor guess ids
    res2 = await env.call("discovery", "request_result", {"request_id": rid}, key=env.keys["multi"])
    assert res2["__error__"]["error"] == "not_found"
    st2 = await env.call("discovery", "request_status", {"request_id": rid}, key=env.keys["multi"])
    assert st2["__error__"]["error"] == "not_found"


async def test_release_then_withhold_blocks_further_reads(env: Env) -> None:
    rid = await _run_released(env, "discovery", "discovery_scan", {"providers": ["demo-fake"]})
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert res["summary"]["observations"] > 0
    await env.withhold(rid)
    assert (await env.call("discovery", "request_result", {"request_id": rid}))["__error__"]["error"] == "authorization_denied"


async def test_redacted_release_hides_fields_and_original(env: Env) -> None:
    sub = await env.call("diagnosis", "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events", "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("diagnosis", rid)
    priv = await env.core.db.result(rid)
    ev_id = priv["candidate"]["evidence"][0]["evidence_id"]
    await env.release(rid, redact_paths="items.0.actor, items.1.source_ip", exclude_evidence=ev_id)
    res = await env.call("diagnosis", "request_result", {"request_id": rid})
    assert res["items"][0]["actor"] == "[REDACTED by reviewer]"
    assert res["items"][1]["source_ip"] == "[REDACTED by reviewer]"
    assert res["items"][2]["actor"] == "carol-departed"
    assert res["redaction_record"]["paths"] == ["items.0.actor", "items.1.source_ip"]
    assert all(e["evidence_id"] != ev_id for e in res.get("evidence", []))
    r = await env.call("diagnosis", "evidence_get", {"evidence_id": ev_id})
    assert r["__error__"]["error"] == "not_found"
    # the original unredacted candidate is not reachable through any agent tool
    priv2 = await env.core.db.result(rid)
    assert priv2["candidate"]["items"][0]["actor"] == "alice"


async def test_derived_findings_require_released_evidence(env: Env) -> None:
    sub = await env.call("diagnosis", "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("diagnosis", rid)
    assert (await env.call("diagnosis", "findings_read", {"request_id": rid}))["__error__"]["error"] == "review_required"
    assert (await env.call("diagnosis", "findings_read", {}))["count"] == 0
    priv = await env.core.db.result(rid)
    assert priv["candidate"]["finding_count"] > 0
    await env.withhold(rid)
    assert (await env.call("diagnosis", "findings_read", {}))["count"] == 0
    assert (await env.call("diagnosis", "findings_read", {"request_id": rid}))["__error__"]["error"] == "authorization_denied"
    await env.release(rid)
    fr = await env.call("diagnosis", "findings_read", {"request_id": rid})
    assert fr["count"] == priv["candidate"]["finding_count"]
    # investigation page for reviewer shows findings; agent of another key cannot see them
    assert (await env.call("diagnosis", "findings_read", {}, key=env.keys["multi"]))["count"] == 0


async def test_provider_error_messages_are_scrubbed_and_private(env: Env) -> None:
    env.demo.fail_next = True
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    await env.approve(rid)
    st = await env.wait("discovery", rid)
    assert st["execution_status"] in ("failed", "partial")
    await env.release(rid)
    res = await env.call("discovery", "request_result", {"request_id": rid})
    assert "AKIAIOSFODNN7EXAMPLE" not in str(res)
    assert "secret-should-not-leak" not in str(res)
    row = await env.core.db.request(rid)
    assert "AKIA" not in (row.get("private_error") or "") or "[REDACTED" in str(row.get("private_error"))


async def test_secret_shaped_strings_scrubbed_from_logs_and_evidence(env: Env) -> None:
    rid = await _run_released(env, "diagnosis", "evidence_query", {"source_id": "demo-fake", "query_type": "demo_logs"})
    res = await env.call("diagnosis", "request_result", {"request_id": rid})
    text = str(res)
    assert "hunter2" not in text and "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in text and "AKIAIOSFODNN7EXAMPLE" not in text
    assert "X-Amz-Signature=abcdef" not in text
    assert "[REDACTED" in text
    ev = await env.call("diagnosis", "evidence_get", {"evidence_id": res["evidence"][0]["evidence_id"]})
    assert "hunter2" not in ev["content"] and "[REDACTED" in ev["content"]
    assert ev["sanitization"]["removed"]


async def test_ui_renders_provider_strings_as_text(env: Env) -> None:
    rid = await _run_released(env, "diagnosis", "evidence_query", {"source_id": "demo-fake", "query_type": "demo_logs"})
    c = await env.reviewer()
    page = await c.get(f"/review/{rid}")
    assert "<script>alert" not in page.text and "&lt;script&gt;alert" in page.text
    assert "default-src 'self'" in page.headers["content-security-policy"]
    ev_id = (await env.core.db.evidence_for_request(rid))[0]["id"]
    ep = await c.get(f"/review/{rid}/evidence/{ev_id}")
    assert "<script>alert" not in ep.text
    await c.aclose()


async def test_status_before_release_reveals_no_result_preview(env: Env) -> None:
    sub = await env.call("diagnosis", "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events"})
    rid = sub["request_id"]
    await env.approve(rid)
    st = await env.wait("diagnosis", rid)
    assert set(st.keys()) <= {"request_id", "operation", "capability", "execution_status", "response_status", "review_url", "submitted_at", "updated_at", "revision", "poll_after_ms", "public_error"}
    assert "carol" not in str(st)
