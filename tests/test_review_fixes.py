"""Regressions for the independent review blockers: redaction-only release, unscrubbed derived rows,
and artifact-string injection."""

from __future__ import annotations

import pytest

from local_ops.operations.execution import ActionPrepareArgs
from tests.conftest import REPO, Env

pytestmark = pytest.mark.asyncio


async def test_redaction_only_release_grants_no_underlying_rows(env: Env) -> None:
    # B1: redact a field without excluding evidence; the field must not leak via evidence_get or findings_read.
    sub = await env.call("diagnosis", "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("diagnosis", rid)
    priv = await env.core.db.result(rid)
    ev_ids = [e["evidence_id"] for e in priv["candidate"]["evidence"]]
    await env.release(rid, redact_paths="timeline.0.actor")
    res = await env.call("diagnosis", "request_result", {"request_id": rid})
    assert res["timeline"][0]["actor"] == "[REDACTED by reviewer]"
    assert res["evidence"] == [] and res["evidence_withheld_due_to_redaction"] is True
    for eid in ev_ids:
        assert (await env.call("diagnosis", "evidence_get", {"evidence_id": eid}))["__error__"]["error"] == "not_found"
    assert (await env.call("diagnosis", "findings_read", {"request_id": rid}))["count"] == 0
    assert await env.core.db.audit_events(request_id=rid, audience=(await env.core.db.principal_by_name("diagnosis-default"))["id"]) == []


async def test_excluding_evidence_cascades_to_derived_observations(env: Env) -> None:
    sub = await env.call("discovery", "discovery_scan", {"providers": ["demo-fake"]})
    rid = sub["request_id"]
    await env.approve(rid)
    await env.wait("discovery", rid)
    ev = (await env.core.db.evidence_for_request(rid))[0]["id"]
    await env.release(rid, exclude_evidence=ev)
    cat = await env.call("discovery", "catalog_read", {})
    assert cat["unresolved_observations"] == []  # every demo observation derives from the excluded fragment


async def test_observations_are_scrubbed_before_storage(env: Env) -> None:
    # B2: a secret-shaped label on a workload must not reach catalog_read/catalog_export.
    env.kube.workloads[("Deployment", "demo", "orphan-app")]["metadata"]["annotations"] = {"note": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "aws": "AKIAIOSFODNN7EXAMPLE"}
    await env.set_mode("discovery-default", "discovery", "yolo")
    sub = await env.call("discovery", "discovery_scan", {"providers": ["kube-demo"]})
    await env.wait("discovery", sub["request_id"])
    cat = await env.call("discovery", "catalog_read", {})
    exp = await env.call("discovery", "catalog_export", {"format": "json"})
    for blob in (str(cat), str(exp)):
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in blob and "AKIAIOSFODNN7EXAMPLE" not in blob
    rows = await env.core.db.observations()
    assert "AKIAIOSFODNN7EXAMPLE" not in str(rows)


@pytest.mark.parametrize("bad", [
    f"{REPO}@sha256:x,securityContext.privileged=true",
    f"{REPO}:v2,image.pullPolicy=Always",
    f"{REPO}@sha256:{'a' * 63}",
    f"{REPO}:v2 --post-renderer=/bin/sh",
])
async def test_artifact_injection_rejected_at_boundary(bad: str) -> None:
    # B3: the tool argument model rejects anything that is not repository[:tag][@sha256:<64 hex>].
    with pytest.raises(ValueError):
        ActionPrepareArgs(service_id="demo-app", binding_id="demo-deployment", action="update", desired_artifact=bad)


async def test_artifact_injection_rejected_through_mcp(env: Env) -> None:
    await env.set_mode("execution-default", "execution", "yolo")
    r = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "update", "desired_artifact": f"{REPO}@sha256:x,securityContext.privileged=true"})
    assert r["__error__"]["error"] == "invalid_argument"
    assert env.kube.patch_log == []


async def test_controller_owned_workload_refused(env: Env) -> None:
    await env.set_mode("execution-default", "execution", "yolo")
    env.kube.workloads[("Deployment", "demo", "demo-app")]["metadata"]["owner_references"] = [{"kind": "SomeOperator", "name": "op", "uid": "u1"}]
    sub = await env.call("execution", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "restart"})
    await env.wait("execution", sub["request_id"])
    res = await env.call("execution", "request_result", {"request_id": sub["request_id"]})
    assert res["error"]["error"] == "unsupported_deployment_mechanism"
