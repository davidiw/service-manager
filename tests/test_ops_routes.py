"""Operational pages, the observations_query/access_report MCP tools, and proposed resource bindings respect
the release boundary (D26): only released observations appear, unreleased evidence is never linked, the
pages carry no execution controls, and a proposal cannot bind resources the proposer was never shown."""

from __future__ import annotations

import json
from typing import Any

from local_ops.models import Capability
from tests.conftest import Env

PROVIDER = "demo-fake"


async def _principal_id(env: Env, cap: Capability) -> str:
    return next(p.id for p in await env.core.auth.list_principals() if p.has(cap))


async def _observe(env: Env, key: str, name: str, *, released_to: list[str], evidence_released: bool = True, tags: dict[str, str] | None = None) -> str:
    db = env.core.db
    eid = f"evd_{name}"
    await db.insert_evidence(eid, "req_ops_test", PROVIDER, "aws_ec2", json.dumps({"instance": name}).encode(), f"evidence for {name}", {}, {})
    if evidence_released:
        async with db.tx() as c:
            await c.execute("UPDATE evidence SET released_to=? WHERE id=?", (json.dumps(released_to or ["someone"]), eid))
    row = {"provider_id": PROVIDER, "resource_key": key, "resource_type": "aws/ec2_instance", "identity": {"account": "123456789012", "region": "us-west-2", "arn": key, "instance_id": key.rsplit("/", 1)[-1]}, "attributes": {"name": name, "state": "running", "private_ip": "10.1.2.3", "tags": tags or {"Name": name}, "relationships": []}, "evidence_id": eid, "scope_key": f"{PROVIDER}/123456789012/us-west-2/ec2"}
    (oid,) = await db.upsert_observations("req_ops_test", [row])
    async with db.tx() as c:
        await c.execute("UPDATE observations SET released_to=? WHERE id=?", (json.dumps(released_to), oid))
    return oid


KEY = "arn:aws:ec2:us-west-2:123456789012:instance/"


async def test_ops_pages_show_only_released_observations(env: Env) -> None:
    disc = await _principal_id(env, Capability.READ)
    await _observe(env, KEY + "i-released", "released-node", released_to=[disc])
    await _observe(env, KEY + "i-pending", "pending-node", released_to=[])
    await _observe(env, KEY + "i-ev-withheld", "withheld-evidence-node", released_to=[disc], evidence_released=False)
    c = await env.reviewer()
    inv = await c.get(f"/ops/inventory?provider={PROVIDER}&type=aws/ec2_instance")
    assert inv.status_code == 200 and "released-node" in inv.text and "pending-node" not in inv.text
    gone = await c.get("/ops/resource", params={"provider": PROVIDER, "key": KEY + "i-pending"})
    assert "no released observation" in gone.text and "pending-node" not in gone.text
    ok = await c.get("/ops/resource", params={"provider": PROVIDER, "key": KEY + "i-released"})
    assert ok.status_code == 200 and "/evidence/evd_released-node" in ok.text and "10.1.2.3" in ok.text
    wh = await c.get("/ops/resource", params={"provider": PROVIDER, "key": KEY + "i-ev-withheld"})
    assert "evd_withheld-evidence-node not released" in wh.text and "/evidence/evd_withheld-evidence-node" not in wh.text
    index = await c.get("/ops")
    assert index.status_code == 200 and "1 observations not released" in index.text


async def test_ops_pages_require_reviewer_session(env: Env) -> None:
    import httpx

    async with httpx.AsyncClient(base_url=env.base_url, follow_redirects=False) as anon:
        for path in ("/ops", "/ops/services/demo-app", "/ops/inventory", "/ops/access", "/ops/access/guide.md"):
            r = await anon.get(path)
            assert r.status_code == 303 and r.headers["location"].startswith("/login"), path
        r = await anon.get("/ops", headers={"Authorization": f"Bearer {env.keys['read']}"})
        assert r.status_code == 303  # agent API keys never reach reviewer routes


async def test_service_page_has_no_execution_controls(env: Env) -> None:
    c = await env.reviewer()
    page = await c.get("/ops/services/demo-app")
    assert page.status_code == 200 and "Where it runs" in page.text and "What we don't know" in page.text
    forms = page.text.count('method="post"')
    assert forms == 1 and 'action="/logout"' in page.text  # only the logout form in the header
    assert "no controls" in page.text
    missing = await c.get("/ops/services/not-a-service")
    assert "not in catalog" in missing.text


async def test_access_page_and_guide_render_with_unknown_coverage(env: Env) -> None:
    c = await env.reviewer()
    page = await c.get("/ops/access", params={"person": "alice"})
    assert page.status_code == 200 and "Identity Center coverage complete" in page.text
    assert "No released scan reported Identity Center coverage" in page.text
    assert "That is not evidence of no access" in page.text
    md = await c.get("/ops/access/guide.md")
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown") and "Identity Center coverage complete: **False**" in md.text


async def test_observations_query_returns_only_rows_released_to_caller(env: Env) -> None:
    disc = await _principal_id(env, Capability.READ)
    diag = (await env.core.auth.create_key("other-read", [Capability.READ]))[0].id
    await _observe(env, KEY + "i-mine", "mine", released_to=[disc], tags={"Role": "validator"})
    await _observe(env, KEY + "i-theirs", "theirs", released_to=[diag], tags={"Role": "validator"})
    res = await env.call("read", "observations_query", {"provider_id": PROVIDER, "tag_key": "Role", "tag_value": "validator", "include_related": True})
    assert [i["label"] for i in res["items"]] == ["mine (i-mine)"] and res["total"] == 1
    assert res["items"][0]["relationships"] == [] and res["items"][0]["coverage"]["status"] == "never_scanned"
    assert (await env.call("read", "observations_query", {"text": "THEIRS"}))["total"] == 0
    err = await env.call("read", "observations_query", {"limit": 0})
    assert "__error__" in err


async def test_access_report_tool_is_coverage_qualified(env: Env) -> None:
    res = await env.call("read", "access_report", {"person": "nobody@example.invalid"})
    assert res["onboarding"]["coverage"]["identity_center_complete"] is False
    assert any("not evidence that the person has no access" in x for x in res["offboarding"]["limits"])


async def _revision(env: Env) -> str:
    return str((await env.call("read", "catalog_read", {"service_id": "demo-app", "include_observed": False}))["catalog"]["revision"])


async def test_proposed_binding_resource_keys_must_be_released_to_proposer(env: Env) -> None:
    disc = await _principal_id(env, Capability.READ)
    await _observe(env, KEY + "i-seen", "seen", released_to=[disc])
    await _observe(env, KEY + "i-unseen", "unseen", released_to=[])

    def binding(bid: str, keys: list[str]) -> dict[str, Any]:
        return {"op": "add", "path": "/bindings/-", "value": {"id": bid, "environment": "demo", "provider_id": PROVIDER, "workload_kind": "EC2", "resource_keys": keys}}

    rev = await _revision(env)
    denied = await env.call("read", "catalog_propose", {"service_id": "demo-app", "base_revision": rev, "changes": [binding("hosts", [KEY + "i-seen", KEY + "i-unseen"])]})
    assert denied["__error__"]["error"] == "authorization_denied" and "i-unseen" in denied["__error__"]["message"]
    bad_provider = await env.call("read", "catalog_propose", {"service_id": "demo-app", "base_revision": rev, "changes": [{**binding("hosts", [KEY + "i-seen"]), "value": {**binding("hosts", [KEY + "i-seen"])["value"], "provider_id": "nope"}}]})
    assert bad_provider["__error__"]["error"] == "invalid_argument"
    no_tags = await env.call("read", "catalog_propose", {"service_id": "demo-app", "base_revision": rev, "changes": [{"op": "add", "path": "/bindings/-", "value": {"id": "sel", "environment": "demo", "provider_id": PROVIDER, "selector": {"resource_types": ["aws/ec2_instance"], "tags": {}}}}]})
    assert no_tags["__error__"]["error"] == "invalid_argument"
    ok = await env.call("read", "catalog_propose", {"service_id": "demo-app", "base_revision": rev, "changes": [binding("hosts", [KEY + "i-seen"])], "reason": "host observed"})
    assert ok["status"] == "pending_review"
