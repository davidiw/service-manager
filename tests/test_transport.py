"""Transport and authentication: all three mounts initialize, keys are enforced, sessions are bound
to credentials, invalid Host/Origin rejected, no open sensitive REST route."""

from __future__ import annotations

import httpx
import httpx2
import pytest
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from tests.conftest import Env

pytestmark = pytest.mark.asyncio


async def test_all_mounts_initialize_and_list_tools(env: Env) -> None:
    expected = {
        "read": {"discovery_scan", "catalog_read", "catalog_gaps", "catalog_export", "catalog_propose", "catalog_proposals", "observations_query", "access_report",
                 "service_inspect", "evidence_query", "investigation_run", "findings_read", "saved_query_run"},
        "write": {"action_prepare", "action_submit"},
    }
    for cap, tools in expected.items():
        async with env.mcp(cap) as c:
            names = {t.name for t in (await c.list_tools()).tools}
        assert tools <= names, (cap, names)
        assert {"capabilities_get", "request_status", "request_result", "request_cancel", "evidence_get"} <= names
        caps = await env.call(cap, "capabilities_get", {})
        assert caps["capabilities"][cap]["granted"] is True
        modes = caps["capabilities"][cap]["review_modes"]
        assert set(modes) == ({"inventory", "content"} if cap == "read" else {"mutation"})
        assert {m["mode"] for m in modes.values()} == {"review_both"}


async def test_missing_and_wrong_keys_rejected(env: Env) -> None:
    async with httpx.AsyncClient(base_url=env.base_url) as c:
        r = await c.post("/mcp/read/", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
        assert r.status_code == 401
        r = await c.post("/mcp/read/", json={}, headers={"Authorization": "Bearer lop_discovery-default_wrongwrongwrongwrongwrongwrongwrong", "Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
        assert r.status_code == 401
        # key in query string is never accepted
        r = await c.post(f"/mcp/read/?token={env.keys['read']}", json={}, headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
        assert r.status_code == 401


async def test_grants_are_explicit_not_cumulative(env: Env) -> None:
    # read key cannot reach the write mount
    with pytest.raises(Exception):  # noqa: B017 - transport-level 403 surfaces as a connection error
        async with env.mcp("write", env.keys["read"]) as c:
            await c.list_tools()
    # execution key cannot run diagnosis queries
    with pytest.raises(Exception):  # noqa: B017
        async with env.mcp("read", env.keys["write"]) as c:
            await c.list_tools()
    # multi-grant key reaches both
    for cap in ("read", "write"):
        async with env.mcp(cap, env.keys["multi"]) as c:
            assert (await c.list_tools()).tools


async def test_session_swapping_rejected(env: Env) -> None:
    http_a = httpx2.AsyncClient(headers={"Authorization": f"Bearer {env.keys['read']}"})
    async with Client(streamable_http_client(f"{env.base_url}/mcp/read", http_client=http_a)) as a:
        await a.list_tools()
        sid = a.session_id if hasattr(a, "session_id") else None
    # Open a raw session with the multi key and try to reuse a session id minted for the discovery key
    async with httpx.AsyncClient(base_url=env.base_url) as raw:
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
        r = await raw.post("/mcp/read/", json=init, headers={"Authorization": f"Bearer {env.keys['read']}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json"})
        assert r.status_code == 200, r.text
        sid = r.headers.get("mcp-session-id")
        assert sid
        ping = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        r2 = await raw.post("/mcp/read/", json=ping, headers={"Authorization": f"Bearer {env.keys['multi']}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json", "Mcp-Session-Id": sid})
        assert r2.status_code == 404, r2.text
        r3 = await raw.post("/mcp/read/", json=ping, headers={"Authorization": f"Bearer {env.keys['read']}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json", "Mcp-Session-Id": sid})
        assert r3.status_code == 200, r3.text


async def test_invalid_host_and_origin_rejected(env: Env) -> None:
    async with httpx.AsyncClient(base_url=env.base_url) as c:
        r = await c.get("/login", headers={"Host": "evil.example"})
        assert r.status_code == 421
        r = await c.get("/login", headers={"Origin": "http://evil.example"})
        assert r.status_code == 403
        r = await c.post("/mcp/read/", json={}, headers={"Origin": "http://evil.example", "Authorization": f"Bearer {env.keys['read']}"})
        assert r.status_code == 403
        r = await c.get("/login")
        assert r.status_code == 200
        assert "default-src 'self'" in r.headers.get("content-security-policy", "")


async def test_no_open_sensitive_routes_and_safe_health(env: Env) -> None:
    async with httpx.AsyncClient(base_url=env.base_url, follow_redirects=False) as c:
        r = await c.get("/healthz")
        assert r.status_code == 200 and r.json() == {"status": "ok"}
        for path in ("/review", "/catalog", "/investigation", "/history", "/settings", "/api/ui/queue"):
            r = await c.get(path)
            assert r.status_code in (303, 401), path
        r = await c.post("/review/req_x/approve", data={"csrf": "x"})
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
        for path in ("/docs", "/openapi.json", "/redoc"):
            assert (await c.get(path)).status_code == 404
        # agent API key cannot authenticate to reviewer routes
        r = await c.get("/review", headers={"Authorization": f"Bearer {env.keys['multi']}"})
        assert r.status_code == 303
        r = await c.get("/review", cookies={"lop_session": env.keys["multi"]})
        assert r.status_code == 303


async def test_csrf_required_on_reviewer_posts(env: Env) -> None:
    c = await env.reviewer()
    r = await c.post("/settings/stop", data={"stopped": "1"})
    assert r.status_code == 403
    r = await c.post("/settings/stop", data={"stopped": "1", "csrf": "wrong"})
    assert r.status_code == 403
    assert not await env.core.auth.mutations_stopped()
    await c.aclose()


async def test_revoked_key_loses_access(env: Env) -> None:
    _, secret = await env.core.auth.create_key("temp", [__import__("local_ops.models", fromlist=["Capability"]).Capability.READ])
    async with env.mcp("read", secret) as c:
        assert (await c.list_tools()).tools
    await env.core.auth.revoke_key("temp")
    with pytest.raises(Exception):  # noqa: B017
        async with env.mcp("read", secret) as c:
            await c.list_tools()
