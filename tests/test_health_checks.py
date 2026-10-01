"""Generic, data-driven health checks: the server knows HTTP and JSON, never application semantics."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from local_ops.catalog import HealthCheckConfig, ServiceSpec
from local_ops.executors.health import http_check
from tests.conftest import Env

pytestmark = pytest.mark.asyncio


def client(responses: list[tuple[int, object]]) -> httpx.AsyncClient:
    seq = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        status, body = next(seq)
        return httpx.Response(status, json=body) if not isinstance(body, str) else httpx.Response(status, text=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_http_status() -> None:
    hc = HealthCheckConfig(id="h", kind="http_status", url="http://x/health", expected_status=204)
    async with client([(204, "")]) as c:
        assert (await http_check(hc, c)).passed is True
    async with client([(500, "")]) as c:
        assert (await http_check(hc, c)).passed is False


async def test_http_json_equals_nested_field() -> None:
    hc = HealthCheckConfig(id="chain", kind="http_json", url="http://x/", json_field="node.chain_id", equals="126")
    async with client([(200, {"node": {"chain_id": 126}})]) as c:
        assert (await http_check(hc, c)).passed is True
    async with client([(200, {"node": {"chain_id": 4}})]) as c:
        r = await http_check(hc, c)
        assert r.passed is False and "expected '126'" in r.detail
    async with client([(200, {"other": 1})]) as c:
        assert "missing" in (await http_check(hc, c)).detail
    async with client([(200, "not json")]) as c:
        assert (await http_check(hc, c)).detail == "response is not JSON"


async def test_http_json_artifact_version() -> None:
    hc = HealthCheckConfig(id="v", kind="http_json", url="http://x/version", json_field="version", equals_artifact_version=True)
    async with client([(200, {"version": "2.0.0"})]) as c:
        assert (await http_check(hc, c, expected_version="2.0.0")).passed is True
    async with client([(200, {"version": "1.0.0"})]) as c:
        assert (await http_check(hc, c, expected_version="2.0.0")).passed is False
    async with client([(200, {"version": "1.0.0"})]) as c:
        assert (await http_check(hc, c, expected_version=None)).passed is None  # cannot verify, never a pass


async def test_http_json_increases() -> None:
    hc = HealthCheckConfig(id="p", kind="http_json", url="http://x/", json_field="height", increases=True, interval_seconds=1)
    async with client([(200, {"height": "10"}), (200, {"height": "12"})]) as c:
        r = await http_check(hc, c)
        assert r.passed is True and r.observed["value_after"] == "12"
    async with client([(200, {"height": 10}), (200, {"height": 10})]) as c:
        assert "did not increase" in (await http_check(hc, c)).detail


def test_check_config_validation() -> None:
    with pytest.raises(ValidationError):
        HealthCheckConfig(id="x", kind="http_json", url="http://x/")  # no field
    with pytest.raises(ValidationError):
        HealthCheckConfig(id="x", kind="http_json", url="http://x/", json_field="a")  # no assertion
    with pytest.raises(ValidationError):
        HealthCheckConfig(id="x", kind="http_status", url="http://x/", json_field="a")  # json on status check
    base = {"id": "svc", "name": "s"}
    with pytest.raises(ValidationError, match="unknown kind"):
        ServiceSpec.model_validate({**base, "health_checks": [{"id": "a", "kind": "rpc_ledger_progress"}]})
    with pytest.raises(ValidationError, match="reserved"):
        ServiceSpec.model_validate({**base, "health_checks": [{"id": "ready_replicas", "kind": "http_status"}]})
    with pytest.raises(ValidationError, match="neither built in"):
        ServiceSpec.model_validate({**base, "bindings": [{"id": "b", "environment": "e", "provider_id": "p"}], "operations": {"restart": {"executor": "kubernetes_native", "kind": "rollout_restart", "binding_id": "b", "health_checks": ["undeclared"]}}})


async def test_health_checks_recipe_runs_declared_checks(env: Env) -> None:
    await env.set_mode("diagnosis-default", "diagnosis", "yolo")
    env.app_state.version = "1.0.0"
    sub = await env.call("diagnosis", "investigation_run", {"recipe": "health_checks", "service_id": "demo-app", "sources": []})
    await env.wait("diagnosis", sub["request_id"])
    res = await env.call("diagnosis", "request_result", {"request_id": sub["request_id"]})
    by_id = {c["check_id"]: c for c in res["health_checks"]}
    assert by_id["demo_http_health"]["passed"] is True
    assert by_id["demo_http_version"]["passed"] is None  # no deployed artifact version in a snapshot run
    assert any("demo_http_health" in o for o in res["observations"])
