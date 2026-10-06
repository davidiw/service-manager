"""End-to-end boundaries for the reviewed PagerDuty configuration path."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import pytest

from local_ops.config import CredentialRef, ProviderConfig
from local_ops.providers.pagerduty import PagerDutyAdapter
from tests.conftest import Env

pytestmark = pytest.mark.asyncio


def _service(*, bound_id: str | None = None) -> str:
    target = "" if bound_id is None else f"\n      id: {bound_id}"
    return f"""---
schema_version: 1
id: pd-oncall
name: Engineering on-call
environments: [demo]
bindings:
  - id: pd-binding
    environment: demo
    provider_id: pd-test
    execution_enabled: true
    source_state: verified
    pagerduty_target:
      resource_type: schedule
      account_domain: acme.pagerduty.com
      name: Engineering{target}
operations:
  configure:
    executor: pagerduty_configuration
    kind: configure
    binding_id: pd-binding
    health_checks: [pagerduty_configuration_matches]
---
"""


class PD:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.users = [{"id": f"PUSER0{i}", "name": str(i), "html_url": f"https://acme.pagerduty.com/users/PUSER0{i}"} for i in range(1, 6)]
        self.schedules: dict[str, dict[str, Any]] = {}
        self.policies: list[dict[str, Any]] = []
        self.malformed: str | None = None
        self.fail_after_create = False

    def _list(self, key: str, rows: list[dict[str, Any]], request: httpx.Request) -> httpx.Response:
        if self.malformed == key:
            return httpx.Response(200, json={key: rows, "offset": 0})
        return httpx.Response(200, json={key: rows, "offset": 0, "more": False})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "GET" and path == "/users":
            return self._list("users", self.users, request)
        if request.method == "GET" and path == "/schedules":
            return self._list("schedules", list(self.schedules.values()), request)
        if request.method == "GET" and path == "/v3/schedules":
            return self._list("schedules", [], request)
        if request.method == "GET" and path == "/escalation_policies":
            return self._list("escalation_policies", self.policies, request)
        if request.method == "GET" and path.startswith("/schedules/"):
            item = self.schedules.get(path.rsplit("/", 1)[1])
            return httpx.Response(200, json={"schedule": item}) if item else httpx.Response(404)
        if request.method == "POST" and path == "/schedules":
            body = json.loads(request.content)
            item = {**body["schedule"], "id": "PSCHED1", "html_url": "https://acme.pagerduty.com/schedules/PSCHED1"}
            # PagerDuty can express the same instant in UTC; matching must not compare strings.
            for layer in item["schedule_layers"]:
                layer["start"] = "2026-10-05T16:00:00Z"
                layer["rotation_virtual_start"] = "2026-10-05T16:00:00+00:00"
            self.schedules[item["id"]] = item
            if self.fail_after_create:
                raise httpx.ReadError("response lost", request=request)
            return httpx.Response(200, json={"schedule": item})
        if request.method == "DELETE" and path.startswith("/schedules/"):
            self.schedules.pop(path.rsplit("/", 1)[1], None)
            return httpx.Response(204)
        return httpx.Response(500, json={"error": "unexpected"})


@pytest.fixture
async def pd_env(env: Env, monkeypatch: pytest.MonkeyPatch) -> tuple[Env, PD]:
    monkeypatch.setenv("PD_TEST_RO", "read-token")
    monkeypatch.setenv("PD_TEST_EXEC", "exec-token")
    assert env.catalog_dir
    (env.catalog_dir / "services" / "syntheticpd-oncall.md").write_text(_service(), encoding="utf-8")
    env.core.config.credentials += [CredentialRef(id="pd-ro", kind="env", env_var="PD_TEST_RO"), CredentialRef(id="pd-exec", kind="env", env_var="PD_TEST_EXEC")]
    config = ProviderConfig(id="pd-test", kind="pagerduty", credential="pd-ro", execution_credential="pd-exec")
    env.core.config.providers.append(config)
    pd = PD()
    env.core.providers.register(PagerDutyAdapter(config, env.core.config, env.core.resolver, http=httpx.AsyncClient(transport=httpx.MockTransport(pd.handler))))
    env.core.reload_catalog()
    await env.set_mode("write-default", "mutation", "yolo")
    return env, pd


def _desired() -> dict[str, Any]:
    return {"kind": "schedule", "name": "Engineering", "time_zone": "America/Los_Angeles", "rotation_start": "2026-10-05T09:00:00-07:00", "rotation_turn_length_seconds": 259200, "user_ids": [f"PUSER0{i}" for i in range(1, 6)]}


async def _prepare(env: Env) -> dict[str, Any]:
    sub = await env.call("write", "action_prepare", {"service_id": "pd-oncall", "binding_id": "pd-binding", "action": "configure", "desired_configuration": _desired()})
    await env.wait("write", sub["request_id"])
    return await env.call("write", "request_result", {"request_id": sub["request_id"]})


async def _submit(env: Env, plan: dict[str, Any], key: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": key or str(uuid.uuid4())})
    status = await env.wait("write", sub["request_id"], timeout=30)
    return sub, await env.call("write", "request_result", {"request_id": sub["request_id"]}) if status["response_status"] == "released" else status


async def test_schedule_create_uses_execution_credential_exact_payload_and_idempotency(pd_env: tuple[Env, PD]) -> None:
    env, pd = pd_env
    plan = await _prepare(env)
    key = "pd-create-replay"
    sub, result = await _submit(env, plan, key)
    assert result["receipt"]["health_checks"][0]["passed"] is True
    post = [r for r in pd.requests if r.method == "POST"]
    assert len(post) == 1 and post[0].headers["authorization"] == "Token token=exec-token"
    payload = json.loads(post[0].content)["schedule"]
    assert [u["user"]["id"] for u in payload["schedule_layers"][0]["users"]] == _desired()["user_ids"]
    assert all(r.headers["authorization"] == "Token token=exec-token" for r in pd.requests)
    replay = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": key})
    assert replay["request_id"] == sub["request_id"] and len([r for r in pd.requests if r.method == "POST"]) == 1


@pytest.mark.parametrize("missing_exec,wrong_domain", [(True, False), (False, True)])
async def test_prepare_refuses_missing_execution_or_wrong_account_users(pd_env: tuple[Env, PD], missing_exec: bool, wrong_domain: bool) -> None:
    env, pd = pd_env
    if missing_exec:
        env.core.config.credentials[-1] = CredentialRef(id="pd-exec", kind="none")
    if wrong_domain:
        pd.users[0]["html_url"] = "https://other.pagerduty.com/users/PUSER01"
    result = await _prepare(env)
    assert result["error"]["error"] in {"auth_required", "scope_unresolved"}
    assert not [r for r in pd.requests if r.method == "POST"]


async def test_interrupted_create_is_unknown_and_never_replayed(pd_env: tuple[Env, PD]) -> None:
    env, pd = pd_env
    pd.fail_after_create = True
    _, result = await _submit(env, await _prepare(env))
    assert result["receipt"]["ran"] == "uncertain"
    assert result["receipt"]["outcome"].startswith("create identity was not confirmed")
    assert len([r for r in pd.requests if r.method == "POST"]) == 1


@pytest.mark.parametrize(("malformed", "error"), [(False, "conflict"), (True, "provider_unavailable")])
async def test_delete_refuses_referenced_or_incomplete_policy_listing(pd_env: tuple[Env, PD], malformed: bool, error: str) -> None:
    env, pd = pd_env
    assert env.catalog_dir
    pd.schedules["PSCHED1"] = {"id": "PSCHED1", "name": "Engineering", "html_url": "https://acme.pagerduty.com/schedules/PSCHED1", "time_zone": "UTC", "schedule_layers": []}
    pd.policies = [{"id": "PE1", "name": "Primary", "html_url": "https://acme.pagerduty.com/escalation_policies/PE1", "num_loops": 1, "escalation_rules": [{"escalation_delay_in_minutes": 5, "targets": [{"id": "PSCHED1", "type": "schedule_reference"}]}]}]
    if malformed:
        pd.malformed = "escalation_policies"
    (env.catalog_dir / "services" / "syntheticpd-oncall.md").write_text(_service(bound_id="PSCHED1"), encoding="utf-8")
    env.core.reload_catalog()
    args = {"service_id": "pd-oncall", "binding_id": "pd-binding", "action": "configure", "desired_configuration": {"kind": "schedule_delete", "confirm_name": "Engineering"}}
    sub = await env.call("write", "action_prepare", args)
    await env.wait("write", sub["request_id"])
    result = await env.call("write", "request_result", {"request_id": sub["request_id"]})
    assert result["error"]["error"] == error, result
    assert not [r for r in pd.requests if r.method == "DELETE"]
