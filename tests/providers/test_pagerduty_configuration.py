"""PagerDuty configuration transport contracts run wholly against MockTransport."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import OpsError, utcnow
from local_ops.operations.base import Budget
from local_ops.operations.diagnosis import EvidenceQueryArgs
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.pagerduty import PagerDutyAdapter
from local_ops.release import Sanitizer


def _adapter(monkeypatch: pytest.MonkeyPatch, handler: httpx.MockTransport) -> PagerDutyAdapter:
    monkeypatch.setenv("PD_READ", "synthetic-read-token")
    monkeypatch.setenv("PD_EXEC", "synthetic-execution-token")
    config = ServerConfig(
        credentials=[CredentialRef(id="read", kind="env", env_var="PD_READ"), CredentialRef(id="exec", kind="env", env_var="PD_EXEC")],
        providers=[ProviderConfig(id="pd", kind="pagerduty", credential="read", execution_credential="exec")],
    )
    return PagerDutyAdapter(config.providers[0], config, CredentialResolver(config, Sanitizer()), http=httpx.AsyncClient(transport=handler))


def _budget() -> Budget:
    return Budget(deadline=utcnow() + timedelta(seconds=10), max_bytes=100_000)


@pytest.mark.asyncio
async def test_configuration_reads_project_and_execution_uses_execution_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"service": {"id": "PSVC1", "name": "api", "html_url": "https://acme.pagerduty.com/service-directory/PSVC1", "status": "active", "escalation_policy": {"id": "PEP1", "type": "escalation_policy_reference", "summary": "Primary"}, "integrations": [{"integration_key": "never-store"}], "alert_creation": "create_alerts_and_incidents"}})

    adapter = _adapter(monkeypatch, httpx.MockTransport(handler))
    normal = await adapter.configuration_get("service", "PSVC1", _budget())
    execution = await adapter.configuration_get("service", "PSVC1", _budget(), execution=True)
    assert normal and execution and "integrations" not in normal
    assert seen[0].headers["authorization"] == "Token token=synthetic-read-token"
    assert seen[1].headers["authorization"] == "Token token=synthetic-execution-token"


@pytest.mark.asyncio
async def test_configuration_list_v3_is_read_only_complete_and_write_is_whitelisted(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v3/schedules":
            return httpx.Response(200, json={"schedules": [{"id": "PV3", "summary": "new schedule", "html_url": "https://acme.pagerduty.com/schedules/PV3", "type": "schedule"}], "offset": 0, "more": False})
        if request.method == "POST" and request.url.path == "/schedules":
            return httpx.Response(200, json={"schedule": {"id": "PS2", "name": "new", "time_zone": "UTC", "schedule_layers": [{"start": "2026-01-01T00:00:00Z", "users": [{"user": {"id": "PU1", "type": "user_reference", "summary": "Taylor"}}]}]}})
        return httpx.Response(500, json={"error": {"message": "private"}})

    adapter = _adapter(monkeypatch, httpx.MockTransport(handler))
    assert await adapter.configuration_list("schedule_v3", _budget(), execution=True) == [{"id": "PV3", "name": "new schedule", "html_url": "https://acme.pagerduty.com/schedules/PV3", "type": "schedule"}]
    created = await adapter.configuration_write("POST", "schedule", None, {"schedule": {"name": "new"}})
    assert created and created["id"] == "PS2"
    assert created["schedule_layers"][0]["users"] == [{"id": "PU1", "type": "user_reference", "summary": "Taylor"}]
    assert all(r.headers["authorization"] == "Token token=synthetic-execution-token" for r in seen)
    with pytest.raises(OpsError):
        await adapter.configuration_write("POST", "service", None, {})


@pytest.mark.asyncio
async def test_configuration_refuses_ambiguous_pagination_invalid_ids_and_unauthenticated_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def malformed(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"users": [], "offset": 0})  # missing required boolean `more`

    adapter = _adapter(monkeypatch, httpx.MockTransport(malformed))
    with pytest.raises(OpsError):
        await adapter.configuration_list("user", _budget())
    with pytest.raises(OpsError):
        await adapter.configuration_get("user", "PU%2f1", _budget())
    assert len(seen) == 1  # invalid ID made no provider request

    config = ServerConfig(credentials=[CredentialRef(id="read", kind="env", env_var="PD_READ"), CredentialRef(id="exec", kind="none")], providers=[ProviderConfig(id="pd", kind="pagerduty", credential="read", execution_credential="exec")])
    no_auth_calls: list[httpx.Request] = []
    no_auth = PagerDutyAdapter(config.providers[0], config, CredentialResolver(config, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(lambda request: no_auth_calls.append(request) or httpx.Response(204))))
    with pytest.raises(OpsError):
        await no_auth.configuration_get("user", "PU1", _budget(), execution=True)
    assert no_auth_calls == []

    for status in (204, 302):
        strict_read = _adapter(monkeypatch, httpx.MockTransport(lambda request, status=status: httpx.Response(status, headers={"location": "https://elsewhere.invalid"} if status == 302 else {})))
        with pytest.raises(OpsError) as raised:
            await strict_read.configuration_get("user", "PU1", _budget())
        if status == 302:
            assert raised.value.data == {"http_status": 302}


@pytest.mark.asyncio
async def test_configuration_evidence_uses_release_gate_and_bounded_schedule_window(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"schedule": {"id": "PS1", "name": "Primary", "time_zone": "UTC", "schedule_layers": [], "final_schedule": {"rendered_schedule_entries": []}}})

    class Context:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        async def store_evidence(self, *args: object, **kwargs: object) -> str:
            self.calls.append(args)
            return "ev_1"

    adapter = _adapter(monkeypatch, httpx.MockTransport(handler))
    ctx = Context()
    end = utcnow()
    result = await adapter.query(ctx, {"query_type": "pagerduty_configuration", "scope": {"resource_type": "schedule", "resource_id": "PS1"}, "time_range": {"start": (end - timedelta(days=1)).isoformat(), "end": end.isoformat()}}, _budget())  # type: ignore[arg-type]
    assert result.raw_evidence_ids == ["ev_1"] and ctx.calls and ctx.calls[0][1] == "pagerduty_configuration"
    assert set(httpx.QueryParams(seen[0].url.query).keys()) == {"since", "until", "overflow"}


def test_configuration_evidence_scope_is_exact_and_schedule_window_is_bounded() -> None:
    end = utcnow()
    args = EvidenceQueryArgs.model_validate({"source_id": "pd", "query_type": "pagerduty_configuration", "scope": {"resource_type": "schedule", "resource_id": "PS1"}, "time_range": {"start": end - timedelta(days=31), "end": end}})
    assert args.scope["resource_id"] == "PS1"
    with pytest.raises(ValueError):
        EvidenceQueryArgs.model_validate({"source_id": "pd", "query_type": "pagerduty_configuration", "scope": {"resource_type": "schedule", "resource_id": "PS/1"}, "time_range": {"start": end - timedelta(days=32), "end": end}})
