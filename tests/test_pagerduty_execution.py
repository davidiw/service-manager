from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from local_ops.catalog import Binding, ServiceSpec
from local_ops.executors.pagerduty import PagerDutyConfigurationExecutor
from local_ops.models import ActionPlan, ExecutionStatus
from local_ops.operations.base import OperationContext


def test_schedule_match_uses_actual_wire_shape_order_and_instant() -> None:
    mutation = {
        "method": "POST", "resource_type": "schedule", "resource_id": None,
        "payload": {"schedule": {"name": "Engineering", "time_zone": "America/Los_Angeles", "schedule_layers": [{"start": "2026-10-05T09:00:00-07:00", "rotation_virtual_start": "2026-10-05T09:00:00-07:00", "rotation_turn_length_seconds": 259200, "users": [{"user": {"id": "U1", "type": "user_reference"}}, {"user": {"id": "U2", "type": "user_reference"}}, {"user": {"id": "U3", "type": "user_reference"}}, {"user": {"id": "U4", "type": "user_reference"}}, {"user": {"id": "U5", "type": "user_reference"}}]}]}},
    }
    observed = {"id": "PS1", "name": "Engineering", "html_url": "https://acme.pagerduty.com/schedules/PS1", "time_zone": "America/Los_Angeles", "schedule_layers": [{"start": "2026-10-05T16:00:00Z", "rotation_virtual_start": "2026-10-05T16:00:00+00:00", "rotation_turn_length_seconds": 259200, "users": [{"id": f"U{i}", "type": "user_reference"} for i in range(1, 6)]}]}
    assert PagerDutyConfigurationExecutor._matches(mutation, observed)
    observed["schedule_layers"][0]["users"].reverse()  # type: ignore[index]
    assert not PagerDutyConfigurationExecutor._matches(mutation, observed)


def test_escalation_match_requires_full_rules_not_only_resource_presence() -> None:
    mutation = {"method": "PUT", "resource_type": "escalation_policy", "resource_id": "PE1", "payload": {"escalation_policy": {"name": "Primary", "num_loops": 2, "escalation_rules": [{"escalation_delay_in_minutes": 5, "targets": [{"id": "PS1", "type": "schedule_reference"}]}]}}}
    observed = {"id": "PE1", "name": "Primary", "num_loops": 2, "rules": [{"delay_minutes": 10, "targets": [{"id": "PS1", "type": "schedule_reference"}]}]}
    assert not PagerDutyConfigurationExecutor._matches(mutation, observed)


@pytest.mark.asyncio
@pytest.mark.parametrize("resource_type", ["service", "incident", "schedule"])
@pytest.mark.parametrize("intent_status", [None, "accepted", "uncertain", "not_applied"])
async def test_recovery_consumes_nullable_durable_intents(resource_type: str, intent_status: str | None) -> None:
    now = datetime.now(UTC)
    rid = "PRESOURCE1"
    if resource_type == "schedule":
        layer = {"start": "2026-10-06T00:00:00Z", "rotation_virtual_start": "2026-10-06T00:00:00Z", "rotation_turn_length_seconds": 259200, "users": [{"user": {"id": "PUSER01", "type": "user_reference"}}]}
        payload = {"schedule": {"name": "Engineering", "time_zone": "UTC", "schedule_layers": [layer]}}
        observed: dict[str, Any] = {"id": rid, "name": "Engineering", "time_zone": "UTC", "schedule_layers": [{**layer, "users": [{"id": "PUSER01", "type": "user_reference"}]}]}
    else:
        payload = {resource_type: {"escalation_policy": {"id": "PEPOL01", "type": "escalation_policy_reference"}}}
        observed = {"id": rid, "name": "Target", "status": "acknowledged", "escalation_policy": {"id": "PEPOL01"}}
    observed["html_url"] = f"https://acme.pagerduty.com/{resource_type}/{rid}"
    mutation = {"method": "POST" if resource_type == "schedule" else "PUT", "resource_type": resource_type, "resource_id": None if resource_type == "schedule" else rid, "payload": payload}
    plan = ActionPlan(plan_id="plan1", plan_hash="hash", service_id="svc", binding_id="binding", action="configure", environment="test", executor="pagerduty_configuration", mechanism="test", target={"account_domain": "acme.pagerduty.com"}, target_fingerprint="fp", provider_mutations=[mutation], timeout_seconds=1, expected_disruption="test", catalog_revision="rev", implementation_version="1", prepared_by="principal", prepared_at=now, expires_at=now + timedelta(minutes=1))
    binding = Binding(id="binding", environment="test", provider_id="pd")
    spec = ServiceSpec(id="svc", name="Service", bindings=[binding])
    adapter = SimpleNamespace(kind="pagerduty", configuration_get=AsyncMock(return_value=observed), configuration_write=AsyncMock())
    ctx = cast(OperationContext, SimpleNamespace(catalog=SimpleNamespace(service=lambda _: SimpleNamespace(spec=spec)), providers=SimpleNamespace(get=lambda _: adapter), budget=None, scrub=lambda value: value))
    intents: list[dict[str, Any]] = [{"result": None}]
    if intent_status is not None:
        result: dict[str, Any] = {"status": intent_status}
        if intent_status == "accepted" and resource_type == "schedule":
            result["created_target_id"] = rid
        if intent_status == "not_applied":
            result["http_status"] = 403
        intents.append({"result": result})
    status, detail = await PagerDutyConfigurationExecutor().reconcile(ctx, plan, intents)
    refused = intent_status == "not_applied"
    unconfirmed = resource_type in {"incident", "schedule"} and intent_status != "accepted"
    expected = ExecutionStatus.FAILED if refused else ExecutionStatus.OUTCOME_UNKNOWN if unconfirmed else ExecutionStatus.SUCCEEDED
    assert status is expected
    assert adapter.configuration_get.await_count == (0 if refused or (resource_type == "schedule" and unconfirmed) else 1)
    adapter.configuration_write.assert_not_called()
    if refused:
        assert detail["ran"] == "not_started"
    if expected is ExecutionStatus.SUCCEEDED:
        assert detail["observed"]["id"] == rid
