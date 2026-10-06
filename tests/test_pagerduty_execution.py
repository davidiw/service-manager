from __future__ import annotations

from local_ops.executors.pagerduty import PagerDutyConfigurationExecutor


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


def test_definitive_provider_refusal_wins_recovery_without_a_target_read() -> None:
    assert PagerDutyConfigurationExecutor._not_applied([{"result": {"status": "not_applied", "http_status": 403}}])
    assert not PagerDutyConfigurationExecutor._not_applied([{"result": {"status": "accepted"}}])
