from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from local_ops.catalog import ServiceSpec
from local_ops.operations.execution import ActionPrepareArgs
from local_ops.pagerduty_contracts import (
    IncidentReassignmentConfiguration,
    PagerDutyTarget,
    ScheduleConfiguration,
    configuration_matches_target,
)


def schedule_configuration() -> dict[str, object]:
    return {
        "kind": "schedule",
        "name": "Engineering three-day rotation",
        "time_zone": "America/Los_Angeles",
        "rotation_start": datetime(2026, 10, 5, tzinfo=UTC),
        "rotation_turn_length_seconds": 259200,
        "user_ids": ["ABC1234"],
    }


def test_target_and_schedule_configuration_are_typed_and_match_creation() -> None:
    target = PagerDutyTarget(resource_type="schedule", account_domain="example.pagerduty.com", name="Engineering three-day rotation")
    configuration = ScheduleConfiguration.model_validate(schedule_configuration())
    assert configuration_matches_target(configuration, target)


def test_schedule_creation_cannot_substitute_a_name_for_the_bound_target() -> None:
    target = PagerDutyTarget(resource_type="schedule", account_domain="example.pagerduty.com", name="Approved rotation")
    configuration = ScheduleConfiguration.model_validate({**schedule_configuration(), "name": "Different rotation"})
    assert not configuration_matches_target(configuration, target)


def test_incident_target_requires_id_and_reassignment_matches_exact_incident() -> None:
    with pytest.raises(ValidationError, match="incident targets require"):
        PagerDutyTarget(resource_type="incident", account_domain="example.pagerduty.com", name="Network retirement")
    target = PagerDutyTarget(resource_type="incident", account_domain="example.pagerduty.com", id="INC1234", name="Network retirement")
    configuration = IncidentReassignmentConfiguration(kind="incident_reassignment", escalation_policy_id="EP12345")
    assert configuration_matches_target(configuration, target)


def test_incident_configure_requires_catalog_actor_and_never_accepts_caller_actor() -> None:
    service = {
        "id": "network-retirement",
        "name": "Network retirement",
        "bindings": [{"id": "pagerduty-incident", "environment": "production", "provider_id": "pagerduty", "pagerduty_target": {"resource_type": "incident", "account_domain": "example.pagerduty.com", "id": "INC1234", "name": "Network retirement"}}],
        "operations": {"configure": {"executor": "pagerduty_configuration", "kind": "configure", "binding_id": "pagerduty-incident", "health_checks": ["pagerduty_configuration_matches"]}},
    }
    with pytest.raises(ValidationError, match="pagerduty_actor_user_id"):
        ServiceSpec.model_validate(service)
    with pytest.raises(ValidationError):
        ActionPrepareArgs.model_validate({"service_id": "network-retirement", "binding_id": "pagerduty-incident", "action": "configure", "desired_configuration": {"kind": "incident_reassignment", "escalation_policy_id": "EP12345"}, "pagerduty_actor_user_id": "USR1234"})


def test_target_accepts_eu_hostname_but_not_a_lookalike() -> None:
    target = PagerDutyTarget(resource_type="service", account_domain="example.eu.pagerduty.com", id="ABC1234", name="Engineering")
    assert target.account_domain == "example.eu.pagerduty.com"
    with pytest.raises(ValidationError):
        PagerDutyTarget(resource_type="service", account_domain="example.eu.pagerduty.com.invalid", id="ABC1234", name="Engineering")


@pytest.mark.parametrize(
    "target",
    [
        {"resource_type": "schedule", "account_domain": "Example.pagerduty.com", "name": "x"},
        {"resource_type": "schedule", "account_domain": "example.pagerduty.com", "id": "short", "name": "x"},
    ],
)
def test_target_rejects_unbound_domain_and_provider_id(target: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        PagerDutyTarget.model_validate(target)


def test_schedule_rejects_naive_rotation_and_non_iana_timezone() -> None:
    invalid = schedule_configuration()
    invalid["rotation_start"] = datetime(2026, 10, 5)
    with pytest.raises(ValidationError):
        ScheduleConfiguration.model_validate(invalid)
    invalid = schedule_configuration()
    invalid["time_zone"] = "Pacific Time"
    with pytest.raises(ValidationError):
        ScheduleConfiguration.model_validate(invalid)


def test_configure_requires_typed_configuration_and_forbids_artifact() -> None:
    with pytest.raises(ValidationError, match="desired_configuration is required"):
        ActionPrepareArgs(service_id="service-one", binding_id="binding-one", action="configure")
    with pytest.raises(ValidationError, match="desired_artifact is forbidden"):
        ActionPrepareArgs(service_id="service-one", binding_id="binding-one", action="configure", desired_artifact="registry.test/team/image:v1", desired_configuration=schedule_configuration())
    with pytest.raises(ValidationError, match="only allowed for configure"):
        ActionPrepareArgs(service_id="service-one", binding_id="binding-one", action="restart", desired_configuration=schedule_configuration())
