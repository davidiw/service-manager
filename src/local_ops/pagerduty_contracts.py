"""Typed, secret-free PagerDuty configuration contracts."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, field_validator

from local_ops.models import StrictModel

_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.eu)?\.pagerduty\.com$")
_ID_RE = re.compile(r"^[A-Za-z0-9]{7,32}$")


class PagerDutyTarget(StrictModel):
    resource_type: Literal["schedule", "escalation_policy", "service"]
    account_domain: str
    id: str | None = None
    name: str = Field(min_length=1, max_length=256)

    @field_validator("account_domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        if not _DOMAIN_RE.fullmatch(value):
            raise ValueError("account_domain must be an exact lowercase subdomain.pagerduty.com or subdomain.eu.pagerduty.com")
        return value

    @field_validator("id")
    @classmethod
    def _id(cls, value: str | None) -> str | None:
        if value is not None and not _ID_RE.fullmatch(value):
            raise ValueError("id must be an alphanumeric PagerDuty provider ID")
        return value


class PagerDutyReference(StrictModel):
    id: str
    type: Literal["user_reference", "schedule_reference"]

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value):
            raise ValueError("id must be an alphanumeric PagerDuty provider ID")
        return value


class EscalationRule(StrictModel):
    delay_minutes: int = Field(ge=1, le=60, strict=True)
    targets: list[PagerDutyReference] = Field(min_length=1, max_length=50)


class ScheduleConfiguration(StrictModel):
    kind: Literal["schedule"]
    name: str = Field(min_length=1, max_length=256)
    time_zone: str = Field(min_length=1, max_length=128)
    rotation_start: datetime
    rotation_turn_length_seconds: int = Field(ge=3600, le=2592000, strict=True)
    user_ids: list[str] = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=1024)

    @field_validator("rotation_start")
    @classmethod
    def _aware_rotation_start(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("rotation_start must be timezone-aware")
        return value

    @field_validator("time_zone")
    @classmethod
    def _time_zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("time_zone must be an IANA timezone") from exc
        return value

    @field_validator("user_ids")
    @classmethod
    def _user_ids(cls, values: list[str]) -> list[str]:
        if any(not _ID_RE.fullmatch(value) for value in values):
            raise ValueError("user_ids must be alphanumeric PagerDuty provider IDs")
        if len(values) != len(set(values)):
            raise ValueError("user_ids must be unique")
        return values


class EscalationPolicyConfiguration(StrictModel):
    kind: Literal["escalation_policy"]
    name: str = Field(min_length=1, max_length=256)
    num_loops: int = Field(ge=0, le=9, strict=True)
    rules: list[EscalationRule] = Field(min_length=1, max_length=50)


class ServiceRoutingConfiguration(StrictModel):
    kind: Literal["service_routing"]
    escalation_policy_id: str

    @field_validator("escalation_policy_id")
    @classmethod
    def _escalation_policy_id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value):
            raise ValueError("escalation_policy_id must be an alphanumeric PagerDuty provider ID")
        return value


class ScheduleDeleteConfiguration(StrictModel):
    kind: Literal["schedule_delete"]
    confirm_name: str = Field(min_length=1, max_length=256)


PagerDutyConfiguration = Annotated[
    ScheduleConfiguration | EscalationPolicyConfiguration | ServiceRoutingConfiguration | ScheduleDeleteConfiguration,
    Field(discriminator="kind"),
]


def configuration_matches_target(configuration: PagerDutyConfiguration, target: PagerDutyTarget) -> bool:
    if isinstance(configuration, ScheduleConfiguration):
        return target.resource_type == "schedule" and target.id is None and configuration.name == target.name
    if isinstance(configuration, EscalationPolicyConfiguration):
        return target.resource_type == "escalation_policy" and (target.id is not None or configuration.name == target.name)
    if isinstance(configuration, ServiceRoutingConfiguration):
        return target.resource_type == "service" and target.id is not None
    return target.resource_type == "schedule" and target.id is not None and configuration.confirm_name == target.name
