"""Typed contracts for reviewed AWS changes (D35).

Each configuration names exactly one bounded change against a catalog-declared `AwsTarget`; the
`aws_change` executor refuses anything the target does not fence. No raw API arguments, no free-form
actions: the kinds below are the complete list of what Service Manager can change in AWS."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from local_ops.models import StrictModel

_ACCOUNT_RE = re.compile(r"^\d{12}$")
_ZONE_RE = re.compile(r"^Z[0-9A-Z]{6,31}$")
_ACCESS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")
_SERVICE_CRED_RE = re.compile(r"^ACCA[0-9A-Z]{16,}$")
_FQDN_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+$")
_PRINCIPAL_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_USER_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:(user|role)/[\w+=,.@/-]{1,128}$")
_PERMISSION_SET_RE = re.compile(r"^arn:aws:sso:::permissionSet/ssoins-[0-9a-f]{16}/ps-[0-9a-f]{16}$")
_INSTANCE_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[0-9a-f]{16}$")
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")
_CLUSTER_RE = re.compile(r"^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$")


class AwsTarget(StrictModel):
    """The exact AWS scope a binding may change. Everything an operation touches must sit inside it."""

    resource_type: Literal["route53_zone", "iam_user", "iam_credentials", "identity_center", "eks_cluster"]
    account_id: str
    zone_id: str | None = None
    zone_name: str | None = None  # trailing dot, e.g. "example.com."
    user_name: str | None = None
    instance_arn: str | None = None
    cluster_name: str | None = None
    region: str | None = None
    # identity_center only: the accounts whose assignments this binding may remove (D35 fence).
    assignment_account_ids: list[str] = []

    @field_validator("account_id")
    @classmethod
    def _account(cls, v: str) -> str:
        if not _ACCOUNT_RE.fullmatch(v):
            raise ValueError("account_id must be a 12-digit AWS account id")
        return v

    @model_validator(mode="after")
    def _shape(self) -> AwsTarget:
        rt = self.resource_type
        if rt == "route53_zone":
            if not (self.zone_id and _ZONE_RE.fullmatch(self.zone_id) and self.zone_name and _FQDN_RE.fullmatch(self.zone_name)):
                raise ValueError("route53_zone target needs zone_id and a trailing-dot zone_name")
        elif rt in ("iam_user", "iam_credentials"):
            if not (self.user_name and _USER_NAME_RE.fullmatch(self.user_name)):
                raise ValueError(f"{rt} target needs user_name")
        elif rt == "identity_center":
            if not (self.instance_arn and _INSTANCE_RE.fullmatch(self.instance_arn) and self.region and _REGION_RE.fullmatch(self.region)):
                raise ValueError("identity_center target needs instance_arn and region")
            if not self.assignment_account_ids or not all(_ACCOUNT_RE.fullmatch(a) for a in self.assignment_account_ids):
                raise ValueError("identity_center target needs assignment_account_ids (12-digit account ids)")
        elif rt == "eks_cluster":
            if not (self.cluster_name and _CLUSTER_RE.fullmatch(self.cluster_name) and self.region and _REGION_RE.fullmatch(self.region)):
                raise ValueError("eks_cluster target needs cluster_name and region")
        return self


class Route53Alias(StrictModel):
    hosted_zone_id: str
    dns_name: str
    evaluate_target_health: bool = False

    @field_validator("hosted_zone_id")
    @classmethod
    def _hz(cls, v: str) -> str:
        if not _ZONE_RE.fullmatch(v):
            raise ValueError("alias hosted_zone_id must be a Route53 zone id")
        return v

    @field_validator("dns_name")
    @classmethod
    def _dns(cls, v: str) -> str:
        if not _FQDN_RE.fullmatch(v.lower()):
            raise ValueError("alias dns_name must be a trailing-dot hostname")
        return v.lower()


class Route53RecordConfiguration(StrictModel):
    kind: Literal["route53_record"]
    action: Literal["upsert", "delete"]
    name: str
    record_type: Literal["A", "AAAA", "CNAME", "TXT"]
    ttl: int | None = Field(default=None, ge=1, le=172800)
    values: list[str] | None = Field(default=None, min_length=1, max_length=20)
    alias: Route53Alias | None = None
    set_identifier: str | None = Field(default=None, min_length=1, max_length=128)
    weight: int | None = Field(default=None, ge=0, le=255)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _FQDN_RE.fullmatch(v.lower()):
            raise ValueError("record name must be a trailing-dot fully qualified name")
        return v.lower()

    @field_validator("values")
    @classmethod
    def _values(cls, v: list[str] | None) -> list[str] | None:
        for x in v or []:
            if not (1 <= len(x) <= 4000) or any(ch in x for ch in "\n\r"):
                raise ValueError("record values must be single-line strings")
        return v

    @model_validator(mode="after")
    def _shape(self) -> Route53RecordConfiguration:
        if (self.values is None) == (self.alias is None):
            raise ValueError("exactly one of values or alias is required")
        if self.values is not None and self.ttl is None:
            raise ValueError("ttl is required with values")
        if self.alias is not None and self.ttl is not None:
            raise ValueError("ttl is not allowed with an alias")
        if (self.weight is None) != (self.set_identifier is None):
            raise ValueError("weight and set_identifier go together")
        return self


class IamCredentialStateConfiguration(StrictModel):
    kind: Literal["iam_credential_state"]
    user_name: str
    credential_kind: Literal["access_key", "service_specific"]
    credential_id: str
    status: Literal["Active", "Inactive"]

    @model_validator(mode="after")
    def _shape(self) -> IamCredentialStateConfiguration:
        if not _USER_NAME_RE.fullmatch(self.user_name):
            raise ValueError("user_name is not a valid IAM user name")
        ok = _ACCESS_KEY_RE if self.credential_kind == "access_key" else _SERVICE_CRED_RE
        if not ok.fullmatch(self.credential_id):
            raise ValueError("credential_id does not match the credential kind")
        return self


class IamUserRemoveConfiguration(StrictModel):
    kind: Literal["iam_user_remove"]
    confirm_user_name: str

    @field_validator("confirm_user_name")
    @classmethod
    def _u(cls, v: str) -> str:
        if not _USER_NAME_RE.fullmatch(v):
            raise ValueError("confirm_user_name is not a valid IAM user name")
        return v


class IdentityCenterAssignmentRemoveConfiguration(StrictModel):
    kind: Literal["identity_center_assignment_remove"]
    target_account_id: str
    permission_set_arn: str
    principal_type: Literal["USER", "GROUP"]
    principal_id: str

    @model_validator(mode="after")
    def _shape(self) -> IdentityCenterAssignmentRemoveConfiguration:
        if not _ACCOUNT_RE.fullmatch(self.target_account_id):
            raise ValueError("target_account_id must be a 12-digit AWS account id")
        if not _PERMISSION_SET_RE.fullmatch(self.permission_set_arn):
            raise ValueError("permission_set_arn is not an Identity Center permission set ARN")
        if not _PRINCIPAL_ID_RE.fullmatch(self.principal_id):
            raise ValueError("principal_id is not an Identity Center principal id")
        return self


class EksAccessEntryRemoveConfiguration(StrictModel):
    kind: Literal["eks_access_entry_remove"]
    principal_arn: str

    @field_validator("principal_arn")
    @classmethod
    def _arn(cls, v: str) -> str:
        if not _ROLE_ARN_RE.fullmatch(v):
            raise ValueError("principal_arn must be an IAM user or role ARN")
        return v


AwsChangeConfiguration = Annotated[
    Route53RecordConfiguration | IamCredentialStateConfiguration | IamUserRemoveConfiguration | IdentityCenterAssignmentRemoveConfiguration | EksAccessEntryRemoveConfiguration,
    Field(discriminator="kind"),
]

AWS_CHANGE_KINDS = frozenset({"route53_record", "iam_credential_state", "iam_user_remove", "identity_center_assignment_remove", "eks_access_entry_remove"})


def aws_configuration_matches_target(configuration: object, target: AwsTarget) -> bool:
    """True only when the configuration stays inside the bound target. Checked before any provider read."""
    if isinstance(configuration, Route53RecordConfiguration):
        return target.resource_type == "route53_zone" and bool(target.zone_name) and (configuration.name == target.zone_name or configuration.name.endswith("." + str(target.zone_name)))
    if isinstance(configuration, IamCredentialStateConfiguration):
        return target.resource_type == "iam_credentials" and configuration.user_name == target.user_name
    if isinstance(configuration, IamUserRemoveConfiguration):
        return target.resource_type == "iam_user" and configuration.confirm_user_name == target.user_name
    if isinstance(configuration, IdentityCenterAssignmentRemoveConfiguration):
        return (target.resource_type == "identity_center" and bool(target.instance_arn)
                and configuration.permission_set_arn.split("/")[1] == str(target.instance_arn).split("/")[1]
                and configuration.target_account_id in target.assignment_account_ids)
    if isinstance(configuration, EksAccessEntryRemoveConfiguration):
        return target.resource_type == "eks_cluster"
    return False
