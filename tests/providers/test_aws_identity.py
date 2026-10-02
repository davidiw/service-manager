"""AWS IAM Identity Center / Identity Store census, and the IAM group/policy-reference
additions in `AwsAdapter._fam_iam`. All calls are in-process fakes (see tests/providers/test_aws.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from local_ops.providers.base import DiscoveryScope
from tests.providers.test_aws import (
    ACCOUNT,
    R1,
    FakeClient,
    adapter,
    client_error,
    ctx,  # noqa: F401
    empty_global,
    empty_regional,
    stored_evidence_text,
    sts_client,
)

INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1111111111111111"
INSTANCE_ID = "ssoins-1111111111111111"
STORE_ID = "d-1234567890"
PSET_ARN = f"arn:aws:sso:::permissionSet/{INSTANCE_ID}/ps-2222222222222222"
OTHER_ACCOUNT = "210987654321"


def _sso_client(*, instances: list[dict[str, Any]] | Exception, permission_sets: list[str] | None = None, managed: list[dict[str, Any]] | None = None, custom: list[dict[str, Any]] | None = None, provisioned_accounts: list[str] | None = None, assignments_by_account: dict[str, list[dict[str, Any]]] | None = None) -> FakeClient:
    if isinstance(instances, Exception):
        return FakeClient("sso-admin", {}, {"list_instances": instances})
    permission_sets = permission_sets if permission_sets is not None else [PSET_ARN]
    provisioned_accounts = provisioned_accounts if provisioned_accounts is not None else []
    assignments_by_account = assignments_by_account or {}

    def describe_permission_set(kw: dict[str, Any]) -> dict[str, Any]:
        return {"PermissionSet": {"Name": "ReadOnly", "Description": "read only", "SessionDuration": "PT1H", "CreatedDate": datetime(2025, 1, 1, tzinfo=UTC)}}

    def account_assignments(kw: dict[str, Any]) -> list[dict[str, Any]]:
        rows = assignments_by_account.get(kw["AccountId"], [])
        return [{"AccountAssignments": rows}]

    return FakeClient(
        "sso-admin",
        {"describe_permission_set": describe_permission_set},
        {
            "list_instances": [{"Instances": instances}],
            "list_permission_sets": [{"PermissionSets": permission_sets}],
            "list_managed_policies_in_permission_set": [{"AttachedManagedPolicies": managed or []}],
            "list_customer_managed_policy_references_in_permission_set": [{"CustomerManagedPolicyReferences": custom or []}],
            "list_accounts_for_provisioned_permission_set": [{"AccountIds": provisioned_accounts}],
            "list_account_assignments": account_assignments,
        },
    )


def _identitystore_client(*, users: list[dict[str, Any]] | None = None, groups: list[dict[str, Any]] | None = None, memberships: Any = None) -> FakeClient:
    return FakeClient(
        "identitystore",
        {},
        {
            "list_users": [{"Users": users or []}],
            "list_groups": [{"Groups": groups or []}],
            "list_group_memberships": memberships if memberships is not None else [{"GroupMemberships": []}],
        },
    )


def _instance(arn: str = INSTANCE_ARN, store_id: str = STORE_ID) -> dict[str, Any]:
    return {"InstanceArn": arn, "IdentityStoreId": store_id, "OwnerAccountId": ACCOUNT, "Name": "default", "Status": "ACTIVE", "CreatedDate": datetime(2025, 1, 1, tzinfo=UTC)}


def _base_clients(sso: FakeClient, idstore: FakeClient) -> dict[Any, FakeClient]:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    clients[("sso-admin", R1)] = sso
    clients[("identitystore", R1)] = idstore
    return clients


# ---------------------------------------------------------------- Identity Center instance / permission sets


async def test_instance_and_permission_sets_with_managed_and_customer_policies(ctx: Any) -> None:  # noqa: F811
    sso = _sso_client(instances=[_instance()], managed=[{"Name": "ViewOnly", "Arn": "arn:aws:iam::aws:policy/ViewOnlyAccess"}], custom=[{"Name": "custom-pol", "Path": "/"}], provisioned_accounts=[ACCOUNT, OTHER_ACCOUNT])
    idstore = _identitystore_client()
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    assert key in report.completed_scopes
    instance_obs = next(o for o in report.observations if o.resource_type == "aws/sso_instance")
    assert instance_obs.resource_key == INSTANCE_ARN
    assert instance_obs.identity == {"account": ACCOUNT, "region": R1, "arn": INSTANCE_ARN, "instance_id": INSTANCE_ID, "identity_store_id": STORE_ID, "name": "default"}
    pset = next(o for o in report.observations if o.resource_type == "aws/sso_permission_set")
    assert pset.resource_key == PSET_ARN
    assert pset.identity == {"account": ACCOUNT, "region": R1, "arn": PSET_ARN, "name": "ReadOnly", "instance_arn": INSTANCE_ARN}
    assert pset.attributes["managed_policies"] == [{"name": "ViewOnly", "arn": "arn:aws:iam::aws:policy/ViewOnlyAccess"}]
    assert pset.attributes["customer_managed_policies"] == [{"name": "custom-pol", "path": "/"}]
    assert sorted(pset.attributes["provisioned_account_ids"]) == sorted([ACCOUNT, OTHER_ACCOUNT])
    assert pset.attributes["policy_refs_complete"] is True
    assert {"kind": "member_of", "target": INSTANCE_ARN} in pset.relationships
    assert {"kind": "grants_access_to", "target": f"aws:account:{OTHER_ACCOUNT}"} in pset.relationships
    pset_scope = f"{key}/{INSTANCE_ID}/permission_sets"
    assert pset_scope in report.completed_scopes


async def test_direct_user_and_group_account_assignments(ctx: Any) -> None:  # noqa: F811
    sso = _sso_client(instances=[_instance()], provisioned_accounts=[ACCOUNT, OTHER_ACCOUNT], assignments_by_account={ACCOUNT: [{"AccountId": ACCOUNT, "PermissionSetArn": PSET_ARN, "PrincipalType": "USER", "PrincipalId": "u-1"}], OTHER_ACCOUNT: [{"AccountId": OTHER_ACCOUNT, "PermissionSetArn": PSET_ARN, "PrincipalType": "GROUP", "PrincipalId": "g-1"}]})
    idstore = _identitystore_client()
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    assignments = [o for o in report.observations if o.resource_type == "aws/sso_account_assignment"]
    assert len(assignments) == 2
    user_assignment = next(a for a in assignments if a.identity["principal_type"] == "USER")
    assert user_assignment.resource_key == f"sso:{INSTANCE_ID}:assignment:{ACCOUNT}:{PSET_ARN}:USER:u-1"
    assert user_assignment.identity == {"account": ACCOUNT, "region": R1, "instance_arn": INSTANCE_ARN, "target_account_id": ACCOUNT, "permission_set_arn": PSET_ARN, "principal_type": "USER", "principal_id": "u-1"}
    assert {"kind": "assigns", "target": f"identitystore:{STORE_ID}:user:u-1"} in user_assignment.relationships
    assert {"kind": "grants_permission_set", "target": PSET_ARN} in user_assignment.relationships
    assert {"kind": "grants_access_to", "target": f"aws:account:{ACCOUNT}"} in user_assignment.relationships
    group_assignment = next(a for a in assignments if a.identity["principal_type"] == "GROUP")
    assert group_assignment.resource_key == f"sso:{INSTANCE_ID}:assignment:{OTHER_ACCOUNT}:{PSET_ARN}:GROUP:g-1"
    assert {"kind": "assigns", "target": f"identitystore:{STORE_ID}:group:g-1"} in group_assignment.relationships
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    assert f"{key}/{INSTANCE_ID}/assignments" in report.completed_scopes


# ---------------------------------------------------------------- Identity Store users/groups/memberships


async def test_users_groups_and_memberships(ctx: Any) -> None:  # noqa: F811
    sso = _sso_client(instances=[_instance()])
    idstore = _identitystore_client(
        users=[{"UserId": "u-1", "UserName": "alice", "DisplayName": "Alice A"}],
        groups=[{"GroupId": "g-1", "DisplayName": "admins", "Description": "admin group"}],
        memberships=[{"GroupMemberships": [{"MembershipId": "m-1", "GroupId": "g-1", "MemberId": {"UserId": "u-1"}}]}],
    )
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    user = next(o for o in report.observations if o.resource_type == "aws/identitystore_user")
    assert user.resource_key == f"identitystore:{STORE_ID}:user:u-1"
    assert user.identity == {"account": ACCOUNT, "region": R1, "identity_store_id": STORE_ID, "user_id": "u-1", "user_name": "alice"}
    assert user.attributes["display_name"] == "Alice A"
    group = next(o for o in report.observations if o.resource_type == "aws/identitystore_group")
    assert group.resource_key == f"identitystore:{STORE_ID}:group:g-1"
    assert group.attributes["member_count"] == 1 and group.attributes["members_complete"] is True
    membership = next(o for o in report.observations if o.resource_type == "aws/identitystore_group_membership")
    assert membership.resource_key == f"identitystore:{STORE_ID}:membership:m-1"
    assert {"kind": "member", "target": f"identitystore:{STORE_ID}:user:u-1"} in membership.relationships
    assert {"kind": "group", "target": f"identitystore:{STORE_ID}:group:g-1"} in membership.relationships
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    assert f"{key}/{INSTANCE_ID}/users" in report.completed_scopes
    assert f"{key}/{INSTANCE_ID}/groups" in report.completed_scopes
    assert f"{key}/{INSTANCE_ID}/memberships" in report.completed_scopes


async def test_no_emails_phones_or_external_ids_persisted_only_issuers(ctx: Any) -> None:  # noqa: F811
    canary_email = "alice+canary@example.com"
    canary_phone = "+1-555-0100-canary"
    canary_external_id = "scim-external-id-canary-value"
    sso = _sso_client(instances=[_instance()])
    idstore = _identitystore_client(
        users=[{"UserId": "u-1", "UserName": "alice", "DisplayName": "Alice A", "Emails": [{"Value": canary_email}], "PhoneNumbers": [{"Value": canary_phone}], "Addresses": [{"StreetAddress": "canary street"}], "Name": {"GivenName": "canary-given"}, "ExternalIds": [{"Issuer": "https://idp.example.com/", "Id": canary_external_id}]}],
        groups=[{"GroupId": "g-1", "DisplayName": "admins", "Description": "admin group", "ExternalIds": [{"Issuer": "https://idp.example.com/", "Id": canary_external_id}]}],
    )
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    user = next(o for o in report.observations if o.resource_type == "aws/identitystore_user")
    group = next(o for o in report.observations if o.resource_type == "aws/identitystore_group")
    assert user.attributes["external_id_issuers"] == ["https://idp.example.com/"]
    assert group.attributes["external_id_issuers"] == ["https://idp.example.com/"]
    blob = str([o.model_dump() for o in report.observations])
    assert canary_email not in blob and canary_phone not in blob and "canary street" not in blob and "canary-given" not in blob and canary_external_id not in blob
    text = await stored_evidence_text(ctx)
    assert canary_email not in text and canary_phone not in text and canary_external_id not in text


# ---------------------------------------------------------------- failure / absence semantics


async def test_inaccessible_identity_center_is_unavailable_never_no_instance(ctx: Any) -> None:  # noqa: F811
    sso = FakeClient("sso-admin", {}, {"list_instances": client_error("AccessDeniedException", "ListInstances")})
    idstore = _identitystore_client()
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    assert key not in report.completed_scopes
    assert not any(o.resource_type.startswith("aws/sso_") or o.resource_type.startswith("aws/identitystore_") for o in report.observations)
    denied = next(u for u in report.unavailable if u["source"] == key)
    assert denied["reason"] == "permission_denied"
    ic = report.aws_coverage.get("identity_center") or []
    assert ic and ic[0]["status"] == "unavailable"
    assert "no instance" not in str(ic[0].get("note") or "").lower()  # unavailable is never reported as "no instance"


async def test_empty_instances_is_complete_with_note(ctx: Any) -> None:  # noqa: F811
    sso = _sso_client(instances=[])
    idstore = _identitystore_client()
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    assert key in report.completed_scopes
    ic = report.aws_coverage.get("identity_center") or []
    assert ic and ic[0]["status"] == "no_instance_in_this_account_region"
    assert "management or delegated-administrator account" in ic[0]["note"]
    assert not any(o.resource_type == "aws/sso_instance" for o in report.observations)


async def test_partial_group_membership_listing_does_not_fail_other_groups(ctx: Any) -> None:  # noqa: F811
    def memberships(kw: dict[str, Any]) -> Any:
        if kw["GroupId"] == "g-bad":
            return client_error("AccessDenied", "ListGroupMemberships")
        return [{"GroupMemberships": [{"MembershipId": "m-ok", "GroupId": "g-ok", "MemberId": {"UserId": "u-1"}}]}]

    sso = _sso_client(instances=[_instance()])
    idstore = _identitystore_client(groups=[{"GroupId": "g-ok", "DisplayName": "ok"}, {"GroupId": "g-bad", "DisplayName": "bad"}], memberships=memberships)
    ad, _ = adapter(_base_clients(sso, idstore), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["identitycenter"]), ctx.budget)
    key = f"aws-prod/{ACCOUNT}/{R1}/identitycenter"
    memberships_scope = f"{key}/{INSTANCE_ID}/memberships"
    assert memberships_scope in report.partial_scopes and memberships_scope not in report.completed_scopes
    groups_by_id = {o.identity["group_id"]: o for o in report.observations if o.resource_type == "aws/identitystore_group"}
    assert groups_by_id["g-ok"].attributes["members_complete"] is True
    assert groups_by_id["g-bad"].attributes["members_complete"] is False
    assert any(u.get("operation") == "list_group_memberships" for u in report.unavailable)


# ---------------------------------------------------------------- IAM groups / policy references / instance profiles


def _iam_client(ops: dict[str, Any] | None = None, **pages: Any) -> FakeClient:
    base_pages = {"list_users": [{"Users": []}], "list_roles": [{"Roles": []}], "list_groups": [{"Groups": []}], "list_instance_profiles": [{"InstanceProfiles": []}], "list_attached_user_policies": [{"AttachedPolicies": []}], "list_user_policies": [{"PolicyNames": []}], "list_attached_role_policies": [{"AttachedPolicies": []}], "list_role_policies": [{"PolicyNames": []}], "list_attached_group_policies": [{"AttachedPolicies": []}], "list_group_policies": [{"PolicyNames": []}], "list_access_keys": [{"AccessKeyMetadata": []}]}
    base_pages.update(pages)
    base_ops: dict[str, Any] = {"get_account_summary": {"SummaryMap": {}}, "get_group": lambda kw: {"Group": {"Arn": f"arn:aws:iam::{ACCOUNT}:group/{kw['GroupName']}", "GroupId": "GID1", "Path": "/", "CreateDate": datetime(2025, 1, 1, tzinfo=UTC)}, "Users": [{"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice"}]}}
    base_ops.update(ops or {})
    return FakeClient("iam", base_ops, base_pages)


async def test_iam_groups_get_group_membership_and_policy_refs(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    clients["iam"] = _iam_client(
        list_users=[{"Users": [{"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "UserId": "AIDA1"}]}],
        list_groups=[{"Groups": [{"GroupName": "admins"}]}],
        list_attached_user_policies=[{"AttachedPolicies": [{"PolicyName": "ViewOnly", "PolicyArn": "arn:aws:iam::aws:policy/ViewOnlyAccess"}]}],
        list_user_policies=[{"PolicyNames": ["inline-one"]}],
        list_attached_group_policies=[{"AttachedPolicies": [{"PolicyName": "GroupPolicy", "PolicyArn": "arn:aws:iam::aws:policy/GroupPolicy"}]}],
        list_group_policies=[{"PolicyNames": ["group-inline"]}],
        list_access_keys=[{"AccessKeyMetadata": []}],
    )
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    group = next(o for o in report.observations if o.resource_type == "aws/iam_group")
    assert group.resource_key == f"arn:aws:iam::{ACCOUNT}:group/admins"
    assert group.attributes["member_user_names"] == ["alice"]
    assert group.attributes["members_complete"] is True
    assert group.attributes["attached_policies"] == [{"name": "GroupPolicy", "arn": "arn:aws:iam::aws:policy/GroupPolicy"}]
    assert group.attributes["inline_policy_names"] == ["group-inline"]
    assert {"kind": "has_member", "target": f"arn:aws:iam::{ACCOUNT}:user/alice"} in group.relationships
    user = next(o for o in report.observations if o.resource_type == "aws/iam_user")
    assert user.attributes["group_names"] == ["admins"]
    assert user.attributes["attached_policies"] == [{"name": "ViewOnly", "arn": "arn:aws:iam::aws:policy/ViewOnlyAccess"}]
    assert user.attributes["inline_policy_names"] == ["inline-one"]
    assert user.attributes["policy_refs_complete"] is True
    assert {"kind": "member_of", "target": f"arn:aws:iam::{ACCOUNT}:group/admins"} in user.relationships
    assert {"kind": "attached_policy", "target": "arn:aws:iam::aws:policy/ViewOnlyAccess"} in user.relationships
    iam_key = f"aws-prod/{ACCOUNT}/global/iam"
    assert f"{iam_key}/groups" in report.completed_scopes
    assert f"{iam_key}/policy_refs" in report.completed_scopes
    # Only name/ARN listing operations were called, never a policy-document read.
    all_ops = {name for name, _ in clients["iam"].calls}
    forbidden = {"get_policy_version", "get_user_policy", "get_group_policy", "get_role_policy", "get_account_authorization_details", "get_inline_policy_for_permission_set"}
    assert not (all_ops & forbidden)


async def test_iam_instance_profile_to_role_relationship(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/node"
    clients["iam"] = _iam_client(list_instance_profiles=[{"InstanceProfiles": [{"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/node", "InstanceProfileName": "node", "InstanceProfileId": "IPID1", "Path": "/", "CreateDate": datetime(2025, 1, 1, tzinfo=UTC), "Roles": [{"Arn": role_arn}]}]}])
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    profile = next(o for o in report.observations if o.resource_type == "aws/iam_instance_profile")
    assert profile.resource_key == f"arn:aws:iam::{ACCOUNT}:instance-profile/node"
    assert profile.attributes["role_arns"] == [role_arn]
    assert {"kind": "contains_role", "target": role_arn} in profile.relationships
    iam_key = f"aws-prod/{ACCOUNT}/global/iam"
    assert f"{iam_key}/instance_profiles" in report.completed_scopes


async def test_role_class_and_trust_principals_dict_and_url_encoded(ctx: Any) -> None:  # noqa: F811
    dict_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    url_trust = "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A999999999999%3Aroot%22%7D%7D%5D%7D"
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    clients["iam"] = _iam_client(
        list_roles=[{"Roles": [
            {"RoleName": "sso-role", "Arn": f"arn:aws:iam::{ACCOUNT}:role/sso-role", "Path": "/aws-reserved/sso.amazonaws.com/", "AssumeRolePolicyDocument": dict_trust},
            {"RoleName": "cross-account", "Arn": f"arn:aws:iam::{ACCOUNT}:role/cross-account", "Path": "/", "AssumeRolePolicyDocument": url_trust},
            {"RoleName": "linked", "Arn": f"arn:aws:iam::{ACCOUNT}:role/linked", "Path": "/aws-service-role/elasticloadbalancing.amazonaws.com/", "AssumeRolePolicyDocument": {"Statement": []}},
        ]}],
    )
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    roles = {o.identity["name"]: o for o in report.observations if o.resource_type == "aws/iam_role"}
    assert roles["sso-role"].attributes["role_class"] == "identity_center"
    assert roles["sso-role"].attributes["trust_principals"]["services"] == ["eks.amazonaws.com"]
    assert roles["cross-account"].attributes["role_class"] == "standard"
    assert roles["cross-account"].attributes["trust_principals"]["aws"] == ["arn:aws:iam::999999999999:root"]
    assert roles["linked"].attributes["role_class"] == "service_linked"


async def test_iam_access_key_behavior_unchanged_no_credential_values(ctx: Any) -> None:  # noqa: F811
    fake_key = "AKIAIOSFODNN7EXAMPLE"
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    clients["iam"] = _iam_client(
        ops={"get_access_key_last_used": {"AccessKeyLastUsed": {}}},
        list_users=[{"Users": [{"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "UserId": "AIDA1"}]}],
        list_access_keys=[{"AccessKeyMetadata": [{"AccessKeyId": fake_key, "Status": "Active", "CreateDate": datetime(2024, 1, 1, tzinfo=UTC)}]}],
    )
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    key_obs = next(o for o in report.observations if o.resource_type == "aws/iam_access_key")
    assert key_obs.identity["access_key_suffix"] == "MPLE"
    assert "access_key_hash" in key_obs.identity and fake_key not in key_obs.identity["access_key_hash"]
    blob = str([o.model_dump() for o in report.observations])
    assert fake_key not in blob
