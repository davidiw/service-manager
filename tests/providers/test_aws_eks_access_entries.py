"""EKS access entries: `list_access_entries`, `describe_access_entry`, and
`list_associated_access_policies`, with Identity Center permission-set name recovery for
`AWSReservedSSO_<permission set>_<suffix>` principals. All calls are in-process fakes (see
tests/providers/test_aws.py)."""

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
    sts_client,
)

CLUSTER_ARN = f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/prod"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/deploy-bot"
SSO_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_1234567890abcdef"


def _eks_client(*, clusters: list[str] | None = None, access_entries: Any = None, describe: Any = None, policies: Any = None) -> FakeClient:
    pages: dict[str, Any] = {"list_clusters": [{"clusters": clusters if clusters is not None else ["prod"]}]}
    if access_entries is not None:
        pages["list_access_entries"] = access_entries
    else:
        pages["list_access_entries"] = [{"accessEntries": []}]
    if policies is not None:
        pages["list_associated_access_policies"] = policies
    ops: dict[str, Any] = {"describe_cluster": {"cluster": {"name": "prod", "arn": CLUSTER_ARN}}}
    if describe is not None:
        ops["describe_access_entry"] = describe
    return FakeClient("eks", ops, pages)


def _base_clients(eks: FakeClient) -> dict[Any, FakeClient]:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    clients[("eks", R1)] = eks
    return clients


async def test_access_entry_with_associated_policy_and_scope(ctx: Any) -> None:  # noqa: F811
    def describe(kw: dict[str, Any]) -> dict[str, Any]:
        return {"accessEntry": {"clusterName": "prod", "principalArn": ROLE_ARN, "kubernetesGroups": ["system:masters"], "username": "deploy-bot", "type": "STANDARD", "accessEntryArn": f"{CLUSTER_ARN}/access-entry/deploy-bot", "createdAt": datetime(2026, 1, 1, tzinfo=UTC), "modifiedAt": datetime(2026, 1, 2, tzinfo=UTC)}}

    eks = _eks_client(
        access_entries=[{"accessEntries": [ROLE_ARN]}],
        describe=describe,
        policies=[{"associatedAccessPolicies": [{"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy", "accessScope": {"type": "namespace", "namespaces": ["default"]}, "associatedAt": datetime(2026, 1, 1, tzinfo=UTC)}]}],
    )
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    entries = [o for o in report.observations if o.resource_type == "aws/eks_access_entry"]
    assert len(entries) == 1
    e = entries[0]
    assert e.resource_key == f"{CLUSTER_ARN}/access-entry/deploy-bot"
    assert e.identity == {"account": ACCOUNT, "region": R1, "cluster": "prod", "principal_arn": ROLE_ARN}
    assert e.attributes["type"] == "STANDARD"
    assert e.attributes["kubernetes_groups"] == ["system:masters"]
    assert e.attributes["username"] == "deploy-bot"
    assert e.attributes["created_at"] == "2026-01-01T00:00:00Z"
    assert e.attributes["associated_policies"] == [{"policy_arn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy", "access_scope_type": "namespace", "namespaces": ["default"], "associated_at": "2026-01-01T00:00:00Z"}]
    assert e.attributes["access_scope_types"] == ["namespace"]
    assert e.attributes["permission_set_name"] is None
    assert e.attributes["detail_complete"] is True
    assert {"kind": "grants_cluster_access", "target": CLUSTER_ARN} in e.relationships
    assert {"kind": "principal", "target": ROLE_ARN} in e.relationships
    scope_key = f"aws-prod/{ACCOUNT}/{R1}/eks/prod/access_entries"
    assert scope_key in report.completed_scopes


async def test_identity_center_reserved_role_permission_set_name_recovered(ctx: Any) -> None:  # noqa: F811
    def describe(kw: dict[str, Any]) -> dict[str, Any]:
        return {"accessEntry": {"clusterName": "prod", "principalArn": SSO_ROLE_ARN, "kubernetesGroups": [], "username": None, "type": "STANDARD"}}

    eks = _eks_client(access_entries=[{"accessEntries": [SSO_ROLE_ARN]}], describe=describe, policies=[{"associatedAccessPolicies": []}])
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    e = next(o for o in report.observations if o.resource_type == "aws/eks_access_entry")
    assert e.attributes["permission_set_name"] == "AdministratorAccess"
    assert {"kind": "principal", "target": SSO_ROLE_ARN} in e.relationships


async def test_access_entries_paginated(ctx: Any) -> None:  # noqa: F811
    other_role = f"arn:aws:iam::{ACCOUNT}:role/other-bot"

    def describe(kw: dict[str, Any]) -> dict[str, Any]:
        return {"accessEntry": {"clusterName": "prod", "principalArn": kw["principalArn"], "kubernetesGroups": [], "username": None, "type": "STANDARD"}}

    eks = _eks_client(access_entries=[{"accessEntries": [ROLE_ARN]}, {"accessEntries": [other_role]}], describe=describe, policies=[{"associatedAccessPolicies": []}])
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    entries = {o.identity["principal_arn"] for o in report.observations if o.resource_type == "aws/eks_access_entry"}
    assert entries == {ROLE_ARN, other_role}


async def test_list_access_entries_denied_is_partial_child_scope(ctx: Any) -> None:  # noqa: F811
    eks = _eks_client(access_entries=client_error("AccessDeniedException", "ListAccessEntries"))
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    scope_key = f"aws-prod/{ACCOUNT}/{R1}/eks/prod/access_entries"
    assert scope_key in report.partial_scopes and scope_key not in report.completed_scopes
    assert not any(o.resource_type == "aws/eks_access_entry" for o in report.observations)
    denied = [u for u in report.unavailable if u["source"] == scope_key]
    assert denied and denied[0]["operation"] == "list_access_entries" and denied[0]["reason"] == "permission_denied"
    # the cluster itself is still observed; a denied access-entry listing never hides the cluster
    assert any(o.resource_type == "aws/eks_cluster" for o in report.observations)


async def test_describe_access_entry_denied_keeps_entry_partial(ctx: Any) -> None:  # noqa: F811
    eks = _eks_client(access_entries=[{"accessEntries": [ROLE_ARN]}], describe=client_error("AccessDenied", "DescribeAccessEntry"), policies=[{"associatedAccessPolicies": []}])
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    e = next(o for o in report.observations if o.resource_type == "aws/eks_access_entry")
    assert e.attributes["detail_complete"] is False
    assert e.attributes["type"] is None and e.attributes["kubernetes_groups"] == []
    scope_key = f"aws-prod/{ACCOUNT}/{R1}/eks/prod/access_entries"
    assert scope_key in report.partial_scopes and scope_key not in report.completed_scopes
    assert any(u["operation"] == "describe_access_entry" for u in report.unavailable)


async def test_list_associated_access_policies_denied_keeps_entry_partial(ctx: Any) -> None:  # noqa: F811
    def describe(kw: dict[str, Any]) -> dict[str, Any]:
        return {"accessEntry": {"clusterName": "prod", "principalArn": ROLE_ARN, "kubernetesGroups": [], "username": None, "type": "STANDARD"}}

    eks = _eks_client(access_entries=[{"accessEntries": [ROLE_ARN]}], describe=describe, policies=client_error("AccessDenied", "ListAssociatedAccessPolicies"))
    ad, _ = adapter(_base_clients(eks), regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    e = next(o for o in report.observations if o.resource_type == "aws/eks_access_entry")
    assert e.attributes["detail_complete"] is False
    assert e.attributes["associated_policies"] == []
    assert any(u["operation"] == "list_associated_access_policies" for u in report.unavailable)
