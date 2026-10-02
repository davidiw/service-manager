"""Deterministic resource relationships added to EC2/ASG/ELB/Lambda/EKS, and a read-only-API audit
for every new AWS operation touched by this change. All calls are in-process fakes."""

from __future__ import annotations

import ast
import re
from pathlib import Path
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

_PROVIDER_DIR = Path(__file__).parents[2] / "src" / "local_ops" / "providers"


# ---------------------------------------------------------------- EC2 instance relationships


async def test_ec2_instance_relationships_subnet_vpc_sg_volume_profile(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    instance = {
        "InstanceId": "i-1",
        "InstanceType": "m6i.large",
        "State": {"Name": "running"},
        "SubnetId": "subnet-1",
        "VpcId": "vpc-1",
        "PrivateDnsName": "ip-10-0-0-1.ec2.internal",
        "PublicDnsName": "ec2-1-2-3-4.compute-1.amazonaws.com",
        "Platform": "linux",
        "PlatformDetails": "Linux/UNIX",
        "Architecture": "x86_64",
        "SecurityGroups": [{"GroupId": "sg-1"}],
        "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
        "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/node"},
    }
    clients[("ec2", R1)] = FakeClient("ec2", {"describe_regions": {"Regions": [{"RegionName": R1}]}}, {"describe_instances": [{"Reservations": [{"Instances": [instance]}]}], "describe_volumes": [{"Volumes": []}], "describe_vpcs": [{"Vpcs": []}], "describe_subnets": [{"Subnets": []}], "describe_security_groups": [{"SecurityGroups": []}], "describe_nat_gateways": [{"NatGateways": []}], "describe_snapshots": [{"Snapshots": []}], "describe_images": [{"Images": []}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["ec2"]), ctx.budget)
    inst = next(o for o in report.observations if o.resource_type == "aws/ec2_instance")
    rels = inst.relationships
    assert {"kind": "network_in", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:subnet/subnet-1"} in rels
    assert {"kind": "network_in", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:vpc/vpc-1"} in rels
    assert {"kind": "network_in", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:security-group/sg-1"} in rels
    assert {"kind": "uses_volume", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:volume/vol-1"} in rels
    assert {"kind": "uses_instance_profile", "target": f"arn:aws:iam::{ACCOUNT}:instance-profile/node"} in rels
    assert inst.attributes["private_dns_name"] == "ip-10-0-0-1.ec2.internal"
    assert inst.attributes["public_dns_name"] == "ec2-1-2-3-4.compute-1.amazonaws.com"
    assert inst.attributes["platform_details"] == "Linux/UNIX"
    assert inst.attributes["architecture"] == "x86_64"


# ---------------------------------------------------------------- Auto Scaling group


async def test_asg_contains_instances_and_name_key(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    group = {"AutoScalingGroupARN": f"arn:aws:autoscaling:{R1}:{ACCOUNT}:autoScalingGroup:uuid:autoScalingGroupName/web-asg", "AutoScalingGroupName": "web-asg", "Instances": [{"InstanceId": "i-1"}, {"InstanceId": "i-2"}]}
    clients[("autoscaling", R1)] = FakeClient("autoscaling", {}, {"describe_auto_scaling_groups": [{"AutoScalingGroups": [group]}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["autoscaling"]), ctx.budget)
    asg = next(o for o in report.observations if o.resource_type == "aws/autoscaling_group")
    assert asg.identity["name_key"] == f"aws:{ACCOUNT}:{R1}:autoscaling:web-asg"
    assert {"kind": "contains", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:instance/i-1"} in asg.relationships
    assert {"kind": "contains", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:instance/i-2"} in asg.relationships


# ---------------------------------------------------------------- ELB target health


async def test_target_health_routes_to_instance_ip_and_lambda_with_partial_on_failure(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    tgs = [
        {"TargetGroupArn": "arn:tg:instance", "TargetGroupName": "tg-instance", "TargetType": "instance"},
        {"TargetGroupArn": "arn:tg:ip", "TargetGroupName": "tg-ip", "TargetType": "ip"},
        {"TargetGroupArn": "arn:tg:lambda", "TargetGroupName": "tg-lambda", "TargetType": "lambda"},
        {"TargetGroupArn": "arn:tg:broken", "TargetGroupName": "tg-broken", "TargetType": "instance"},
    ]

    def describe_target_health(kw: dict[str, Any]) -> Any:
        arn = kw["TargetGroupArn"]
        if arn == "arn:tg:instance":
            return {"TargetHealthDescriptions": [{"Target": {"Id": "i-1", "Port": 80}, "TargetHealth": {"State": "healthy"}}]}
        if arn == "arn:tg:ip":
            return {"TargetHealthDescriptions": [{"Target": {"Id": "10.0.0.5", "Port": 80}, "TargetHealth": {"State": "healthy"}}]}
        if arn == "arn:tg:lambda":
            return {"TargetHealthDescriptions": [{"Target": {"Id": "arn:aws:lambda:x:1:function:f"}, "TargetHealth": {"State": "healthy"}}]}
        return client_error("AccessDenied", "DescribeTargetHealth")

    clients[("elbv2", R1)] = FakeClient("elbv2", {"describe_target_health": describe_target_health}, {"describe_load_balancers": [{"LoadBalancers": []}], "describe_target_groups": [{"TargetGroups": tgs}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["elb"]), ctx.budget)
    by_arn = {o.resource_key: o for o in report.observations if o.resource_type == "aws/target_group"}
    assert {"kind": "routes_to", "target": f"arn:aws:ec2:{R1}:{ACCOUNT}:instance/i-1"} in by_arn["arn:tg:instance"].relationships
    assert {"kind": "routes_to_ip", "target": "10.0.0.5"} in by_arn["arn:tg:ip"].relationships
    assert {"kind": "routes_to", "target": "arn:aws:lambda:x:1:function:f"} in by_arn["arn:tg:lambda"].relationships
    assert by_arn["arn:tg:instance"].attributes["targets"] == [{"id": "i-1", "port": 80, "availability_zone": None, "health_state": "healthy", "health_reason": None}]
    target_health_scope = f"aws-prod/{ACCOUNT}/{R1}/elb/target_health"
    assert target_health_scope in report.partial_scopes and target_health_scope not in report.completed_scopes
    assert any(u.get("operation") == "describe_target_health" for u in report.unavailable)
    assert by_arn["arn:tg:broken"].attributes["targets"] == []


# ---------------------------------------------------------------- Lambda logs_to


async def test_lambda_logs_to_only_when_logging_config_present(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    with_log = {"FunctionArn": "arn:fn:with-log", "FunctionName": "with-log", "LoggingConfig": {"LogGroup": "/custom/log/group"}}
    without_log = {"FunctionArn": "arn:fn:without-log", "FunctionName": "without-log"}
    clients[("lambda", R1)] = FakeClient("lambda", {}, {"list_functions": [{"Functions": [with_log, without_log]}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["lambda"]), ctx.budget)
    by_arn = {o.resource_key: o for o in report.observations if o.resource_type == "aws/lambda_function"}
    assert by_arn["arn:fn:with-log"].attributes["log_group"] == "/custom/log/group"
    assert {"kind": "logs_to", "target": f"arn:aws:logs:{R1}:{ACCOUNT}:log-group:/custom/log/group"} in by_arn["arn:fn:with-log"].relationships
    assert by_arn["arn:fn:without-log"].attributes["log_group"] is None
    assert not any(r["kind"] == "logs_to" for r in by_arn["arn:fn:without-log"].relationships)


# ---------------------------------------------------------------- EKS control-plane logging


async def test_eks_logs_to_only_when_control_plane_logging_enabled(ctx: Any) -> None:  # noqa: F811
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global(), **empty_regional(R1)}
    logging_enabled = {"name": "with-logs", "arn": f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/with-logs", "logging": {"clusterLogging": [{"types": ["api"], "enabled": True}]}}
    logging_disabled = {"name": "no-logs", "arn": f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/no-logs", "logging": {"clusterLogging": [{"types": ["api"], "enabled": False}]}}
    clients[("eks", R1)] = FakeClient("eks", {"describe_cluster": lambda kw: {"cluster": logging_enabled if kw["name"] == "with-logs" else logging_disabled}}, {"list_clusters": [{"clusters": ["with-logs", "no-logs"]}], "list_access_entries": [{"accessEntries": []}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["eks"]), ctx.budget)
    by_arn = {o.resource_key: o for o in report.observations if o.resource_type == "aws/eks_cluster"}
    enabled = by_arn[f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/with-logs"]
    disabled = by_arn[f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/no-logs"]
    assert enabled.attributes["control_plane_log_group"] == "/aws/eks/with-logs/cluster"
    assert {"kind": "logs_to", "target": f"arn:aws:logs:{R1}:{ACCOUNT}:log-group:/aws/eks/with-logs/cluster"} in enabled.relationships
    assert disabled.attributes["control_plane_log_group"] is None
    assert not any(r["kind"] == "logs_to" for r in disabled.relationships)


# ---------------------------------------------------------------- read-only API audit


def test_every_new_aws_operation_is_a_read_operation() -> None:
    """Every `_call`/`_paginate` operation name added by this change is list_/describe_/get_, and
    never a policy-document or credential-value read."""
    forbidden = {"get_policy_version", "get_role_policy", "get_user_policy", "get_group_policy", "get_inline_policy_for_permission_set", "get_account_authorization_details", "get_secret_value", "get_login_profile"}
    pattern = re.compile(r'"(list_[a-z_]+|describe_[a-z_]+|get_[a-z_]+)"')
    found: set[str] = set()
    for name in ("aws.py", "aws_identity.py"):
        source = (_PROVIDER_DIR / name).read_text(encoding="utf-8")
        # Only inspect call sites that go through the adapter's bounded call/pagination helpers.
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"_call", "_paginate"}:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and pattern.fullmatch(f'"{arg.value}"'):
                        found.add(arg.value)
    assert found  # sanity: the scan actually found operations
    assert not (found & forbidden)
    assert all(op.startswith(("list_", "describe_", "get_")) for op in found)


def test_aws_identity_module_never_reads_policy_documents_or_secret_values() -> None:
    source = (_PROVIDER_DIR / "aws_identity.py").read_text(encoding="utf-8").lower()
    for forbidden in ("get_policy_version", "get_role_policy", "get_user_policy", "get_group_policy", "get_inline_policy_for_permission_set", "get_account_authorization_details"):
        assert forbidden not in source
