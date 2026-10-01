"""Contract fixtures for data census families through AwsAdapter, not a facade."""
from __future__ import annotations

from typing import Any

import pytest

from local_ops.providers.base import DiscoveryScope
from tests.providers.test_aws import (
    ACCOUNT,
    R1,
    FakeClient,
    adapter,
    client_error,
    stored_evidence_text,
    sts_client,
)

pytest_plugins = ["tests.providers.test_aws"]


def _two_pages(key: str, values: list[Any]) -> list[dict[str, Any]]:
    return [{key: [values[0]]}, {key: values[1:]}]


def _client_for(family: str) -> FakeClient:
    if family == "secretsmanager":
        def secret(kwargs: dict[str, Any]) -> dict[str, Any]:
            arn = kwargs["SecretId"]
            return {"ARN": arn, "Name": arn.rsplit(":", 1)[-1], "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/k", "SecretString": "must-not-store"}
        def secret_pages(kwargs: dict[str, Any]) -> list[dict[str, Any]]:
            return [{"SecretList": [{"ARN": "arn:secret:one"}], "NextToken": "two"}] if not kwargs.get("NextToken") else [{"SecretList": [{"ARN": "arn:secret:two"}]}]
        return FakeClient("secretsmanager", {"describe_secret": secret, "list_secrets": lambda k: secret_pages(k)[0]}, {})
    if family == "logs":
        def log_pages(kwargs: dict[str, Any]) -> dict[str, Any]:
            return {"logGroups": [{"arn": "arn:aws:logs:us-east-1:123:log-group:/one:*", "logGroupName": "/one"}], "nextToken": "two"} if not kwargs.get("nextToken") else {"logGroups": [{"arn": "arn:aws:logs:us-east-1:123:log-group:/two:*", "logGroupName": "/two"}]}
        return FakeClient("logs", {"describe_log_groups": log_pages, "list_tags_for_resource": {"tags": {"team": "x"}}}, {})
    if family == "kms":
        return FakeClient("kms", {"describe_key": lambda k: {"KeyMetadata": {"KeyId": k["KeyId"], "Arn": f"arn:aws:kms:{R1}:{ACCOUNT}:key/{k['KeyId']}", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT"}}, "get_key_rotation_status": {"KeyRotationEnabled": True}}, {"list_keys": _two_pages("Keys", [{"KeyId": "one"}, {"KeyId": "two"}]), "list_aliases": [{"Aliases": []}], "list_resource_tags": [{"Tags": [{"TagKey": "team", "TagValue": "x"}]}]})
    if family == "cloudwatch":
        return FakeClient("cloudwatch", {}, {"describe_alarms": [{"MetricAlarms": [{"AlarmArn": "arn:a:one", "AlarmName": "one"}], "CompositeAlarms": [{"AlarmArn": "arn:a:two", "AlarmName": "two", "AlarmRule": "ALARM(one)"}], "LogAlarms": [{"AlarmArn": "arn:a:log", "AlarmName": "log", "ScheduledQueryConfiguration": {"LogGroupIdentifiers": ["arn:aws:logs:us-east-1:123:log-group:/safe"], "QueryARN": "arn:query"}}]}, {"MetricAlarms": [{"AlarmArn": "arn:a:three", "AlarmName": "three"}], "CompositeAlarms": [], "LogAlarms": []}]})
    if family == "dynamodb":
        return FakeClient("dynamodb", {"describe_table": lambda k: {"Table": {"TableName": k["TableName"], "TableArn": f"arn:aws:dynamodb:{R1}:{ACCOUNT}:table/{k['TableName']}", "SSEDescription": {"KMSMasterKeyArn": "arn:kms:k"}}}}, {"list_tables": _two_pages("TableNames", ["one", "two"]), "list_tags_of_resource": [{"Tags": []}]})
    if family == "elasticache":
        return FakeClient("elasticache", {"list_tags_for_resource": {"TagList": []}}, {"describe_cache_clusters": _two_pages("CacheClusters", [{"CacheClusterId": "one", "ARN": "arn:cache:one"}, {"CacheClusterId": "two", "ARN": "arn:cache:two"}]), "describe_replication_groups": _two_pages("ReplicationGroups", [{"ReplicationGroupId": "r1", "MemberClusters": ["one"]}, {"ReplicationGroupId": "r2", "MemberClusters": ["two"]}])})
    if family == "efs":
        return FakeClient("efs", {"list_tags_for_resource": {"Tags": []}, "describe_mount_target_security_groups": {"SecurityGroups": ["sg-1"]}}, {"describe_file_systems": _two_pages("FileSystems", [{"FileSystemId": "one", "FileSystemArn": "arn:efs:one"}, {"FileSystemId": "two", "FileSystemArn": "arn:efs:two"}]), "describe_mount_targets": [{"MountTargets": [{"MountTargetId": "mt-1", "SubnetId": "subnet-1"}]}]})
    if family == "opensearch":
        names = [{"DomainName": f"d{i}"} for i in range(6)]
        return FakeClient("opensearch", {"list_domain_names": {"DomainNames": names}, "describe_domains": lambda k: {"DomainStatusList": [{"DomainName": n, "ARN": f"arn:os:{n}"} for n in k["DomainNames"]]}, "list_tags": {"TagList": []}}, {})
    raise AssertionError(family)


@pytest.mark.parametrize("family,minimum", [("secretsmanager", 2), ("kms", 2), ("logs", 2), ("cloudwatch", 3), ("dynamodb", 2), ("elasticache", 4), ("efs", 2), ("opensearch", 6)])
async def test_data_families_enumerate_multiple_provider_pages_via_adapter(ctx: Any, family: str, minimum: int) -> None:
    client = _client_for(family)
    ad, _ = adapter({"sts": sts_client(), (client.service, R1): client}, regions=[R1], families=[family])
    report = await ad.discover(ctx, DiscoveryScope(families=[family]), ctx.budget)
    assert len(report.observations) >= minimum
    assert not report.unavailable, report.unavailable
    assert f"aws-prod/{ACCOUNT}/{R1}/{family}" in report.completed_scopes, report.model_dump()
    if family == "secretsmanager":
        text = await stored_evidence_text(ctx)
        assert "must-not-store" not in text
        assert "get_secret_value" not in [name for name, _ in client.calls]
    if family == "logs":
        tag_calls = [kwargs for name, kwargs in client.calls if name == "list_tags_for_resource"]
        assert tag_calls and all(not call["resourceArn"].endswith(":*") for call in tag_calls)
    if family == "cloudwatch":
        assert any(o.resource_type == "aws/cloudwatch_alarm" and o.attributes["type"] == "log" for o in report.observations)
    if family == "opensearch":
        assert len([1 for name, _ in client.calls if name == "describe_domains"]) == 2


async def test_denied_data_family_is_partial_while_other_data_family_completes(ctx: Any) -> None:
    denied = FakeClient("dynamodb", {}, {"list_tables": client_error("AccessDeniedException", "ListTables")})
    logs = _client_for("logs")
    ad, _ = adapter({"sts": sts_client(), ("dynamodb", R1): denied, ("logs", R1): logs}, regions=[R1], families=["dynamodb", "logs"])
    report = await ad.discover(ctx, DiscoveryScope(families=["dynamodb", "logs"]), ctx.budget)
    assert f"aws-prod/{ACCOUNT}/{R1}/dynamodb" in report.partial_scopes
    assert f"aws-prod/{ACCOUNT}/{R1}/logs" in report.completed_scopes
