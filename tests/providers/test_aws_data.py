from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from botocore.session import get_session

from local_ops.providers import aws_data


class _Budget:
    def check(self) -> None: pass


class _Ctx:
    async def store_evidence(self, provider: str, kind: str, payload: dict[str, Any], *, summary: str) -> str:
        self.payloads.append((kind, payload))
        return f"e-{len(self.payloads)}"

    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, Any]]] = []


class _Client:
    async def __aenter__(self) -> _Client: return self
    async def __aexit__(self, *args: Any) -> None: return None


class _Adapter:
    def __init__(self, pages: dict[tuple[str, str], list[list[Any]]], calls: dict[tuple[str, str], dict[str, Any]]) -> None:
        self.pages, self.responses = pages, calls
        self.calls: list[str] = []
        self.observations: list[dict[str, Any]] = []

    def _client(self, service: str, region: str) -> _Client: return _Client()
    def _fkey(self, account: str, region: str, family: str) -> str: return f"p/{account}/{region}/{family}"
    async def _evidence(self, ctx: _Ctx, account: str, region: str, family: str, payload: dict[str, Any], summary: str) -> str:
        return await ctx.store_evidence("p", family, payload, summary=summary)
    def _obs(self, key: str, resource_type: str, identity: dict[str, Any], attributes: dict[str, Any], scope_key: str, eid: str, relationships: list[dict[str, str]] | None = None) -> dict[str, Any]:
        return {"key": key, "type": resource_type, "attributes": attributes, "relationships": relationships or []}
    async def _call(self, client: _Client, operation: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(operation)
        return self.responses.get(("call", operation), {})
    async def _paginate(self, client: _Client, operation: str, result_key: str, ctx: Any, budget: Any, **kwargs: Any) -> tuple[list[Any], bool]:
        self.calls.append(operation)
        return [i for page in self.pages.get(("paginate", operation), []) for i in page], True
    async def _census_pages(self, client: _Client, operation: str, result_key: str, ctx: Any, budget: Any, report: Any, **kwargs: Any):
        self.calls.append(operation)
        for page in self.pages.get(("census", operation), []):
            yield page


class _Report:
    def __init__(self) -> None:
        self.observations: list[dict[str, Any]] = []
        self.unavailable: list[dict[str, Any]] = []


@pytest.mark.asyncio
async def test_secrets_pages_store_metadata_only_and_never_read_values() -> None:
    ad = _Adapter({("census", "list_secrets"): [[{"ARN": "arn:secret:one"}], [{"ARN": "arn:secret:two"}]]}, {("call", "describe_secret"): {"ARN": "arn:secret:one", "Name": "one", "KmsKeyId": "arn:kms:key", "RotationEnabled": True}})
    ctx, report = _Ctx(), _Report()
    assert await aws_data.discover(ad, "secretsmanager", ctx, _Budget(), report, None, "123", "us-east-1", [])
    assert len(report.observations) == 2
    assert "get_secret_value" not in ad.calls
    assert "SecretString" not in str(ctx.payloads)
    assert report.observations[0]["relationships"] == [{"kind": "encrypted_by", "target": "arn:kms:key"}]


@pytest.mark.asyncio
async def test_log_groups_resume_by_page_and_do_not_read_log_contents() -> None:
    ad = _Adapter({("census", "describe_log_groups"): [[{"arn": "arn:log:one", "logGroupName": "/a", "kmsKeyId": "arn:kms:key"}], [{"arn": "arn:log:two", "logGroupName": "/b"}]]}, {("call", "list_tags_for_resource"): {"tags": {"app": "x"}}})
    ctx, report = _Ctx(), _Report()
    assert await aws_data.discover(ad, "logs", ctx, _Budget(), report, None, "123", "us-east-1", [])
    assert len(ctx.payloads) == 2
    assert len(report.observations) == 2
    assert not {"filter_log_events", "get_log_events", "start_query"} & set(ad.calls)


@pytest.mark.asyncio
async def test_dynamodb_emits_only_provider_evidenced_kms_relationship() -> None:
    ad = _Adapter({("paginate", "list_tables"): [["t1"]]}, {("call", "describe_table"): {"Table": {"TableName": "t1", "TableArn": "arn:table:t1", "SSEDescription": {"KMSMasterKeyArn": "arn:kms:key"}}}, ("call", "list_tags_of_resource"): {"Tags": []}})
    ctx, report = _Ctx(), _Report()
    assert await aws_data.discover(ad, "dynamodb", ctx, _Budget(), report, None, "123", "us-east-1", [])
    assert report.observations[0]["relationships"] == [{"kind": "encrypted_by", "target": "arn:kms:key"}]


@pytest.mark.parametrize(("service", "operations"), [
    ("secretsmanager", ["ListSecrets", "DescribeSecret"]),
    ("kms", ["ListKeys", "ListAliases", "ListResourceTags", "DescribeKey", "GetKeyRotationStatus"]),
    ("logs", ["DescribeLogGroups", "ListTagsForResource"]),
    ("cloudwatch", ["DescribeAlarms"]),
    ("dynamodb", ["ListTables", "DescribeTable", "ListTagsOfResource"]),
    ("elasticache", ["DescribeCacheClusters", "DescribeReplicationGroups", "ListTagsForResource"]),
    ("efs", ["DescribeFileSystems", "DescribeMountTargets", "DescribeMountTargetSecurityGroups", "ListTagsForResource"]),
    ("opensearch", ["ListDomainNames", "DescribeDomains", "ListTags"]),
])
def test_every_data_family_uses_installed_read_only_api_models(service: str, operations: list[str]) -> None:
    model = get_session().get_service_model(service)
    for operation in operations:
        assert model.operation_model(operation).input_shape is not None


def test_data_inventory_never_contains_secret_values_or_log_data_calls() -> None:
    source = (Path(__file__).parents[2] / "src/local_ops/providers/aws_data.py").read_text(encoding="utf-8").lower()
    for forbidden in ("get_secret_value", "filter_log_events", "get_log_events", "start_query", "decrypt(", "generate_data_key"):
        assert forbidden not in source
