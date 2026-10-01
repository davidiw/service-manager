"""Resume contract tests using the real AWS adapter and its in-process session fake."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from local_ops.config import ServerConfig
from local_ops.models import utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.operations.discovery import DiscoveryScanArgs, run_scan
from local_ops.providers.base import DiscoveryScope
from tests.providers.test_aws import ACCOUNT, R1, FakeClient, adapter, sts_client
from tests.providers.test_aws import ctx as _aws_ctx


@pytest.fixture
async def aws_context(tmp_path: Path) -> AsyncIterator[OperationContext]:
    async for context in _aws_ctx.__wrapped__(tmp_path):  # type: ignore[attr-defined]
        yield context


def _log(name: str) -> dict[str, Any]:
    return {"arn": f"arn:aws:logs:{R1}:{ACCOUNT}:log-group:{name}", "logGroupName": name}


def _secret(name: str) -> dict[str, Any]:
    return {"ARN": f"arn:aws:secretsmanager:{R1}:{ACCOUNT}:secret:{name}", "Name": name}


def _prepare(context: OperationContext, ad: Any, request_id: str) -> None:
    # The checkpoint binding includes the configured provider, principal and verified STS identity.
    context.config = ServerConfig(providers=[ad.config])
    context.providers.register(ad)
    context.request = {"id": request_id, "review_mode": "yolo"}
    context.budget = Budget(deadline=utcnow() + timedelta(seconds=30), max_bytes=1_000_000)


async def test_logs_lowercase_next_token_is_private_and_pages_exhaustively(aws_context: OperationContext) -> None:
    calls = 0

    def pages(kwargs: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if kwargs.get("nextToken") == "lower-token":
            return {"logGroups": [_log("/group-b")]}
        return {"logGroups": [_log("/group-a")], "nextToken": "lower-token"}

    logs = FakeClient("logs", {"describe_log_groups": pages, "list_tags_for_resource": {"tags": {}}})
    ad, _ = adapter({"sts": sts_client(), ("logs", R1): logs}, regions=[R1])
    _prepare(aws_context, ad, "scan-logs")

    await run_scan(aws_context, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["logs"])))
    assert calls == 2
    assert [r["resource_key"] for r in await aws_context.db.observations(provider_id=ad.provider_id)] == [
        _log("/group-a")["arn"], _log("/group-b")["arn"]
    ]
    # Continuation updates are intentionally excluded from provider serialization and results.
    report = await ad.discover(aws_context, DiscoveryScope(families=["logs"]), aws_context.budget)
    assert "checkpoint_updates" not in report.model_dump()
    assert "lower-token" not in str(report.model_dump())


async def test_throttled_secrets_resume_from_checkpoint_without_marking_prior_page_missing(aws_context: OperationContext) -> None:
    first_calls = 0

    def interrupted(kwargs: dict[str, Any]) -> dict[str, Any]:
        nonlocal first_calls
        first_calls += 1
        if kwargs.get("NextToken") == "resume-token":
            from tests.providers.test_aws import client_error

            return client_error("ThrottlingException", "ListSecrets")
        return {"SecretList": [_secret("first")], "NextToken": "resume-token"}

    secrets = FakeClient("secretsmanager", {"list_secrets": interrupted, "describe_secret": lambda kwargs: {**_secret(str(kwargs["SecretId"]).rsplit(":", 1)[-1])}})
    ad, _ = adapter({"sts": sts_client(), ("secretsmanager", R1): secrets}, regions=[R1])
    _prepare(aws_context, ad, "scan-secrets-first")
    first = await run_scan(aws_context, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["secretsmanager"])))
    assert first.coverage and first.coverage.truncated
    assert first_calls >= 2  # throttling retries may be attempted within the discovery budget
    rows = await aws_context.db.observations(provider_id=ad.provider_id)
    assert len(rows) == 1 and rows[0]["missing_since"] is None

    def resumed(kwargs: dict[str, Any]) -> dict[str, Any]:
        assert kwargs.get("NextToken") == "resume-token"
        return {"SecretList": [_secret("bravo")]}

    secrets.ops["list_secrets"] = resumed
    aws_context.request = {"id": "scan-secrets-resumed", "review_mode": "yolo"}
    second = await run_scan(aws_context, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["secretsmanager"])))
    assert second.coverage and not second.coverage.truncated
    rows = await aws_context.db.observations(provider_id=ad.provider_id)
    assert {r["resource_key"] for r in rows} == {_secret("first")["ARN"], _secret("bravo")["ARN"]}
    assert all(r["missing_since"] is None for r in rows)


async def test_cancelled_scan_persists_only_the_completed_page_checkpoint(aws_context: OperationContext) -> None:
    def cancel_after_page(kwargs: dict[str, Any]) -> dict[str, Any]:
        if kwargs.get("NextToken"):
            raise AssertionError("cancellation must stop before fetching the next page")
        return {"SecretList": [_secret("alpha")], "NextToken": "cancel-token"}

    def detail(kwargs: dict[str, Any]) -> dict[str, Any]:
        aws_context.cancel_event.set()
        return _secret("alpha")

    secrets = FakeClient("secretsmanager", {"list_secrets": cancel_after_page, "describe_secret": detail})
    ad, _ = adapter({"sts": sts_client(), ("secretsmanager", R1): secrets}, regions=[R1])
    _prepare(aws_context, ad, "scan-cancelled")
    outcome = await run_scan(aws_context, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["secretsmanager"])))
    assert outcome.coverage and outcome.coverage.truncated
    assert len(await aws_context.db.observations(provider_id=ad.provider_id)) == 1
    checkpoint = await aws_context.db.fetchone("SELECT cursor,version FROM discovery_checkpoints")
    assert checkpoint and checkpoint["version"] == 0 and "cancel-token" in checkpoint["cursor"]
