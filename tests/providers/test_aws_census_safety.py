from __future__ import annotations

from local_ops.config import ServerConfig
from local_ops.operations.base import OperationContext
from local_ops.operations.discovery import DiscoveryScanArgs, run_scan
from local_ops.providers.base import DiscoveryScope
from tests.providers.test_aws import (  # noqa: F401
    ACCOUNT,
    R1,
    FakeClient,
    adapter,
    ctx,
    stored_evidence_text,
    sts_client,
)


async def test_ecs_task_definition_evidence_is_allowlisted(ctx: OperationContext) -> None:  # noqa: F811
    # The canaries intentionally do not resemble credential patterns, so sanitizer matching cannot mask
    # an unsafe raw response.
    canary = "plain-text-canary-should-never-persist"
    task = {"taskDefinitionArn": f"arn:aws:ecs:{R1}:{ACCOUNT}:task-definition/app:1", "family": "app", "revision": 1, "status": "ACTIVE", "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/task", "executionRoleArn": f"arn:aws:iam::{ACCOUNT}:role/exec", "containerDefinitions": [{"name": "app", "image": "repo/app:1", "command": [canary], "entryPoint": [canary], "environment": [{"name": "X", "value": canary}], "logConfiguration": {"options": {"awslogs-group": "/aws/ecs/app", "unsafe": canary}}, "secrets": [{"name": "TOKEN", "valueFrom": "arn:aws:secretsmanager:x"}]}]}
    clients = {"sts": sts_client(), ("ecs", R1): FakeClient("ecs", {"describe_services": {"services": [{"serviceArn": f"arn:aws:ecs:{R1}:{ACCOUNT}:service/c/s", "serviceName": "s", "clusterArn": f"arn:aws:ecs:{R1}:{ACCOUNT}:cluster/c", "taskDefinition": task["taskDefinitionArn"]}]}, "describe_task_definition": {"taskDefinition": task}}, {"list_clusters": [{"clusterArns": [f"arn:aws:ecs:{R1}:{ACCOUNT}:cluster/c"]}], "list_services": [{"serviceArns": ["s"]}]}),}
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["ecs"]), ctx.budget)
    assert canary not in await stored_evidence_text(ctx)
    td = next(o for o in report.observations if o.resource_type == "aws/ecs_task_definition")
    assert {r["target"] for r in td.relationships} >= {task["taskRoleArn"], task["executionRoleArn"], "repo/app:1", "/aws/ecs/app"}


async def test_filtered_backup_scan_never_marks_excluded_vault_missing(ctx: OperationContext) -> None:  # noqa: F811
    backup = FakeClient("backup", pages={
        "list_backup_vaults": [{"BackupVaultList": [{"BackupVaultArn": f"arn:backup:{name}", "BackupVaultName": name} for name in ["a", "b"]]}],
        "list_recovery_points_by_backup_vault": [{"RecoveryPoints": []}],
    })
    ad, _ = adapter({"sts": sts_client(), "backup": backup}, regions=[R1], families=["backup"])
    ctx.config = ServerConfig(providers=[ad.config])
    ctx.providers.register(ad)
    await run_scan(ctx, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["backup"])))
    ctx.request = {"id": "filtered-backup", "review_mode": "yolo"}
    result = await run_scan(ctx, DiscoveryScanArgs(providers=[ad.provider_id], scope=DiscoveryScope(families=["backup"], vaults=["a"])))
    assert result.coverage and f"aws-prod/{ACCOUNT}/{R1}/backup" not in result.coverage.completed_scopes
    rows = await ctx.db.observations(provider_id=ad.provider_id)
    assert {row["resource_key"] for row in rows} == {"arn:backup:a", "arn:backup:b"}
    assert all(row["missing_since"] is None for row in rows)
