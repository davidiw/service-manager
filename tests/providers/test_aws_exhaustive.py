"""Guard removed first-N child bounds as well as the shared paginator limit."""
from __future__ import annotations

from typing import Any

import pytest

from local_ops.providers.base import DiscoveryScope
from tests.providers.test_aws import ACCOUNT, R1, FakeClient, adapter, ctx, sts_client  # noqa: F401


@pytest.mark.parametrize("family", ["elb", "backup", "acm", "ecr"])
async def test_inventory_and_children_exceed_former_sampling_bounds(ctx: Any, family: str) -> None:  # noqa: F811
    if family == "elb":
        client = FakeClient("elbv2", pages={
            "describe_load_balancers": [{"LoadBalancers": [{"LoadBalancerArn": f"arn:lb:{i}"} for i in range(51)]}],
            "describe_target_groups": [{"TargetGroups": []}],
            "describe_listeners": [{"Listeners": [{"Port": n, "Protocol": "HTTP"}]} for n in range(6)],
        })
        rtype, count, child_field, child_count = "aws/load_balancer", 51, "listeners", 6
    elif family == "backup":
        client = FakeClient("backup", pages={
            "list_backup_vaults": [{"BackupVaultList": [{"BackupVaultArn": f"arn:vault:{i}", "BackupVaultName": str(i)} for i in range(51)]}],
            "list_recovery_points_by_backup_vault": [{"RecoveryPoints": [{"RecoveryPointArn": f"arn:point:{n}"}]} for n in range(3)],
        })
        rtype, count, child_field, child_count = "aws/backup_vault", 51, "recent_recovery_points", 3
    elif family == "acm":
        client = FakeClient("acm", {"describe_certificate": lambda args: {"Certificate": {"CertificateArn": args["CertificateArn"]}}}, {
            "list_certificates": [{"CertificateSummaryList": [{"CertificateArn": f"arn:cert:{n}"}]} for n in range(101)],
        })
        rtype, count, child_field, child_count = "aws/acm_certificate", 101, "", 0
    else:
        client = FakeClient("ecr", pages={
            "describe_repositories": [{"repositories": [{"repositoryArn": f"arn:repo:{i}", "repositoryName": str(i)}]} for i in range(51)],
            "describe_images": [{"imageDetails": [{"imageDigest": f"sha256:{n:064x}"}]} for n in range(51)],
        })
        rtype, count, child_field, child_count = "aws/ecr_image", 51 * 51, "", 0
    ad, _ = adapter({"sts": sts_client(), client.service: client}, regions=[R1], families=[family])
    report = await ad.discover(ctx, DiscoveryScope(families=[family]), ctx.budget)
    assert not report.unavailable, report.unavailable
    assert f"aws-prod/{ACCOUNT}/{R1}/{family}" in report.completed_scopes
    resources = [o for o in report.observations if o.resource_type == rtype]
    assert len(resources) == count
    if child_field:
        assert all(len(o.attributes[child_field]) == child_count for o in resources)
