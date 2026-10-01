from __future__ import annotations

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.providers.aws_coverage import build_aws_coverage
from local_ops.providers.base import DiscoveryReport, DiscoveryScope, Observation

ACCOUNT = "123456789012"
OTHER = "210987654321"
R1 = "us-east-1"
R2 = "eu-west-1"


def _config(*providers: ProviderConfig) -> ServerConfig:
    return ServerConfig(providers=list(providers))


def _aws(pid: str, account: str, *, enabled: bool = True, regions: list[str] | None = None) -> ProviderConfig:
    return ProviderConfig(id=pid, kind="aws", enabled=enabled, expected_account_id=account, regions=regions or [R1])


def test_billed_unknown_service_is_explicitly_unsupported() -> None:
    report = DiscoveryReport(
        provider_id="aws-a",
        identity={"account": ACCOUNT},
        observations=[Observation(provider_id="aws-a", resource_key="bill", resource_type="aws/billing_service_cost", identity={"account": ACCOUNT, "service": "Amazon Mystery Fabric"}, attributes={"amount": 2.5})],
    )
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT)), ["aws-a"], DiscoveryScope())
    assert coverage["billing_service_coverage"] == [{"service": "Amazon Mystery Fabric", "account": ACCOUNT, "amount": 2.5, "enumerator_family": None, "status": "unsupported"}]


def test_organization_account_without_provider_is_not_configured() -> None:
    org = Observation(provider_id="aws-a", resource_key="org", resource_type="aws/org_account", identity={"account_id": OTHER, "name": "other"}, scope_key=f"aws-a/{ACCOUNT}/global/organizations")
    report = DiscoveryReport(provider_id="aws-a", identity={"account": ACCOUNT}, observations=[org], completed_scopes=[f"aws-a/{ACCOUNT}/global/organizations"])
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT)), ["aws-a"], DiscoveryScope())
    accounts = {entry["account_id"]: entry for entry in coverage["accounts"]["coverage"]}
    assert coverage["accounts"]["organization_denominator"] == "unknown_or_partial"
    assert accounts[OTHER]["status"] == "not_configured"


def test_account_coverage_distinguishes_disabled_not_requested_and_inaccessible() -> None:
    config = _config(
        _aws("inaccessible", ACCOUNT),
        _aws("not-requested", OTHER),
        _aws("excluded", "333333333333", enabled=False),
    )
    coverage = build_aws_coverage([], config, ["inaccessible"], DiscoveryScope())
    accounts = {entry["account_id"]: entry for entry in coverage["accounts"]["coverage"]}
    assert accounts[ACCOUNT]["status"] == "inaccessible"
    assert accounts[OTHER]["status"] == "not_requested"
    assert accounts["333333333333"]["status"] == "excluded"


def test_cross_region_permission_failure_prevents_complete_coverage() -> None:
    report = DiscoveryReport(
        provider_id="aws-a",
        identity={"account": ACCOUNT},
        completed_scopes=[f"aws-a/{ACCOUNT}/{R1}/lambda"],
        partial_scopes=[f"aws-a/{ACCOUNT}/{R2}/lambda"],
        unavailable=[{"source": f"aws-a/{ACCOUNT}/{R2}/lambda/detail", "reason": "permission_denied", "operation": "list_functions"}],
    )
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT, regions=[R1, R2])), ["aws-a"], DiscoveryScope(families=["lambda"]))
    scopes = {entry["scope_key"]: entry for entry in coverage["family_scopes"]}
    assert scopes[f"aws-a/{ACCOUNT}/{R1}/lambda"]["status"] == "complete"
    assert scopes[f"aws-a/{ACCOUNT}/{R2}/lambda"]["status"] == "unavailable"
    assert coverage["authorization_failures"][0]["source"] == f"aws-a/{ACCOUNT}/{R2}/lambda/detail"


def test_explicit_adapter_coverage_preserves_resumed_suffix_and_cloudwatch_requires_logs() -> None:
    report = DiscoveryReport(
        provider_id="aws-a",
        identity={"account": ACCOUNT},
        aws_coverage={
            "regions_configured": [R1], "regions_requested": [R1], "regions_enabled": [R1], "region_denominator_known": True,
            "family_scopes": [
                {"scope_key": f"aws-a/{ACCOUNT}/{R1}/logs", "account": ACCOUNT, "region": R1, "family": "logs", "status": "partial_resumable", "resumed": True, "checkpoint_available": True},
                {"scope_key": f"aws-a/{ACCOUNT}/{R1}/cloudwatch", "account": ACCOUNT, "region": R1, "family": "cloudwatch", "status": "complete"},
            ],
        },
        observations=[Observation(provider_id="aws-a", resource_key="bill", resource_type="aws/billing_service_cost", identity={"account": ACCOUNT, "service": "AmazonCloudWatch"}, attributes={"amount": 1})],
    )
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT)), ["aws-a"], DiscoveryScope())
    scopes = {entry["family"]: entry for entry in coverage["family_scopes"]}
    assert scopes["logs"]["status"] == "partial_resumable" and scopes["logs"]["checkpoint_available"] is True
    assert coverage["billing_service_coverage"][0]["status"] == "supported_but_not_complete"
    assert "resumed suffix" in coverage["absence_note"]


def test_billing_is_not_complete_when_one_configured_region_is_denied() -> None:
    report = DiscoveryReport(
        provider_id="aws-a", identity={"account": ACCOUNT},
        aws_coverage={"region_denominator_known": True, "regions_not_configured": [], "family_scopes": [
            {"scope_key": f"aws-a/{ACCOUNT}/{R1}/lambda", "account": ACCOUNT, "region": R1, "family": "lambda", "status": "complete"},
            {"scope_key": f"aws-a/{ACCOUNT}/{R2}/lambda", "account": ACCOUNT, "region": R2, "family": "lambda", "status": "unavailable", "reason": "permission_denied"},
        ]},
        observations=[Observation(provider_id="aws-a", resource_key="bill", resource_type="aws/billing_service_cost", identity={"account": ACCOUNT, "service": "AWS Lambda"}, attributes={"amount": 1})],
    )
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT, regions=[R1, R2])), ["aws-a"], DiscoveryScope())
    assert coverage["billing_service_coverage"][0]["status"] == "supported_but_not_complete"


def test_billing_rejects_resumed_suffix_and_omitted_enabled_region() -> None:
    base = {"region_denominator_known": True, "regions_enabled": [R1, R2], "regions_not_configured": []}
    resumed = DiscoveryReport(
        provider_id="aws-a", identity={"account": ACCOUNT},
        aws_coverage={**base, "family_scopes": [{"scope_key": f"aws-a/{ACCOUNT}/{R1}/secretsmanager", "account": ACCOUNT, "region": R1, "family": "secretsmanager", "status": "complete", "resumed": True, "absence_proven": False}]},
        observations=[Observation(provider_id="aws-a", resource_key="bill", resource_type="aws/billing_service_cost", identity={"account": ACCOUNT, "service": "AWS Secrets Manager"}, attributes={"amount": 1})],
    )
    omitted = DiscoveryReport(
        provider_id="aws-b", identity={"account": ACCOUNT},
        aws_coverage={**base, "family_scopes": [{"scope_key": f"aws-b/{ACCOUNT}/{R1}/lambda", "account": ACCOUNT, "region": R1, "family": "lambda", "status": "complete"}]},
        observations=[Observation(provider_id="aws-b", resource_key="bill2", resource_type="aws/billing_service_cost", identity={"account": ACCOUNT, "service": "AWS Lambda"}, attributes={"amount": 1})],
    )
    config = _config(_aws("aws-a", ACCOUNT, regions=[R1, R2]), _aws("aws-b", ACCOUNT, regions=[R1, R2]))
    coverage = build_aws_coverage([resumed, omitted], config, ["aws-a", "aws-b"], DiscoveryScope())
    assert [entry["status"] for entry in coverage["billing_service_coverage"]] == ["supported_but_not_complete", "supported_but_not_complete"]


def test_explicit_scopes_preserve_supplemental_legacy_children_without_regional_sts() -> None:
    report = DiscoveryReport(
        provider_id="aws-a", identity={"account": ACCOUNT},
        aws_coverage={"family_scopes": [
            {"scope_key": f"aws-a/{ACCOUNT}/global/sts", "account": ACCOUNT, "region": "global", "family": "sts", "status": "complete"},
            {"scope_key": f"aws-a/{ACCOUNT}/{R1}/logs", "account": ACCOUNT, "region": R1, "family": "logs", "status": "partial_resumable", "resumed": True},
        ]},
        completed_scopes=[f"aws-a/{ACCOUNT}/{R1}/regions", f"aws-a/{ACCOUNT}/global/iam/access_keys", f"aws-a/{ACCOUNT}/{R1}/logs"],
        partial_scopes=[f"aws-a/{ACCOUNT}/{R1}/logs"],
    )
    coverage = build_aws_coverage([report], _config(_aws("aws-a", ACCOUNT)), ["aws-a"], DiscoveryScope(families=["sts", "logs"]))
    scopes = {entry["scope_key"]: entry for entry in coverage["family_scopes"]}
    assert scopes[f"aws-a/{ACCOUNT}/{R1}/regions"]["status"] == "complete"
    assert scopes[f"aws-a/{ACCOUNT}/global/iam/access_keys"]["status"] == "complete"
    assert scopes[f"aws-a/{ACCOUNT}/{R1}/logs"]["status"] == "partial_resumable"
    assert f"aws-a/{ACCOUNT}/{R1}/sts" not in scopes
