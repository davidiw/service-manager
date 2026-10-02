"""AWS adapter tests over a stubbed aiobotocore session. Nothing here touches the network: every client is
an in-process fake, and botocore exceptions are constructed directly to simulate denied/expired credentials."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
from botocore import xform_name
from botocore.exceptions import ClientError, SSOTokenLoadError, UnauthorizedSSOTokenError
from botocore.session import get_session

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import ErrorCode, OpsError, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.aws import AwsAdapter, classify_boto_error
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.release import Sanitizer
from local_ops.storage import Database

ACCOUNT = "123456789012"
R1, R2 = "us-east-1", "eu-west-1"
FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"


def client_error(code: str, op: str, message: str = "denied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, op)


class FakePaginator:
    def __init__(self, pages: Any):
        self.pages = pages

    def paginate(self, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        pages = self.pages(kwargs) if callable(self.pages) else self.pages

        async def gen() -> AsyncIterator[dict[str, Any]]:
            if isinstance(pages, BaseException):
                raise pages
            for p in pages:
                yield p

        return gen()


@lru_cache
def _paginator_operations(service: str) -> set[str]:
    model = get_session().get_paginator_model(service)
    return {xform_name(name) for name in model._paginator_config}


class FakeClient:
    """ops maps a boto method name to a dict (returned), an exception (raised) or a callable(kwargs)."""

    def __init__(self, service: str, ops: dict[str, Any] | None = None, pages: dict[str, Any] | None = None):
        self.service = service
        self.ops = ops or {}
        self.pages = pages or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_paginator(self, op: str) -> FakePaginator:
        self.calls.append((f"paginate:{op}", {}))
        if op not in _paginator_operations(self.service):
            raise AssertionError(f"{self.service}:{op} has no botocore paginator")
        if op not in self.pages:
            raise AssertionError(f"{self.service}: no fake pages for {op}")
        return FakePaginator(self.pages[op])

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_") or name not in self.ops:
            raise AttributeError(f"{self.service}: no fake op {name}")
        spec = self.ops[name]

        async def method(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            if isinstance(spec, BaseException):
                raise spec
            if callable(spec):
                out = spec(kwargs)
                if hasattr(out, "__await__"):
                    out = await out
                if isinstance(out, BaseException):
                    raise out
                return out
            return spec

        return method


class _Ctx:
    def __init__(self, client: FakeClient):
        self.client = client

    async def __aenter__(self) -> FakeClient:
        return self.client

    async def __aexit__(self, *exc: Any) -> None:
        return None


class FakeSession:
    def __init__(self, clients: dict[Any, FakeClient]):
        self.clients = clients
        self.created: list[tuple[str, str | None]] = []

    def create_client(self, service: str, region_name: str | None = None, **kw: Any) -> _Ctx:
        self.created.append((service, region_name))
        c = self.clients.get((service, region_name)) or self.clients.get(service)
        if c is None:
            raise AssertionError(f"no fake client for {service} in {region_name}")
        return _Ctx(c)


def sts_client(account: str = ACCOUNT, role: str = "ops") -> FakeClient:
    return FakeClient("sts", {"get_caller_identity": {"Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/{role}/x", "UserId": "AROA123:x"}})


def empty_regional(region: str) -> dict[Any, FakeClient]:
    """Every regional family returning nothing, so a region completes cleanly."""
    return {
        ("eks", region): FakeClient("eks", {"describe_cluster": {"cluster": {}}}, {"list_clusters": [{"clusters": []}]}),
        ("ec2", region): FakeClient("ec2", {"describe_regions": {"Regions": [{"RegionName": R1}, {"RegionName": R2}]}}, {"describe_instances": [{"Reservations": []}], "describe_volumes": [{"Volumes": []}], "describe_vpcs": [{"Vpcs": []}], "describe_subnets": [{"Subnets": []}], "describe_security_groups": [{"SecurityGroups": []}], "describe_nat_gateways": [{"NatGateways": []}]}),
        ("elbv2", region): FakeClient("elbv2", {}, {"describe_load_balancers": [{"LoadBalancers": []}], "describe_target_groups": [{"TargetGroups": []}]}),
        ("rds", region): FakeClient("rds", {}, {"describe_db_instances": [{"DBInstances": []}], "describe_db_clusters": [{"DBClusters": []}]}),
        ("ecr", region): FakeClient("ecr", {}, {"describe_repositories": [{"repositories": []}]}),
        ("backup", region): FakeClient("backup", {}, {"list_backup_vaults": [{"BackupVaultList": []}]}),
        ("acm", region): FakeClient("acm", {}, {"list_certificates": [{"CertificateSummaryList": []}]}),
        ("lambda", region): FakeClient("lambda", {}, {"list_functions": [{"Functions": []}]}),
        ("ecs", region): FakeClient("ecs", {}, {"list_clusters": [{"clusterArns": []}]}),
        ("events", region): FakeClient("events", {"list_event_buses": {"EventBuses": []}}, {"list_rules": [{"Rules": []}]}),
        ("autoscaling", region): FakeClient("autoscaling", {}, {"describe_auto_scaling_groups": [{"AutoScalingGroups": []}]}),
        ("sso-admin", region): FakeClient("sso-admin", {}, {"list_instances": [{"Instances": []}]}),
    }


# IAM calls added for policy-reference inventory (groups, instance profiles, attached/inline policy
# names); most IAM-focused tests only exercise access keys or the account summary and need these to
# return empty so the fake client does not reject an unexpected operation.
IAM_EMPTY_POLICY_PAGES: dict[str, Any] = {
    "list_groups": [{"Groups": []}],
    "list_instance_profiles": [{"InstanceProfiles": []}],
    "list_attached_user_policies": [{"AttachedPolicies": []}],
    "list_user_policies": [{"PolicyNames": []}],
    "list_attached_role_policies": [{"AttachedPolicies": []}],
    "list_role_policies": [{"PolicyNames": []}],
}


def empty_global() -> dict[Any, FakeClient]:
    return {
        "s3": FakeClient("s3", {}, {"list_buckets": [{"Buckets": []}]}),
        "route53": FakeClient("route53", {}, {"list_hosted_zones": [{"HostedZones": []}]}),
        "iam": FakeClient("iam", {"get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}, {"list_users": [{"Users": []}], "list_roles": [{"Roles": []}]}),
        "ce": FakeClient("ce", {"get_cost_and_usage": {"ResultsByTime": [{"Groups": [{"Keys": ["Amazon Elastic Compute Cloud - Compute"], "Metrics": {"UnblendedCost": {"Amount": "12.5", "Unit": "USD"}}}]}]}}),
    }


def make_config(**over: Any) -> ProviderConfig:
    base: dict[str, Any] = {"id": "aws-prod", "kind": "aws", "regions": [R1, R2], "expected_account_id": ACCOUNT, "credential": None}
    base.update(over)
    return ProviderConfig.model_validate(base)


def adapter(clients: dict[Any, FakeClient], **over: Any) -> tuple[AwsAdapter, FakeSession]:
    session = FakeSession(clients)
    return AwsAdapter(make_config(**over), ServerConfig(), None, session_factory=lambda: session), session


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[OperationContext]:
    db = Database(tmp_path / "state" / "db.sqlite", tmp_path / "state" / "evidence")
    await db.open()
    cat = tmp_path / "catalog"
    (cat / "services").mkdir(parents=True)
    (cat / "catalog.yaml").write_text("name: t\n", encoding="utf-8")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    c = OperationContext(db=db, config=ServerConfig(), catalog=load_catalog(cat), providers=ProviderRegistry(), sanitizer=Sanitizer(), principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)
    yield c
    await db.close()


async def stored_evidence_text(ctx: OperationContext) -> str:
    out = []
    for eid in ctx.evidence_ids:
        rec = await ctx.db.evidence(eid)
        assert rec is not None
        out.append(ctx.db.evidence_bytes(rec).decode("utf-8"))
    return "\n".join(out)


# ---------------------------------------------------------------- availability


async def test_account_mismatch_rejected() -> None:
    ad, _ = adapter({"sts": sts_client("999999999999")})
    av = await ad.check_availability(live=True)
    assert av.available is False
    assert av.reason == "account_mismatch"
    assert av.checked_live is True
    assert "999999999999" not in (av.detail or "")  # the live account id stays in private detail


async def test_expired_sso_is_auth_required() -> None:
    ad, _ = adapter({"sts": FakeClient("sts", {"get_caller_identity": UnauthorizedSSOTokenError()})})
    av = await ad.check_availability(live=True)
    assert av.available is False
    assert av.reason == "auth_required"
    ad2, _ = adapter({"sts": FakeClient("sts", {"get_caller_identity": client_error("ExpiredToken", "GetCallerIdentity")})})
    av2 = await ad2.check_availability(live=True)
    assert (av2.available, av2.reason) == (False, "auth_required")
    assert "re-authenticate" in (av2.detail or "")


async def test_signature_expiry_is_clock_skew_but_generic_signature_mismatch_is_not() -> None:
    expired = client_error("SignatureDoesNotMatch", "GetCallerIdentity", "Signature expired: 20261002T000000Z is now earlier than 20261002T000500Z")
    generic = client_error("SignatureDoesNotMatch", "GetCallerIdentity", "The request signature we calculated does not match the signature you provided")
    assert classify_boto_error(expired)[0] == "clock_skew"
    assert "synchronize this host's clock" in classify_boto_error(expired)[1]
    assert classify_boto_error(generic)[0] == "auth_required"
    assert classify_boto_error(client_error("InvalidSignatureException", "GetCallerIdentity", "invalid signature"))[0] == "auth_required"
    assert classify_boto_error(client_error("RequestTimeTooSkewed", "GetCallerIdentity", "request time too skewed"))[0] == "clock_skew"


async def test_missing_sso_token_fails_identity_once_with_configured_session_name() -> None:
    client = FakeClient("sts", {"get_caller_identity": SSOTokenLoadError(error_msg="token cache entry missing")})
    session = FakeSession({"sts": client})
    session.get_scoped_config = lambda: {"sso_session": "moveindustries-sso"}  # type: ignore[attr-defined]
    server = ServerConfig(credentials=[CredentialRef(id="sso", kind="aws_sso", profile="moveindustries")])
    ad = AwsAdapter(make_config(credential="sso"), server, None, session_factory=lambda: session)
    av = await ad.check_availability(live=True)
    assert (av.available, av.reason, av.checked_live) == (False, "auth_required", True)
    assert "moveindustries-sso" in (av.detail or "")
    assert "token cache entry missing" not in (av.detail or "")
    assert [call for call, _ in client.calls] == ["get_caller_identity"]


async def test_sso_error_while_entering_sts_client_is_safe_auth_required() -> None:
    class BrokenContext:
        async def __aenter__(self) -> FakeClient:
            raise SSOTokenLoadError(error_msg="token cache entry missing")

        async def __aexit__(self, *exc: Any) -> None:
            return None

    session = FakeSession({})
    session.get_scoped_config = lambda: {"sso_session": "moveindustries-sso"}  # type: ignore[attr-defined]
    session.create_client = lambda *args, **kwargs: BrokenContext()  # type: ignore[method-assign]
    server = ServerConfig(credentials=[CredentialRef(id="sso", kind="aws_sso", profile="moveindustries")])
    ad = AwsAdapter(make_config(credential="sso"), server, None, session_factory=lambda: session)
    av = await ad.check_availability(live=True)
    assert (av.available, av.reason) == (False, "auth_required")
    assert "moveindustries-sso" in (av.detail or "")
    assert "token cache entry missing" not in (av.detail or "")


async def test_sso_credential_preflight_stops_before_sts_client_creation() -> None:
    class ExpiredCredentials:
        async def get_frozen_credentials(self) -> None:
            raise SSOTokenLoadError(error_msg="token cache entry missing")

    class PreflightSession(FakeSession):
        async def get_credentials(self) -> ExpiredCredentials:
            return ExpiredCredentials()

    session = PreflightSession({"sts": sts_client()})
    session.get_scoped_config = lambda: {"sso_session": "moveindustries-sso"}  # type: ignore[attr-defined]
    server = ServerConfig(credentials=[CredentialRef(id="sso", kind="aws_sso", profile="moveindustries")])
    ad = AwsAdapter(make_config(credential="sso"), server, None, session_factory=lambda: session)
    av = await ad.check_availability(live=True)
    assert (av.available, av.reason) == (False, "auth_required")
    assert session.created == []


async def test_sso_preflight_logs_one_safe_line_without_traceback(caplog: pytest.LogCaptureFixture) -> None:
    from aiobotocore.credentials import AioDeferredRefreshableCredentials

    async def missing_token() -> dict[str, Any]:
        raise SSOTokenLoadError(error_msg="sensitive cache path /home/operator/.aws/sso/cache/token.json")

    class PreflightSession(FakeSession):
        async def get_credentials(self) -> AioDeferredRefreshableCredentials:
            return AioDeferredRefreshableCredentials(refresh_using=missing_token, method="sso")

    session = PreflightSession({"sts": sts_client()})
    session.get_scoped_config = lambda: {"sso_session": "moveindustries-sso"}  # type: ignore[attr-defined]
    server = ServerConfig(credentials=[CredentialRef(id="sso", kind="aws_sso", profile="moveindustries")])
    ad = AwsAdapter(make_config(credential="sso"), server, None, session_factory=lambda: session)
    caplog.set_level(logging.WARNING, logger="aiobotocore.credentials")
    av = await ad.check_availability(live=True)
    records = [r for r in caplog.records if r.name == "aiobotocore.credentials"]
    assert (av.available, av.reason) == (False, "auth_required")
    assert session.created == []
    assert len(records) == 1
    assert records[0].getMessage() == "AWS SSO session 'moveindustries-sso' is not authenticated; run aws sso login for that session and retry."
    assert records[0].exc_info is None and records[0].exc_text is None
    assert "sensitive cache path" not in caplog.text
    try:
        raise SSOTokenLoadError(error_msg="unrelated token error")
    except SSOTokenLoadError:
        logging.getLogger("aiobotocore.credentials").warning("unrelated credential failure", exc_info=True)
    outside_scope = [r for r in caplog.records if r.name == "aiobotocore.credentials"][-1]
    assert outside_scope.getMessage() == "unrelated credential failure"
    assert outside_scope.exc_info is not None


async def test_expected_role_refuses_mismatch_before_discovery(ctx: OperationContext) -> None:
    ad, session = adapter({"sts": sts_client(role="AdministratorAccess")}, expected_role="AWSReservedSSO_ViewOnlyAccess_*")
    av = await ad.check_availability(live=True)
    assert (av.available, av.reason) == (False, "role_mismatch")
    assert "AdministratorAccess" not in (av.detail or "")
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == []
    assert report.unavailable[0]["reason"] == "role_mismatch"
    assert session.created == [("sts", R1), ("sts", R1)]


async def test_expected_role_accepts_exact_and_glob() -> None:
    exact, _ = adapter({"sts": sts_client(role="ReadOnly")}, expected_role="ReadOnly")
    glob, _ = adapter({"sts": sts_client(role="AWSReservedSSO_ViewOnlyAccess_abcd")}, expected_role="AWSReservedSSO_ViewOnlyAccess_*")
    assert (await exact.check_availability(live=True)).available is True
    assert (await glob.check_availability(live=True)).available is True


def test_expected_role_config_validation() -> None:
    with pytest.raises(ValueError, match="expected_role"):
        ProviderConfig(id="aws", kind="aws", expected_role=" ")
    with pytest.raises(ValueError, match="expected_role"):
        ProviderConfig(id="not-aws", kind="demo", expected_role="role")


async def test_non_live_check_and_classification() -> None:
    ad, _ = adapter({"sts": sts_client()})
    av = await ad.check_availability(live=False)
    assert av.available is True and av.reason == "configured_not_live_checked" and av.checked_live is False
    assert classify_boto_error(client_error("AccessDenied", "ListClusters"))[0] == "permission_denied"
    assert classify_boto_error(client_error("InvalidClientTokenId", "GetCallerIdentity"))[0] == "auth_required"
    assert classify_boto_error(client_error("OptInRequired", "DescribeInstances"))[0] == "region_not_enabled"
    assert classify_boto_error(client_error("ResourceNotFoundException", "DescribeCluster"))[0] == "not_found"
    live = await ad.check_availability(live=True)
    assert live.available and live.identity and live.identity["account"] == ACCOUNT
    assert ad.describe().live_verified is True


async def test_query_with_bad_credentials_raises_auth_required(ctx: OperationContext) -> None:
    ad, _ = adapter({"sts": FakeClient("sts", {"get_caller_identity": client_error("ExpiredToken", "GetCallerIdentity")})})
    with pytest.raises(OpsError) as ei:
        await ad.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert ei.value.code == ErrorCode.AUTH_REQUIRED


# ---------------------------------------------------------------- discovery


async def test_discovery_two_regions_one_permission_denied(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1), **empty_regional(R2), **empty_global()}
    cluster = {"name": "prod", "arn": f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/prod", "version": "1.31", "endpoint": "https://x.eks.amazonaws.com", "createdAt": datetime(2025, 1, 1, tzinfo=UTC), "logging": {"clusterLogging": [{"types": ["api", "authenticator"], "enabled": True}, {"types": ["audit", "controllerManager", "scheduler"], "enabled": False}]}}
    clients[("eks", R1)] = FakeClient("eks", {"describe_cluster": {"cluster": cluster}}, {"list_clusters": [{"clusters": ["prod"]}]})
    clients[("ec2", R1)] = FakeClient("ec2", {"describe_regions": {"Regions": [{"RegionName": R1}, {"RegionName": R2}]}}, {"describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "m6i.large", "State": {"Name": "running"}, "Tags": [{"Key": "eks:cluster-name", "Value": "prod"}, {"Key": "Name", "Value": "node"}], "PrivateIpAddress": "10.0.0.1", "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/node"}}]}]}], "describe_volumes": [{"Volumes": [{"VolumeId": "vol-1", "Size": 100, "Attachments": [{}]}]}]})
    clients[("ec2", R1)].pages.update({"describe_vpcs": [{"Vpcs": []}], "describe_subnets": [{"Subnets": []}], "describe_security_groups": [{"SecurityGroups": []}], "describe_nat_gateways": [{"NatGateways": []}]})
    clients[("eks", R2)] = FakeClient("eks", {}, {"list_clusters": client_error("AccessDeniedException", "ListClusters")})
    ad, _ = adapter(clients)
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.identity and report.identity["account"] == ACCOUNT
    assert f"aws-prod/{ACCOUNT}/{R1}/eks" in report.completed_scopes
    assert f"aws-prod/{ACCOUNT}/{R2}/eks" in report.partial_scopes and f"aws-prod/{ACCOUNT}/{R2}/eks" not in report.completed_scopes
    denied = [u for u in report.unavailable if u["reason"] == "permission_denied"]
    assert denied and denied[0]["source"] == f"aws-prod/{ACCOUNT}/{R2}/eks" and denied[0]["operation"] == "list_clusters"
    # the other region's other families still completed
    assert f"aws-prod/{ACCOUNT}/{R2}/ec2" in report.completed_scopes
    eks = [o for o in report.observations if o.resource_type == "aws/eks_cluster"]
    assert len(eks) == 1 and eks[0].resource_key == cluster["arn"]
    assert eks[0].attributes["logging"] == {"api": True, "audit": False, "authenticator": True, "controllerManager": False, "scheduler": False}
    assert eks[0].attributes["created_at"] == "2025-01-01T00:00:00Z"
    inst = next(o for o in report.observations if o.resource_type == "aws/ec2_instance")
    assert inst.identity == {"account": ACCOUNT, "region": R1, "arn": f"arn:aws:ec2:{R1}:{ACCOUNT}:instance/i-1", "instance_id": "i-1"}
    assert {"kind": "member_of", "target": cluster["arn"]} in inst.relationships
    assert inst.evidence_id in ctx.evidence_ids
    vol = next(o for o in report.observations if o.resource_type == "aws/ebs_volume_summary")
    assert vol.attributes["count"] == 1
    bill = [o for o in report.observations if o.resource_type == "aws/billing_service_cost"]
    assert bill and bill[0].attributes["amount"] == 12.5 and "not a resource inventory" in bill[0].attributes["note"]
    assert f"aws-prod/{ACCOUNT}/global/billing" in report.completed_scopes
    assert not any(o.resource_type == "aws/org_account" for o in report.observations)


async def test_region_not_enabled_and_acm_expiry(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1), **empty_global()}
    clients[("ec2", R1)].ops["describe_regions"] = {"Regions": [{"RegionName": R1}]}
    not_after = datetime(2026, 11, 15, tzinfo=UTC)
    clients[("acm", R1)] = FakeClient("acm", {"describe_certificate": {"Certificate": {"CertificateArn": f"arn:aws:acm:{R1}:{ACCOUNT}:certificate/c1", "DomainName": "api.example.com", "NotAfter": not_after, "Status": "ISSUED", "InUseBy": [f"arn:aws:elasticloadbalancing:{R1}:{ACCOUNT}:loadbalancer/app/x/1"]}}}, {"list_certificates": [{"CertificateSummaryList": [{"CertificateArn": f"arn:aws:acm:{R1}:{ACCOUNT}:certificate/c1"}]}]})
    ad, session = adapter(clients)
    report = await ad.discover(ctx, DiscoveryScope(families=["regions", "acm", "s3"]), ctx.budget)
    assert {"source": f"aws-prod/{ACCOUNT}/{R2}", "reason": "region_not_enabled"}.items() <= next(u for u in report.unavailable if u["reason"] == "region_not_enabled").items()
    assert not any(r == R2 for _, r in session.created)  # the disabled region was never contacted
    assert report.expiries == [{"resource_key": f"arn:aws:acm:{R1}:{ACCOUNT}:certificate/c1", "kind": "certificate", "expires_at": "2026-11-15T00:00:00Z", "domain": "api.example.com", "status": "ISSUED", "region": R1}]
    cert = next(o for o in report.observations if o.resource_type == "aws/acm_certificate")
    assert cert.attributes["not_after"] == "2026-11-15T00:00:00Z"
    assert f"aws-prod/{ACCOUNT}/{R1}/acm" in report.completed_scopes and f"aws-prod/{ACCOUNT}/{R1}/s3" in report.completed_scopes
    # families outside the requested set were never touched
    assert not any(s == "eks" for s, _ in session.created)


async def test_pagination_exhausts_all_pages(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    pages = [{"Functions": [{"FunctionName": f"f{i}", "FunctionArn": f"arn:aws:lambda:{R1}:{ACCOUNT}:function:f{i}"}]} for i in range(60)]
    clients[("lambda", R1)] = FakeClient("lambda", {}, {"list_functions": pages})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["lambda", "rds"]), ctx.budget)
    assert f"aws-prod/{ACCOUNT}/{R1}/lambda" in report.completed_scopes
    assert f"aws-prod/{ACCOUNT}/{R1}/rds" in report.completed_scopes
    assert report.truncated is False
    assert len([o for o in report.observations if o.resource_type == "aws/lambda_function"]) == 60
    # evidence stores at most 200 items per fragment and records the real count
    rec = await ctx.db.evidence(ctx.evidence_ids[-1])  # lambda runs after rds in family order
    assert rec is not None
    body = json.loads(ctx.db.evidence_bytes(rec))
    assert body["functions_count"] == 60 and len(body["functions"]) == 60


async def test_budget_exhaustion_stops_discovery_with_partial_scope(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1), **empty_global()}
    ad, _ = adapter(clients, regions=[R1])
    budget = Budget(deadline=utcnow() - timedelta(seconds=1), max_bytes=1_000_000)
    report = await ad.discover(ctx, DiscoveryScope(families=["eks", "ec2"]), budget)
    assert report.truncated is True
    assert report.partial_scopes == ["aws-prod/identity"]
    assert any(u["reason"] == "budget_exhausted" and u["source"] == "aws-prod" for u in report.unavailable)
    assert report.completed_scopes == []


async def test_discovery_with_account_mismatch_reads_nothing(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client("999999999999"), **empty_regional(R1)}
    ad, session = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == [] and report.unavailable[0]["reason"] == "account_mismatch"
    assert session.created == [("sts", R1)]


async def test_iam_access_keys_are_hashed_and_evidence_scrubbed(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_access_key_last_used": {"AccessKeyLastUsed": {"LastUsedDate": datetime(2026, 9, 1, tzinfo=UTC), "ServiceName": "s3", "Region": R1}}, "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 0}}}, {"list_users": [{"Users": [{"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "UserId": "AIDA1", "PasswordLastUsed": datetime(2026, 9, 30, tzinfo=UTC), "Tags": [{"Key": "secret_access_key_note", "Value": f"leaked {FAKE_KEY}"}]}]}], "list_roles": [{"Roles": [{"RoleName": "admin", "Arn": f"arn:aws:iam::{ACCOUNT}:role/admin", "AssumeRolePolicyDocument": {"Statement": []}}]}], "list_access_keys": [{"AccessKeyMetadata": [{"AccessKeyId": FAKE_KEY, "Status": "Active", "CreateDate": datetime(2024, 1, 1, tzinfo=UTC)}]}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    key_obs = [o for o in report.observations if o.resource_type == "aws/iam_access_key"]
    assert len(key_obs) == 1 and key_obs[0].identity["access_key_suffix"] == "MPLE"
    assert FAKE_KEY not in json.dumps([o.model_dump() for o in report.observations])
    user = next(o for o in report.observations if o.resource_type == "aws/iam_user")
    assert user.attributes["password_last_used"] == "2026-09-30T00:00:00Z" and user.attributes["access_keys"][0]["last_used_service"] == "s3"
    text = await stored_evidence_text(ctx)
    assert "AKIA" not in text
    assert "REDACTED" in text
    # evidence directory files on disk are scrubbed too
    for p in (ctx.db.evidence_dir).rglob("*"):
        if p.is_file():
            assert "AKIA" not in p.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- scope-key completeness regressions


def _dump(report: Any) -> list[dict[str, Any]]:
    out = []
    for o in report.observations:
        d = o.model_dump()
        d.update(match_service_id=None, match_binding_id=None, match_basis=None, match_confidence=None)
        out.append(d)
    return out


async def _persist_and_mark_missing(ctx: OperationContext, report: Any) -> int:
    """Mirror operations/discovery.run_scan's persistence + missing-marking, without the catalog."""
    await ctx.db.upsert_observations(ctx.request_id, _dump(report))
    marked = 0
    for scope_key in report.completed_scopes:
        seen = {o.resource_key for o in report.observations if o.scope_key == scope_key}
        marked += await ctx.db.mark_missing(report.provider_id, scope_key, seen)
    return marked


async def test_filtered_ecr_scan_does_not_mark_other_repos_missing(ctx: OperationContext) -> None:
    repos = [{"repositoryName": "repo-a", "repositoryArn": f"arn:aws:ecr:{R1}:{ACCOUNT}:repository/repo-a"}, {"repositoryName": "repo-b", "repositoryArn": f"arn:aws:ecr:{R1}:{ACCOUNT}:repository/repo-b"}]
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    clients[("ecr", R1)] = FakeClient("ecr", {}, {"describe_repositories": [{"repositories": repos}], "describe_images": [{"imageDetails": []}]})
    ad, _ = adapter(clients, regions=[R1])
    report1 = await ad.discover(ctx, DiscoveryScope(families=["ecr"]), ctx.budget)
    ecr_key = f"aws-prod/{ACCOUNT}/{R1}/ecr"
    assert ecr_key in report1.completed_scopes
    assert await _persist_and_mark_missing(ctx, report1) == 0  # first scan: nothing pre-existing to mark

    # second scan filtered to repo-a only: must not claim the account/region-wide scope as complete
    clients2: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    clients2[("ecr", R1)] = FakeClient("ecr", {}, {"describe_repositories": [{"repositories": [repos[0]]}], "describe_images": [{"imageDetails": []}]})
    ad2, _ = adapter(clients2, regions=[R1])
    report2 = await ad2.discover(ctx, DiscoveryScope(families=["ecr"], repositories=["repo-a"]), ctx.budget)
    assert ecr_key not in report2.completed_scopes and ecr_key in report2.partial_scopes
    marked = await _persist_and_mark_missing(ctx, report2)
    assert marked == 0
    repo_b_arn = f"arn:aws:ecr:{R1}:{ACCOUNT}:repository/repo-b"
    rows = await ctx.db.observations(provider_id="aws-prod")
    repo_b = next(r for r in rows if r["resource_key"] == repo_b_arn)
    assert repo_b["missing_since"] is None


async def test_ecr_images_are_fully_paginated_not_sampled(ctx: OperationContext) -> None:
    repo = {"repositoryName": "repo-a", "repositoryArn": f"arn:aws:ecr:{R1}:{ACCOUNT}:repository/repo-a"}
    image_pages = [{"imageDetails": [{"imageDigest": f"sha256:{i:064d}", "imagePushedAt": datetime(2026, 1, 1, tzinfo=UTC)}]} for i in range(25)]  # > old maxResults=20 bound
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    clients[("ecr", R1)] = FakeClient("ecr", {}, {"describe_repositories": [{"repositories": [repo]}], "describe_images": image_pages})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["ecr"]), ctx.budget)
    imgs = [o for o in report.observations if o.resource_type == "aws/ecr_image"]
    assert len(imgs) == 25
    assert f"aws-prod/{ACCOUNT}/{R1}/ecr" in report.completed_scopes


async def test_route53_zone_over_500_records_is_complete(ctx: OperationContext) -> None:
    zone = {"Id": "/hostedzone/Z1", "Name": "example.com.", "ResourceRecordSetCount": 501, "Config": {"PrivateZone": False}}
    record_pages = [{"ResourceRecordSets": [{"Name": f"r{i}.example.com.", "Type": "A", "ResourceRecords": [{"Value": "1.1.1.1"}]}]} for i in range(501)]
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["route53"] = FakeClient("route53", {}, {"list_hosted_zones": [{"HostedZones": [zone]}], "list_resource_record_sets": record_pages})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["route53"]), ctx.budget)
    zone_key = f"aws-prod/{ACCOUNT}/global/route53"
    records_key = f"{zone_key}/Z1/records"
    assert zone_key in report.completed_scopes  # the zone listing itself was fully enumerated
    assert records_key in report.completed_scopes and records_key not in report.partial_scopes
    zone_obs = next(o for o in report.observations if o.resource_type == "aws/route53_zone")
    assert zone_obs.scope_key == zone_key
    record_obs = [o for o in report.observations if o.resource_type == "aws/route53_record"]
    assert record_obs and all(o.scope_key == records_key for o in record_obs)


async def test_iam_more_than_50_users_inspects_all_access_keys(ctx: OperationContext) -> None:
    users = [{"UserName": f"u{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:user/u{i}", "UserId": f"AID{i}"} for i in range(55)]
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}, {"list_users": [{"Users": users}], "list_roles": [{"Roles": []}], "list_access_keys": [{"AccessKeyMetadata": []}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    iam_key = f"aws-prod/{ACCOUNT}/global/iam"
    access_keys_key = f"{iam_key}/access_keys"
    assert iam_key in report.completed_scopes  # user/role listing itself was not capped
    assert access_keys_key in report.completed_scopes and access_keys_key not in report.partial_scopes


async def test_iam_roles_and_access_key_pages_are_exhaustive(ctx: OperationContext) -> None:
    users = [{"UserName": "a", "Arn": f"arn:aws:iam::{ACCOUNT}:user/a", "UserId": "AIDAa"}]
    roles = [{"RoleName": f"r{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:role/r{i}", "RoleId": f"AROA{i}"} for i in range(201)]
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_access_key_last_used": {"AccessKeyLastUsed": {}}, "get_account_summary": {"SummaryMap": {}}}, {"list_users": [{"Users": users}], "list_roles": [{"Roles": roles[:200]}, {"Roles": roles[200:]}], "list_access_keys": [{"AccessKeyMetadata": [{"AccessKeyId": "AKIA0000000000000001"}]}, {"AccessKeyMetadata": [{"AccessKeyId": "AKIA0000000000000002"}]}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    assert len([o for o in report.observations if o.resource_type == "aws/iam_role"]) == 201
    assert len([o for o in report.observations if o.resource_type == "aws/iam_access_key"]) == 2


async def test_iam_access_key_last_used_workers_are_bounded_and_concurrent(ctx: OperationContext) -> None:
    users = [{"UserName": f"u{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:user/u{i}", "UserId": f"AIDA{i}"} for i in range(4)]
    active = peak = 0

    async def last_used(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"AccessKeyLastUsed": {}}

    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_access_key_last_used": last_used, "get_account_summary": {"SummaryMap": {}}}, {"list_users": [{"Users": users}], "list_roles": [{"Roles": []}], "list_access_keys": lambda kw: [{"AccessKeyMetadata": [{"AccessKeyId": f"AKIA{kw['UserName']:0>16}"}]}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    assert peak > 1
    assert peak <= ad.server.limits.provider_concurrency_per_provider
    assert len([o for o in report.observations if o.resource_type == "aws/iam_access_key"]) == 4


async def test_iam_last_used_denial_keeps_users_and_marks_key_scope_partial(ctx: OperationContext) -> None:
    users = [{"UserName": "u", "Arn": f"arn:aws:iam::{ACCOUNT}:user/u", "UserId": "AIDA"}]
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_access_key_last_used": client_error("AccessDenied", "GetAccessKeyLastUsed"), "get_account_summary": {"SummaryMap": {}}}, {"list_users": [{"Users": users}], "list_roles": [{"Roles": []}], "list_access_keys": [{"AccessKeyMetadata": [{"AccessKeyId": "AKIA0000000000000001"}]}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    iam_key = f"aws-prod/{ACCOUNT}/global/iam"
    assert iam_key in report.partial_scopes and iam_key not in report.completed_scopes
    assert f"{iam_key}/access_keys" in report.partial_scopes
    assert any(o.resource_type == "aws/iam_user" for o in report.observations)
    assert any(u.get("operation") == "get_access_key_last_used" for u in report.unavailable)


async def test_s3_list_buckets_uses_pagination(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["s3"] = FakeClient("s3", {"get_bucket_location": {"LocationConstraint": R1}}, {"list_buckets": [{"Buckets": [{"Name": "one"}]}, {"Buckets": [{"Name": "two"}]}]})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["s3"]), ctx.budget)
    assert {o.identity["name"] for o in report.observations if o.resource_type == "aws/s3_bucket"} == {"one", "two"}


async def test_iam_account_summary_failure_is_partial_not_main_scope(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_global()}
    clients["iam"] = FakeClient("iam", {"get_account_summary": client_error("AccessDeniedException", "GetAccountSummary")}, {"list_users": [{"Users": []}], "list_roles": [{"Roles": []}], **IAM_EMPTY_POLICY_PAGES})
    ad, _ = adapter(clients, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["iam"]), ctx.budget)
    iam_key = f"aws-prod/{ACCOUNT}/global/iam"
    summary_key = f"{iam_key}/account_summary"
    assert iam_key in report.partial_scopes and iam_key not in report.completed_scopes
    assert summary_key in report.partial_scopes and summary_key not in report.completed_scopes


async def test_account_identity_change_yields_different_scope_keys(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    ad, _ = adapter(clients, regions=[R1])
    report1 = await ad.discover(ctx, DiscoveryScope(families=["ec2"]), ctx.budget)

    other_account = "999999999999"
    clients2: dict[Any, FakeClient] = {"sts": sts_client(other_account), **empty_regional(R1)}
    ad2, _ = adapter(clients2, regions=[R1], expected_account_id=other_account)
    report2 = await ad2.discover(ctx, DiscoveryScope(families=["ec2"]), ctx.budget)

    assert set(report1.completed_scopes) and set(report1.completed_scopes).isdisjoint(report2.completed_scopes)
    assert f"aws-prod/{ACCOUNT}/{R1}/ec2" in report1.completed_scopes
    assert f"aws-prod/{other_account}/{R1}/ec2" in report2.completed_scopes


async def test_unverified_identity_completes_no_scope(ctx: OperationContext) -> None:
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    ad, _ = adapter(clients, regions=[R1], expected_account_id=None)
    report = await ad.discover(ctx, DiscoveryScope(families=["ec2"]), ctx.budget)
    assert report.completed_scopes == []
    assert f"aws-prod/{ACCOUNT}/{R1}/ec2" in report.partial_scopes
    assert any("unverified" in n for n in report.notes)


async def test_describe_lists_families_and_limitations() -> None:
    ad, _ = adapter({"sts": sts_client()}, organizations_enumeration=True, cloudtrail_lake_event_data_store="eds-1")
    d = ad.describe()
    assert d.kind == "aws" and d.credential_configured is True
    assert {o.name for o in d.operations} == {"discover", "cloudtrail_events", "cloudwatch_logs", "cloudwatch_metrics", "guardduty_findings", "kubernetes_audit", "eks_log_coverage"}
    assert "organizations" in d.families and "billing" in d.families
    assert "CloudTrail event history is per account/region, management events only, 90 days" in d.limitations
    assert any(lim.startswith("CloudTrail Lake / historical stores not queried") for lim in d.limitations)
    assert "S3 data events and EKS audit activity are not in event history" in d.limitations
    assert "Billing dimensions are cost aggregation, not an inventory" in d.limitations
    assert d.scope_constraints["cloudtrail_lake_event_data_store"] == "eds-1"
    ct = next(o for o in d.operations if o.name == "cloudtrail_events")
    assert "actors" in ct.local_filters and any("EventName" in f for f in ct.provider_side_filters)
    assert next(o for o in d.operations if o.name == "cloudwatch_logs").effect.value == "read_with_bookkeeping"
    assert "organizations" not in AwsAdapter(make_config(), ServerConfig(), None, session_factory=lambda: None).describe().families


# ---------------------------------------------------------------- cloudtrail


def ct_event(eid: str, name: str, user: str, region: str, ip: str = "203.0.113.5", error: str | None = None, access_key: str | None = None) -> dict[str, Any]:
    body = {"eventID": eid, "eventName": name, "eventTime": "2026-09-30T10:00:00Z", "eventSource": "iam.amazonaws.com", "userIdentity": {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}", "accessKeyId": access_key or "ASIAFAKEFAKEFAKEFAKE"}, "sourceIPAddress": ip, "userAgent": "aws-cli", "errorCode": error, "requestParameters": {"userName": "svc"}, "resources": [], "awsRegion": region, "recipientAccountId": ACCOUNT}
    return {"EventId": eid, "EventName": name, "Username": user, "EventTime": datetime(2026, 9, 30, 10, 0, tzinfo=UTC), "AccessKeyId": access_key or "ASIAFAKEFAKEFAKEFAKE", "CloudTrailEvent": json.dumps(body)}


def ct_event_body(eid: str, region: str, body_overrides: dict[str, Any]) -> dict[str, Any]:
    """A raw LookupEvents record wrapping an arbitrary `CloudTrailEvent` JSON body, for event shapes
    (Identity Center sign-ins, SAML federation) `ct_event`'s IAMUser shape cannot express."""
    body = {"eventID": eid, "eventTime": "2026-09-30T10:00:00Z", "sourceIPAddress": "203.0.113.9", "userAgent": "aws-internal", "resources": [], "awsRegion": region, "recipientAccountId": ACCOUNT, **body_overrides}
    return {"EventId": eid, "EventName": body.get("eventName"), "EventTime": datetime(2026, 9, 30, 10, 0, tzinfo=UTC), "CloudTrailEvent": json.dumps(body)}


IDENTITY_STORE_ARN = f"arn:aws:identitystore::{ACCOUNT}:identitystore/d-1234567890"
IDENTITY_CENTER_USER_ID = "11111111-2222-3333-4444-555555555555"


async def test_cloudtrail_federate_identity_center_actor_and_target(ctx: OperationContext) -> None:
    body = {
        "eventName": "Federate",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"type": "IdentityCenterUser", "credentialId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "onBehalfOf": {"userId": IDENTITY_CENTER_USER_ID, "identityStoreArn": IDENTITY_STORE_ARN}},
        "serviceEventDetails": {"account_id": ACCOUNT, "role_name": "AdministratorAccess"},
        "requestParameters": None,
    }
    ct = FakeClient("cloudtrail", {"lookup_events": {"Events": [ct_event_body("e1", R1, body)], "NextToken": None}})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    ev = res.events[0]
    assert ev["actor"] == "identitycenter:d-1234567890:11111111-2222-3333-4444-555555555555"
    assert ev["actor_type"] == "IdentityCenterUser"
    assert ev["fields"]["identity_center_user_id"] == IDENTITY_CENTER_USER_ID
    assert ev["fields"]["identity_store_arn"] == IDENTITY_STORE_ARN
    assert ev["fields"]["target_account_id"] == ACCOUNT and ev["fields"]["target_role_name"] == "AdministratorAccess"
    assert "identity_center_user_name" not in ev["fields"]  # no identitystore observation released yet
    # the credential id on userIdentity never persists, even though it was in the raw upstream record
    text = await stored_evidence_text(ctx)
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in text
    assert "REDACTED" in text


async def test_cloudtrail_get_role_credentials_identity_center_actor_from_request_parameters(ctx: OperationContext) -> None:
    body = {
        "eventName": "GetRoleCredentials",
        "eventSource": "sso.amazonaws.com",
        "userIdentity": {"type": "IdentityCenterUser", "credentialId": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "onBehalfOf": {"userId": IDENTITY_CENTER_USER_ID, "identityStoreArn": IDENTITY_STORE_ARN}},
        "requestParameters": {"accountId": ACCOUNT, "roleName": "AdministratorAccess"},
    }
    ct = FakeClient("cloudtrail", {"lookup_events": {"Events": [ct_event_body("e2", R1, body)], "NextToken": None}})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    ev = res.events[0]
    assert ev["actor"] == "identitycenter:d-1234567890:11111111-2222-3333-4444-555555555555"
    assert ev["fields"]["target_account_id"] == ACCOUNT and ev["fields"]["target_role_name"] == "AdministratorAccess"
    assert ev["fields"]["request_parameters"] == {"accountId": ACCOUNT, "roleName": "AdministratorAccess"}
    text = await stored_evidence_text(ctx)
    assert "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" not in text


async def test_cloudtrail_identity_center_user_name_resolves_from_released_observation(ctx: OperationContext) -> None:
    body = {
        "eventName": "Authenticate",
        "eventSource": "sso.amazonaws.com",
        "userIdentity": {"type": "IdentityCenterUser", "onBehalfOf": {"userId": IDENTITY_CENTER_USER_ID, "identityStoreArn": IDENTITY_STORE_ARN}},
        "requestParameters": None,
    }
    ct = FakeClient("cloudtrail", {"lookup_events": {"Events": [ct_event_body("e3", R1, body)], "NextToken": None}})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1])
    await ctx.db.upsert_observations(ctx.request_id, [{"provider_id": "aws-prod", "resource_key": IDENTITY_CENTER_USER_ID, "resource_type": "aws/identitystore_user", "identity": {"user_id": IDENTITY_CENTER_USER_ID}, "attributes": {"user_name": "alice"}}])
    async with ctx.db.tx() as c:
        await c.execute("UPDATE observations SET released_to=? WHERE resource_key=?", (f'["{ctx.principal.id}"]', IDENTITY_CENTER_USER_ID))
    res = await ad.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert res.events[0]["fields"]["identity_center_user_name"] == "alice"


async def test_cloudtrail_assume_role_with_saml_actor_is_saml_subject(ctx: OperationContext) -> None:
    body = {
        "eventName": "AssumeRoleWithSAML",
        "eventSource": "sts.amazonaws.com",
        "userIdentity": {"type": "SAMLUser", "principalId": "A1B2C3D4E5F6:carol@example.com", "userName": "carol@example.com", "identityProvider": f"arn:aws:iam::{ACCOUNT}:saml-provider/corp-idp"},
        "requestParameters": {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/federated-admin", "SAMLAssertion": "redacted-in-aws-already"},
        "responseElements": {"assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/federated-admin/carol@example.com"}},
    }
    ct = FakeClient("cloudtrail", {"lookup_events": {"Events": [ct_event_body("e4", R1, body)], "NextToken": None}})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert res.events[0]["actor"] == "carol@example.com"
    assert res.events[0]["actor_type"] == "SAMLUser"
    assert "identity_center_user_id" not in res.events[0]["fields"]


async def test_cloudtrail_single_server_side_attribute_and_local_filters(ctx: OperationContext) -> None:
    ct1 = FakeClient("cloudtrail", {"lookup_events": lambda kw: {"Events": [ct_event("e1", "CreateAccessKey", "carol", R1, access_key=FAKE_KEY), ct_event("e2", "CreateAccessKey", "alice", R1), ct_event("e3", "CreateAccessKey", "carol", R1, ip="192.0.2.9")], "NextToken": None}})
    ct2 = FakeClient("cloudtrail", {"lookup_events": client_error("AccessDeniedException", "LookupEvents")})
    ad, _ = adapter({"sts": sts_client(), ("cloudtrail", R1): ct1, ("cloudtrail", R2): ct2})
    start, end = "2026-09-30T00:00:00Z", "2026-09-30T23:59:59Z"
    res = await ad.query(ctx, {"query_type": "cloudtrail_events", "filters": {"event_names": ["CreateAccessKey"], "actors": ["carol"], "source_ips": ["203.0.113.5"]}, "time_range": {"start": start, "end": end}, "limits": {"max_pages": 5, "max_events": 100}}, ctx.budget)
    kw = ct1.calls[0][1]
    assert kw["LookupAttributes"] == [{"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"}]
    assert kw["StartTime"].isoformat() == "2026-09-30T00:00:00+00:00" and kw["EndTime"].year == 2026
    cov = res.coverage
    assert cov.filters_provider_side == ["time_range", "event_names[0] (EventName)"]
    assert cov.filters_local == ["actors", "source_ips"]
    assert [e["event_id"] for e in res.events] == ["e1"]
    assert res.events[0]["actor"] == "carol" and res.events[0]["event_key"] == f"cloudtrail:{ACCOUNT}:e1"
    assert res.cursor is None
    assert cov.completed_scopes == [f"aws-prod/{R1}"] and cov.regions_completed == [R1]
    assert cov.regions_requested == [R1, R2] and cov.accounts_expected == [ACCOUNT] and cov.accounts_reached == [ACCOUNT]
    assert cov.permission_failures == [f"aws-prod/{R2}: lookup_events (permission_denied)"]
    assert cov.unavailable_scopes[0].source == f"aws-prod/{R2}" and cov.unavailable_scopes[0].reason == "permission_denied"
    assert cov.source_retention_known is True
    assert cov.source_retention_note == "CloudTrail event history: management events, last 90 days, per account/region"
    assert "Local filters (actors, source_ips) ran over the complete upstream result set" in cov.conclusion_scope
    assert cov.time_range_requested == {"start": start, "end": end}
    assert cov.event_categories == ["management"] and cov.truncated is False
    assert res.query_description["effect"] == "read"
    # raw evidence was stored and scrubbed: the access key id never persists
    text = await stored_evidence_text(ctx)
    assert "AKIA" not in text and "ASIAFAKE" not in text and "carol" in text


async def test_cloudtrail_capped_upstream_result_set_is_stated(ctx: OperationContext) -> None:
    def pages(kw: dict[str, Any]) -> dict[str, Any]:
        return {"Events": [ct_event(f"e{kw.get('NextToken', '0')}", "ConsoleLogin", "bob", R1)], "NextToken": str(int(kw.get("NextToken", "0")) + 1)}

    ct = FakeClient("cloudtrail", {"lookup_events": pages})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudtrail_events", "filters": {"actors": ["bob"], "event_names": ["ConsoleLogin", "AssumeRole"]}, "limits": {"max_pages": 3, "max_events": 1000}}, ctx.budget)
    assert len(ct.calls) == 3
    cov = res.coverage
    assert cov.truncated is True and cov.pagination_complete is False
    assert cov.completed_scopes == [] and cov.regions_completed == []
    # event_names outranks actors for the single server-side attribute; the second event name and the actor run locally
    assert cov.filters_provider_side == ["time_range", "event_names[0] (EventName)"] and cov.filters_local == ["event_names", "actors"]
    assert "ran over a capped upstream result set" in cov.conclusion_scope
    assert "absence of a match is not evidence of absence" in cov.conclusion_scope
    assert len(res.events) == 3


async def test_cloudtrail_without_filters_and_lake_store_reported(ctx: OperationContext) -> None:
    ct = FakeClient("cloudtrail", {"lookup_events": {"Events": [], "NextToken": None}})
    ad, _ = adapter({"sts": sts_client(), "cloudtrail": ct}, regions=[R1], cloudtrail_lake_event_data_store="eds-1")
    res = await ad.query(ctx, {"query_type": "cloudtrail_events", "scope": {"regions": [R1]}}, ctx.budget)
    assert "LookupAttributes" not in ct.calls[0][1]
    assert res.coverage.filters_provider_side == ["time_range"] and res.coverage.filters_local == []
    lake = [u for u in res.coverage.unavailable_scopes if u.reason == "unsupported_in_this_release"]
    assert lake and "cloudtrail-lake/eds-1" in lake[0].source
    assert res.coverage.completed_scopes == [f"aws-prod/{R1}"]


# ---------------------------------------------------------------- guardduty / eks audit / cloudwatch


async def test_guardduty_no_detector_is_unavailable_scope_not_error(ctx: OperationContext) -> None:
    gd1 = FakeClient("guardduty", {}, {"list_detectors": [{"DetectorIds": []}]})
    gd2 = FakeClient("guardduty", {"get_findings": {"Findings": [{"Id": "f1", "Type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", "Severity": 5.0, "UpdatedAt": "2026-09-30T10:09:00Z", "Title": "x"}]}}, {"list_detectors": [{"DetectorIds": ["d1"]}], "list_findings": [{"FindingIds": ["f1"]}]})
    ad, _ = adapter({"sts": sts_client(), ("guardduty", R1): gd1, ("guardduty", R2): gd2})
    res = await ad.query(ctx, {"query_type": "guardduty_findings", "limits": {"max_events": 10}}, ctx.budget)
    cov = res.coverage
    assert [(u.source, u.reason) for u in cov.unavailable_scopes] == [(f"aws-prod/{R1}", "guardduty_not_enabled")]
    assert cov.completed_scopes == [f"aws-prod/{R2}"] and cov.permission_failures == []
    assert len(res.items) == 1 and res.items[0]["Id"] == "f1" and res.items[0]["evidence_ref"] in ctx.evidence_ids and res.items[0]["region"] == R2
    assert all(c[0] in ("paginate:list_detectors",) for c in gd1.calls)  # nothing was created or enabled
    assert "guardduty_not_enabled" in cov.conclusion_scope


async def test_kubernetes_audit_disabled_logging_is_coverage_gap(ctx: OperationContext) -> None:
    arn = f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/prod"
    eks = FakeClient("eks", {"describe_cluster": {"cluster": {"name": "prod", "arn": arn, "logging": {"clusterLogging": [{"types": ["api"], "enabled": True}]}}}})
    logs = FakeClient("logs", {"filter_log_events": AssertionError("must not read logs when audit logging is disabled")})
    ad, _ = adapter({"sts": sts_client(), "eks": eks, "logs": logs}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "kubernetes_audit", "scope": {"cluster_name": "prod"}}, ctx.budget)
    cov = res.coverage
    assert cov.disabled_logging == ["prod"]
    assert [u.reason for u in cov.unavailable_scopes] == ["audit_log_source_not_available"]
    assert cov.completed_scopes == [] and res.events == [] and cov.clusters_covered == []
    assert "coverage gap" in cov.conclusion_scope
    assert res.query_description["logging"]["audit"] is False
    assert logs.calls == []


async def test_kubernetes_audit_enabled_reads_and_normalizes(ctx: OperationContext) -> None:
    arn = f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/prod"
    eks = FakeClient("eks", {"describe_cluster": {"cluster": {"name": "prod", "arn": arn, "logging": {"clusterLogging": [{"types": ["api", "audit"], "enabled": True}]}}}})
    rec = {"auditID": "a1", "verb": "create", "user": {"username": "system:serviceaccount:kube-system:eks-admin-sa"}, "objectRef": {"resource": "clusterrolebindings", "name": "backdoor"}, "requestReceivedTimestamp": "2026-09-30T10:30:00Z", "sourceIPs": ["192.0.2.44"], "responseStatus": {"code": 201}}
    other = {**rec, "auditID": "a2", "user": {"username": "alice"}, "verb": "get"}
    logs = FakeClient("logs", {"describe_log_groups": {"logGroups": [{"logGroupName": "/aws/eks/prod/cluster", "retentionInDays": 30}]}, "filter_log_events": {"events": [{"logStreamName": "kube-apiserver-audit-1", "timestamp": 1, "message": json.dumps(rec)}, {"logStreamName": "kube-apiserver-audit-1", "timestamp": 2, "message": json.dumps(other)}, {"logStreamName": "kube-apiserver-audit-1", "timestamp": 3, "message": "not json"}]}})
    ad, _ = adapter({"sts": sts_client(), "eks": eks, "logs": logs}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "kubernetes_audit", "scope": {"cluster_name": "prod"}, "filters": {"actors": ["eks-admin-sa"]}}, ctx.budget)
    kw = next(k for n, k in logs.calls if n == "filter_log_events")
    assert kw["logGroupName"] == "/aws/eks/prod/cluster" and kw["logStreamNamePrefix"] == "kube-apiserver-audit"
    assert [e["event_id"] for e in res.events] == ["a1"]
    assert res.events[0]["event_key"] == f"k8saudit:{arn}:a1" and res.events[0]["category"] == "kubernetes_audit"
    assert res.coverage.clusters_covered == [arn] and res.coverage.completed_scopes == [f"aws-prod/{R1}/eks/prod/audit"]
    assert res.coverage.source_retention_known is True and "30 days" in (res.coverage.source_retention_note or "")
    assert res.coverage.filters_local == ["actors"] and res.coverage.disabled_logging == []
    assert any("not valid JSON" in g for g in res.coverage.collection_gaps)


async def test_eks_log_coverage_lists_logging_config(ctx: OperationContext) -> None:
    eks = FakeClient("eks", {"describe_cluster": lambda kw: {"cluster": {"name": kw["name"], "arn": f"arn:aws:eks:{R1}:{ACCOUNT}:cluster/{kw['name']}", "logging": {"clusterLogging": [{"types": ["audit"], "enabled": kw["name"] == "a"}]}}}}, {"list_clusters": [{"clusters": ["a", "b"]}]})
    logs = FakeClient("logs", {"describe_log_groups": lambda kw: {"logGroups": [{"logGroupName": kw["logGroupNamePrefix"], "retentionInDays": None}]}})
    ad, _ = adapter({"sts": sts_client(), "eks": eks, "logs": logs}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "eks_log_coverage"}, ctx.budget)
    assert [(i["cluster"], i["audit_enabled"]) for i in res.items] == [("a", True), ("b", False)]
    assert res.coverage.disabled_logging == ["b"] and len(res.coverage.clusters_covered) == 2


async def test_cloudwatch_logs_insights_job_is_read_with_bookkeeping(ctx: OperationContext) -> None:
    polls = {"n": 0}

    def results(kw: dict[str, Any]) -> dict[str, Any]:
        polls["n"] += 1
        if polls["n"] < 2:
            return {"status": "Running", "results": []}
        return {"status": "Complete", "results": [[{"field": "@timestamp", "value": "2026-09-30 10:00:00.000"}, {"field": "@message", "value": "hello"}]], "statistics": {"recordsScanned": 10}}

    logs = FakeClient("logs", {"describe_log_groups": {"logGroups": []}, "start_query": {"queryId": "q-1"}, "get_query_results": results})
    ad, _ = adapter({"sts": sts_client(), "logs": logs}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudwatch_logs", "scope": {"log_groups": ["/aws/app"]}, "time_range": {"start": "2026-09-30T09:00:00Z", "end": "2026-09-30T11:00:00Z"}}, ctx.budget)
    assert res.query_description["effect"] == "read_with_bookkeeping" and res.query_description["mode"] == "logs_insights"
    assert res.query_description["jobs"][0]["query_id"] == "q-1" and res.query_description["jobs"][0]["status"] == "Complete"
    assert [n for n, _ in logs.calls] == ["describe_log_groups", "start_query", "get_query_results", "get_query_results"]
    assert next(k for n, k in logs.calls if n == "start_query")["queryString"].startswith("fields @timestamp, @message")
    assert res.items == [{"region": R1, "log_groups": ["/aws/app"], "@timestamp": "2026-09-30 10:00:00.000", "@message": "hello", "evidence_ref": res.raw_evidence_ids[0]}]
    assert res.coverage.completed_scopes == [f"aws-prod/{R1}"] and res.coverage.truncated is False
    assert res.coverage.source_retention_known is False


async def test_cloudwatch_logs_filter_pattern_is_plain_read(ctx: OperationContext) -> None:
    logs = FakeClient("logs", {"describe_log_groups": {"logGroups": [{"logGroupName": "/aws/app", "retentionInDays": 14}]}, "filter_log_events": {"events": [{"logStreamName": "s", "timestamp": 1759226400000, "message": "ERROR boom", "eventId": "x"}]}, "start_query": AssertionError("must use FilterLogEvents when filter_pattern is given")})
    ad, _ = adapter({"sts": sts_client(), "logs": logs}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudwatch_logs", "scope": {"log_groups": ["/aws/app"]}, "filters": {"filter_pattern": "ERROR"}}, ctx.budget)
    assert res.query_description["effect"] == "read" and res.query_description["mode"] == "filter_log_events"
    assert res.items[0]["message"] == "ERROR boom" and res.items[0]["timestamp"] == "2025-09-30T10:00:00Z"
    assert res.coverage.source_retention_note == "/aws/app: 14 days"
    assert res.coverage.filters_provider_side == ["log_groups", "time_range", "filter_pattern"]


async def test_cloudwatch_metrics_bounded(ctx: OperationContext) -> None:
    cw = FakeClient("cloudwatch", {"get_metric_data": {"MetricDataResults": [{"Id": "cpu", "Label": "CPUUtilization", "Timestamps": [datetime(2026, 9, 30, 10, tzinfo=UTC)], "Values": [12.0], "StatusCode": "Complete"}]}})
    ad, _ = adapter({"sts": sts_client(), "cloudwatch": cw}, regions=[R1])
    res = await ad.query(ctx, {"query_type": "cloudwatch_metrics", "scope": {"queries": [{"id": "cpu", "namespace": "AWS/EC2", "metric_name": "CPUUtilization", "dimensions": {"InstanceId": "i-1"}, "stat": "Average", "period": 60}]}}, ctx.budget)
    q = cw.calls[0][1]["MetricDataQueries"][0]
    assert q["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "InstanceId", "Value": "i-1"}] and q["MetricStat"]["Period"] == 60
    assert res.items[0]["values"] == [12.0] and res.items[0]["timestamps"] == ["2026-09-30T10:00:00Z"]
    assert res.coverage.completed_scopes == [f"aws-prod/{R1}"]
    with pytest.raises(OpsError) as ei:
        await ad.query(ctx, {"query_type": "cloudwatch_metrics", "scope": {"queries": [{}] * 21}}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


async def test_unsupported_query_type(ctx: OperationContext) -> None:
    ad, _ = adapter({"sts": sts_client()})
    with pytest.raises(OpsError) as ei:
        await ad.query(ctx, {"query_type": "nope"}, ctx.budget)
    assert ei.value.code == ErrorCode.UNSUPPORTED_OPERATION


async def test_lambda_evidence_keeps_environment_names_not_values(ctx: OperationContext) -> None:
    fn = {"FunctionName": "f", "FunctionArn": f"arn:aws:lambda:{R1}:{ACCOUNT}:function:f", "Environment": {"Variables": {"STRIPE_KEY": "sk_live_zzzz", "MODE": "prod-mode-value"}}}
    clients: dict[Any, FakeClient] = {"sts": sts_client(), **empty_regional(R1)}
    clients[("lambda", R1)] = FakeClient("lambda", {}, {"list_functions": [{"Functions": [fn]}]})
    ad, _ = adapter(clients, regions=[R1])
    await ad.discover(ctx, DiscoveryScope(families=["lambda"]), ctx.budget)
    text = await stored_evidence_text(ctx)
    assert "sk_live_zzzz" not in text and "prod-mode-value" not in text
    assert "STRIPE_KEY" in text and "MODE" in text


def test_discovery_denominators_count_regions_from_account_scoped_keys() -> None:
    from local_ops.discovery import denominators
    from local_ops.providers.base import DiscoveryReport

    report = DiscoveryReport(provider_id="aws-prod", completed_scopes=[f"aws-prod/{ACCOUNT}/{R1}/lambda", f"aws-prod/{ACCOUNT}/global/iam"])
    den = denominators([report], {"regions": [R1, R2]}, [], ["aws-prod"])
    assert den.regions_completed == 1


async def test_event_buses_manual_pages_and_rule_targets(ctx: OperationContext) -> None:
    def buses(kwargs: dict[str, Any]) -> dict[str, Any]:
        if kwargs.get("NextToken") == "page-two":
            return {"EventBuses": [{"Name": "second"}]}
        return {"EventBuses": [{"Name": "first"}], "NextToken": "page-two"}

    def rules(kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        name = kwargs["EventBusName"]
        return [{"Rules": [{"Name": name, "Arn": f"arn:rule:{name}", "EventBusName": name}]}]

    ev = FakeClient("events", {"list_event_buses": buses}, {
        "list_rules": rules,
        "list_targets_by_rule": lambda kwargs: [{"Targets": [{"Arn": f"arn:target:{kwargs['Rule']}"}]}],
    })
    ad, _ = adapter({"sts": sts_client(), ("events", R1): ev}, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["events"]), ctx.budget)
    assert not report.unavailable
    assert {o.resource_key for o in report.observations} >= {"arn:rule:first", "arn:rule:second"}
    assert [kw for op, kw in ev.calls if op == "list_event_buses"] == [{}, {"NextToken": "page-two"}]
    assert f"{ad.provider_id}/{ACCOUNT}/{R1}/events" in report.completed_scopes
    for observation in report.observations:
        if observation.resource_type == "aws/eventbridge_rule":
            assert observation.relationships == [{"kind": "targets", "target": f"arn:target:{observation.identity['name']}"}]


async def test_event_bus_page_failure_never_completes_scope(ctx: OperationContext) -> None:
    def buses(kwargs: dict[str, Any]) -> dict[str, Any]:
        if kwargs.get("NextToken"):
            raise client_error("AccessDeniedException", "ListEventBuses")
        return {"EventBuses": [{"Name": "first"}], "NextToken": "page-two"}

    ev = FakeClient("events", {"list_event_buses": buses})
    ad, _ = adapter({"sts": sts_client(), ("events", R1): ev}, regions=[R1])
    report = await ad.discover(ctx, DiscoveryScope(families=["events"]), ctx.budget)
    key = f"{ad.provider_id}/{ACCOUNT}/{R1}/events"
    assert key in report.partial_scopes and key not in report.completed_scopes
    assert any(u["reason"] == "permission_denied" for u in report.unavailable)


@pytest.mark.parametrize("organizations_enabled", [True, False])
async def test_management_billing_retains_linked_account_spend_and_coverage_gap(ctx: OperationContext, organizations_enabled: bool) -> None:
    from local_ops.providers.aws_coverage import build_aws_coverage

    other = "210987654321"
    service = "Amazon Relational Database Service"

    def group(account: str, amount: str) -> dict[str, Any]:
        return {"Keys": [account, service], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}}

    def costs(kwargs: dict[str, Any]) -> dict[str, Any]:
        assert kwargs["GroupBy"] == [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "SERVICE"}]
        if kwargs.get("NextPageToken") == "next":
            return {"ResultsByTime": [{"Groups": [group(other, "150")]}]}
        return {"ResultsByTime": [{"Groups": [group(ACCOUNT, "25"), group(other, "300")]}], "NextPageToken": "next"}

    ce = FakeClient("ce", {"get_cost_and_usage": costs})
    org = FakeClient("organizations", {}, {"list_accounts": [{"Accounts": [{"Id": value, "Arn": f"arn:aws:organizations::account/{value}", "Name": value} for value in (ACCOUNT, other)]}]})
    ad, _ = adapter({"sts": sts_client(), "ce": ce, "organizations": org}, regions=[R1], organizations_enumeration=organizations_enabled)
    scope = DiscoveryScope(families=["billing", "organizations"] if organizations_enabled else ["billing"])
    report = await ad.discover(ctx, scope, ctx.budget)
    assert not report.unavailable
    bills = {o.identity["account"]: o for o in report.observations if o.resource_type == "aws/billing_service_cost"}
    assert set(bills) == {ACCOUNT, other}
    assert bills[ACCOUNT].attributes["amount"] == 25
    assert bills[other].attributes["amount"] == 450
    assert bills[ACCOUNT].resource_key != bills[other].resource_key
    assert all(o.attributes["billing_source_account"] == ACCOUNT for o in bills.values())
    # The collection/comparison scope remains bound to the payer's credential.
    assert all(o.scope_key == f"{ad.provider_id}/{ACCOUNT}/global/billing" for o in bills.values())
    coverage = build_aws_coverage([report], ServerConfig(providers=[ad.config]), [ad.provider_id], scope)
    rows = {row["account"]: row for row in coverage["billing_service_coverage"]}
    assert set(rows) == {ACCOUNT, other}
    assert rows[other]["amount"] == 450 and rows[other]["billing_source_account"] == ACCOUNT
    assert rows[other]["status"] == "supported_but_not_complete"
    accounts = {row["account_id"]: row for row in coverage["accounts"]["coverage"]}
    assert accounts[ACCOUNT]["status"] == "reached"
    assert accounts[other]["status"] == "not_configured"
    assert "billing" in accounts[other]["evidence"]
    assert accounts[other]["reached_provider_ids"] == []
    if not organizations_enabled:
        assert accounts[other]["evidence"] == ["billing"]
        assert coverage["accounts"]["organization_denominator"] == "unknown_or_partial"
        assert not org.calls
