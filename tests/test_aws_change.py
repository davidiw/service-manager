"""D35: reviewed AWS changes through the aws_change executor. Fake sessions only; no network."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from local_ops.aws_change_contracts import (
    AwsTarget,
    EksAccessEntryRemoveConfiguration,
    IamCredentialStateConfiguration,
    IamUserRemoveConfiguration,
    IdentityCenterAssignmentRemoveConfiguration,
    Route53RecordConfiguration,
    aws_configuration_matches_target,
)
from local_ops.catalog import Binding, ServiceSpec
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.executors.aws_change import AwsChangeExecutor
from local_ops.models import ActionPlan, ErrorCode, ExecutionStatus, OpsError
from local_ops.operations.base import OperationContext
from local_ops.operations.execution import ActionPrepareArgs
from local_ops.providers.aws import AwsAdapter
from tests.providers.test_aws import FakeClient, FakeSession, sts_client

ACCOUNT = "111111111111"
ZONE = AwsTarget(resource_type="route53_zone", account_id=ACCOUNT, zone_id="Z0ABCDEFGHIJ", zone_name="example.com.")
IAM_CREDS = AwsTarget(resource_type="iam_credentials", account_id=ACCOUNT, user_name="terraform-bootstrap")
IAM_USER = AwsTarget(resource_type="iam_user", account_id=ACCOUNT, user_name="zac.yang")
IDC = AwsTarget(resource_type="identity_center", account_id=ACCOUNT, instance_arn="arn:aws:sso:::instance/ssoins-0123456789abcdef", region="us-west-2", assignment_account_ids=["222222222222"])
EKS = AwsTarget(resource_type="eks_cluster", account_id=ACCOUNT, cluster_name="network-api", region="us-east-1")
PS = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef"
PRINCIPAL = "d851c320-b081-707e-1b27-0a7e150a99ca"


# --- contracts ------------------------------------------------------------------------------------


def test_route53_configuration_shape_and_target_fence() -> None:
    cname = Route53RecordConfiguration(kind="route53_record", action="upsert", name="_acme.example.com.", record_type="CNAME", ttl=300, values=["_x.acm-validations.aws."])
    assert aws_configuration_matches_target(cname, ZONE)
    assert not aws_configuration_matches_target(Route53RecordConfiguration(kind="route53_record", action="upsert", name="www.other.com.", record_type="A", ttl=60, values=["10.0.0.1"]), ZONE)
    with pytest.raises(ValueError, match="exactly one of values or alias"):
        Route53RecordConfiguration(kind="route53_record", action="upsert", name="a.example.com.", record_type="A", ttl=60)
    with pytest.raises(ValueError, match="weight and set_identifier"):
        Route53RecordConfiguration(kind="route53_record", action="delete", name="a.example.com.", record_type="A", ttl=60, values=["10.0.0.1"], weight=0)
    with pytest.raises(ValueError, match="trailing-dot"):
        Route53RecordConfiguration(kind="route53_record", action="upsert", name="a.example.com", record_type="A", ttl=60, values=["10.0.0.1"])


def test_other_configurations_fence_to_their_targets() -> None:
    cred = IamCredentialStateConfiguration(kind="iam_credential_state", user_name="terraform-bootstrap", credential_kind="access_key", credential_id="AKIA4TUID66BRGOQTANX", status="Inactive")
    assert aws_configuration_matches_target(cred, IAM_CREDS)
    assert not aws_configuration_matches_target(cred, IAM_USER)  # a credentials target is not a user-removal target
    assert not aws_configuration_matches_target(IamCredentialStateConfiguration(kind="iam_credential_state", user_name="someone-else", credential_kind="access_key", credential_id="AKIA4TUID66BRGOQTANX", status="Inactive"), IAM_CREDS)
    with pytest.raises(ValueError, match="credential kind"):
        IamCredentialStateConfiguration(kind="iam_credential_state", user_name="u", credential_kind="service_specific", credential_id="AKIA4TUID66BRGOQTANX", status="Inactive")
    assert aws_configuration_matches_target(IamUserRemoveConfiguration(kind="iam_user_remove", confirm_user_name="zac.yang"), IAM_USER)
    assert not aws_configuration_matches_target(IamUserRemoveConfiguration(kind="iam_user_remove", confirm_user_name="zac.yang"), IAM_CREDS)
    idc = IdentityCenterAssignmentRemoveConfiguration(kind="identity_center_assignment_remove", target_account_id="222222222222", permission_set_arn=PS, principal_type="USER", principal_id=PRINCIPAL)
    assert aws_configuration_matches_target(idc, IDC)
    other = IdentityCenterAssignmentRemoveConfiguration(kind="identity_center_assignment_remove", target_account_id="222222222222", permission_set_arn="arn:aws:sso:::permissionSet/ssoins-fedcba9876543210/ps-0123456789abcdef", principal_type="USER", principal_id=PRINCIPAL)
    assert not aws_configuration_matches_target(other, IDC)  # a permission set of a different Identity Center instance
    elsewhere = idc.model_copy(update={"target_account_id": "333333333333"})
    assert not aws_configuration_matches_target(elsewhere, IDC)  # an account the binding does not fence
    assert aws_configuration_matches_target(EksAccessEntryRemoveConfiguration(kind="eks_access_entry_remove", principal_arn=f"arn:aws:iam::{ACCOUNT}:user/terraform-mainnet"), EKS)
    with pytest.raises(ValueError):
        AwsTarget(resource_type="route53_zone", account_id=ACCOUNT, zone_id="Z0ABCDEFGHIJ")  # zone_name required


def test_prepare_args_accept_aws_configuration_only_for_configure() -> None:
    args = ActionPrepareArgs.model_validate({"service_id": "s", "binding_id": "b", "action": "configure", "desired_configuration": {"kind": "eks_access_entry_remove", "principal_arn": f"arn:aws:iam::{ACCOUNT}:user/x"}})
    assert isinstance(args.desired_configuration, EksAccessEntryRemoveConfiguration)
    with pytest.raises(ValueError):
        ActionPrepareArgs.model_validate({"service_id": "s", "binding_id": "b", "action": "update", "desired_artifact": "repo:v1", "desired_configuration": {"kind": "eks_access_entry_remove", "principal_arn": f"arn:aws:iam::{ACCOUNT}:user/x"}})


# --- catalog and config validation ------------------------------------------------------------------


def _service(target: AwsTarget, executor: str = "aws_change", checks: list[str] | None = None) -> dict[str, Any]:
    return {"id": "aws-mgmt", "name": "x", "environments": ["mgmt"], "bindings": [{"id": "b", "environment": "mgmt", "provider_id": "aws-x", "workload_kind": "External", "execution_enabled": True, "source_state": "verified", "aws_target": target.model_dump()}],
            "operations": {"configure": {"executor": executor, "kind": "configure", "binding_id": "b", "health_checks": checks if checks is not None else ["aws_configuration_matches"]}}}


def test_catalog_requires_aws_change_executor_and_its_health_check() -> None:
    ServiceSpec.model_validate(_service(IAM_CREDS))
    with pytest.raises(ValueError, match="requires aws_change executor"):
        ServiceSpec.model_validate(_service(IAM_CREDS, executor="pagerduty_configuration"))
    with pytest.raises(ValueError, match="exactly aws_configuration_matches"):
        ServiceSpec.model_validate(_service(IAM_CREDS, checks=["ready_replicas"]))


def test_config_requires_execute_purpose_and_expected_account_for_aws_execution_credential() -> None:
    base = {"credentials": [{"id": "ro", "kind": "aws_sso", "profile": "acct-ro", "purpose": "read"}, {"id": "rw", "kind": "aws_sso", "profile": "acct-admin", "purpose": "read"}],
            "providers": [{"id": "aws-x", "kind": "aws", "credential": "ro", "execution_credential": "rw", "expected_account_id": ACCOUNT, "regions": ["us-east-1"]}]}
    with pytest.raises(ValueError, match="purpose 'execute'"):
        ServerConfig.model_validate(base)
    base["credentials"][1]["purpose"] = "execute"
    ServerConfig.model_validate(base)
    del base["providers"][0]["expected_account_id"]
    with pytest.raises(ValueError, match="expected_account_id"):
        ServerConfig.model_validate(base)


# --- adapter: execution session and identity ---------------------------------------------------------


def _adapter(read: FakeSession, execute: FakeSession | None, **over: Any) -> AwsAdapter:
    cfg = ProviderConfig.model_validate({"id": "aws-x", "kind": "aws", "credential": "ro", "execution_credential": "rw" if execute else None, "expected_account_id": ACCOUNT, "regions": ["us-east-1"], **over})
    return AwsAdapter(cfg, ServerConfig(), None, session_factory=lambda: read, execution_session_factory=(lambda: execute) if execute else None)


async def test_execution_identity_is_verified_separately_and_must_match_the_account() -> None:
    read = FakeSession({"sts": sts_client(ACCOUNT, "AWSReservedSSO_ReadOnly_abc")})
    good = FakeSession({"sts": sts_client(ACCOUNT, "AWSReservedSSO_AdministratorAccess_abc")})
    ad = _adapter(read, good, expected_role="AWSReservedSSO_ReadOnly_*", expected_execution_role="AWSReservedSSO_AdministratorAccess_*")
    assert (await ad.verified_identity())["connection"] == "read"
    assert (await ad.verified_identity(execution=True))["connection"] == "execution"
    wrong = FakeSession({"sts": sts_client("999999999999", "AWSReservedSSO_AdministratorAccess_abc")})
    ad2 = _adapter(read, wrong)
    with pytest.raises(OpsError) as ei:
        await ad2.verified_identity(execution=True)
    assert ei.value.data.get("reason") == "account_mismatch"
    assert (await ad2.check_availability(live=True)).available is False
    ad3 = _adapter(read, None)
    assert ad3.has_execution_credential() is False
    assert (await ad3.verified_identity(execution=True))["connection"] == "read"  # no execution credential: unchanged behaviour


# --- executor -------------------------------------------------------------------------------------


class _Exec:
    """Fake AWS adapter: execution_client hands out fake clients; identity is fixed."""

    kind = "aws"
    provider_id = "aws-x"

    def __init__(self, clients: dict[str, FakeClient], account: str = ACCOUNT):
        self.session = FakeSession(clients)
        self.account = account
        self.identity_calls = 0

    def has_execution_credential(self) -> bool:
        return True

    async def verified_identity(self, *, execution: bool = False) -> dict[str, Any]:
        self.identity_calls += 1
        return {"account": self.account, "arn": f"arn:aws:sts::{self.account}:assumed-role/Admin/x", "approved": True, "connection": "execution" if execution else "read"}

    def execution_client(self, service: str, region: str) -> Any:
        return self.session.create_client(service, region_name=region)


class _Db:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def complete_intent(self, intent_id: str, result: dict[str, Any]) -> None:
        self.rows[-1]["result"] = result

    async def intents(self, request_id: str) -> list[dict[str, Any]]:
        return self.rows


def _scrub(value: Any) -> Any:
    from local_ops.release import Sanitizer

    return Sanitizer().scrub(value)[0]


def _ctx(adapter: _Exec, target: AwsTarget) -> tuple[OperationContext, Binding]:
    binding = Binding(id="b", environment="mgmt", provider_id="aws-x", workload_kind="External", execution_enabled=True, source_state="verified", aws_target=target)
    spec = ServiceSpec(id="aws-mgmt", name="x", environments=["mgmt"], bindings=[binding])
    db = _Db()

    async def record_intent(phase: str, lock: str | None, summary: str, record: dict[str, Any]) -> str:
        db.rows.append({"phase": phase, "lock": lock, "summary": summary, "record": record, "result": None})
        return f"int_{len(db.rows)}"

    ctx = SimpleNamespace(catalog=SimpleNamespace(service=lambda _sid: SimpleNamespace(spec=spec), dependents_of=lambda _sid: [], revision="rev"), providers=SimpleNamespace(get=lambda _pid: adapter), budget=None,
                          scrub=_scrub, db=db, record_intent=record_intent, request_id="req_t", request={"review_mode": "yolo"}, principal=SimpleNamespace(id="p"), config=SimpleNamespace(review=SimpleNamespace(plan_ttl_minutes=30)))
    return cast(OperationContext, ctx), binding


def _op(**over: Any) -> Any:
    from local_ops.catalog import OperationConfig

    return OperationConfig.model_validate({"executor": "aws_change", "kind": "configure", "binding_id": "b", "health_checks": ["aws_configuration_matches"], "readiness_timeout_seconds": 30, **over})


async def test_route53_upsert_prepare_execute_and_verify() -> None:
    state: dict[str, Any] = {"records": []}
    zone = {"HostedZone": {"Id": "/hostedzone/Z0ABCDEFGHIJ", "Name": "example.com."}}

    def lrrs(kw: dict[str, Any]) -> dict[str, Any]:
        return {"ResourceRecordSets": list(state["records"]), "IsTruncated": False}

    def change(kw: dict[str, Any]) -> dict[str, Any]:
        ch = kw["ChangeBatch"]["Changes"][0]
        rrs = ch["ResourceRecordSet"]
        state["records"] = [r for r in state["records"] if (r["Name"], r["Type"], r.get("SetIdentifier")) != (rrs["Name"], rrs["Type"], rrs.get("SetIdentifier"))]
        if ch["Action"] == "UPSERT":
            state["records"].append(rrs)
        return {"ChangeInfo": {"Id": "/change/C1", "Status": "INSYNC"}}

    r53 = FakeClient("route53", {"get_hosted_zone": zone, "list_resource_record_sets": lrrs, "change_resource_record_sets": change})
    adapter = _Exec({"route53": r53})
    ctx, binding = _ctx(adapter, ZONE)
    desired = Route53RecordConfiguration(kind="route53_record", action="upsert", name="_acme.example.com.", record_type="CNAME", ttl=300, values=["_x.acm-validations.aws."])
    plan = await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, "test", desired_configuration=desired)
    assert plan.executor == "aws_change" and plan.health_checks == ["aws_configuration_matches"] and plan.rollback["supported"] is False
    assert plan.provider_mutations[0]["before"]["present"] is False and plan.locks == [f"aws:{ACCOUNT}:route53_zone:_acme.example.com."]
    receipt = await AwsChangeExecutor().execute(ctx, plan)
    assert receipt.ran == "ran" and receipt.health_checks[0].passed is True and receipt.after_state["present"] is True
    assert any(c[0] == "change_resource_record_sets" for c in r53.calls)
    # a second execution of the same plan is stale: the record now exists
    with pytest.raises(OpsError) as ei:
        await AwsChangeExecutor().execute(ctx, plan)
    assert ei.value.code == ErrorCode.PLAN_STALE


async def test_route53_delete_requires_exact_live_record_and_zone_name_match() -> None:
    live = {"Name": "mainnet.example.com.", "Type": "A", "SetIdentifier": "us west", "Weight": 0, "AliasTarget": {"HostedZoneId": "Z1H1FL5HABSF5", "DNSName": "dead-alb.us-west-2.elb.amazonaws.com.", "EvaluateTargetHealth": True}}
    r53 = FakeClient("route53", {"get_hosted_zone": {"HostedZone": {"Name": "example.com."}}, "list_resource_record_sets": {"ResourceRecordSets": [live], "IsTruncated": False}})
    adapter = _Exec({"route53": r53})
    ctx, binding = _ctx(adapter, ZONE)
    spec = ctx.catalog.service("aws-mgmt").spec
    wrong_weight = Route53RecordConfiguration(kind="route53_record", action="delete", name="mainnet.example.com.", record_type="A", set_identifier="us west", weight=5, alias={"hosted_zone_id": "Z1H1FL5HABSF5", "dns_name": "dead-alb.us-west-2.elb.amazonaws.com.", "evaluate_target_health": True})
    with pytest.raises(OpsError, match="exactly as it exists"):
        await AwsChangeExecutor().prepare(ctx, spec, binding, _op(), "configure", None, None, desired_configuration=wrong_weight)
    exact = wrong_weight.model_copy(update={"weight": 0})
    plan = await AwsChangeExecutor().prepare(ctx, spec, binding, _op(), "configure", None, None, desired_configuration=exact)
    assert plan.provider_mutations[0]["action"] == "DELETE"
    other_zone = FakeClient("route53", {"get_hosted_zone": {"HostedZone": {"Name": "other.com."}}})
    ctx2, binding2 = _ctx(_Exec({"route53": other_zone}), ZONE)
    with pytest.raises(OpsError, match="hosted zone name does not match"):
        await AwsChangeExecutor().prepare(ctx2, spec, binding2, _op(), "configure", None, None, desired_configuration=exact)


async def test_iam_credential_state_rejection_is_not_applied_and_uncertain_is_reconciled() -> None:
    keys = {"AccessKeyMetadata": [{"AccessKeyId": "AKIA4TUID66BRGOQTANX", "Status": "Active"}], "IsTruncated": False}
    denied = type("E", (Exception,), {})()
    denied.response = {"Error": {"Code": "AccessDenied"}}  # type: ignore[attr-defined]
    iam = FakeClient("iam", {"list_access_keys": keys, "update_access_key": denied})
    adapter = _Exec({"iam": iam})
    ctx, binding = _ctx(adapter, IAM_CREDS)
    desired = IamCredentialStateConfiguration(kind="iam_credential_state", user_name="terraform-bootstrap", credential_kind="access_key", credential_id="AKIA4TUID66BRGOQTANX", status="Inactive")
    plan = await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, None, desired_configuration=desired)
    receipt = await AwsChangeExecutor().execute(ctx, plan)
    assert receipt.ran == "not_started" and receipt.health_checks[0].passed is False and ctx.db.rows[-1]["result"]["status"] == "not_applied"  # type: ignore[attr-defined]
    # transport error with no confirmation: reconcile re-reads; the key is still Active -> outcome unknown, never resent
    boom = FakeClient("iam", {"list_access_keys": keys, "update_access_key": RuntimeError("socket closed")})
    ctx2, binding2 = _ctx(_Exec({"iam": boom}), IAM_CREDS)
    plan2 = await AwsChangeExecutor().prepare(ctx2, ctx2.catalog.service("aws-mgmt").spec, binding2, _op(), "configure", None, None, desired_configuration=desired)
    receipt2 = await AwsChangeExecutor().execute(ctx2, plan2)
    assert receipt2.ran == "uncertain" and sum(1 for c in boom.calls if c[0] == "update_access_key") == 1
    # success path
    ok_state = {"status": "Active"}
    ok = FakeClient("iam", {"list_access_keys": lambda kw: {"AccessKeyMetadata": [{"AccessKeyId": "AKIA4TUID66BRGOQTANX", "Status": ok_state["status"]}], "IsTruncated": False}, "update_access_key": lambda kw: ok_state.update(status=kw["Status"]) or {}})
    ctx3, binding3 = _ctx(_Exec({"iam": ok}), IAM_CREDS)
    plan3 = await AwsChangeExecutor().prepare(ctx3, ctx3.catalog.service("aws-mgmt").spec, binding3, _op(), "configure", None, None, desired_configuration=desired)
    receipt3 = await AwsChangeExecutor().execute(ctx3, plan3)
    assert receipt3.ran == "ran" and receipt3.health_checks[0].passed is True and receipt3.after_state["status"] == "Inactive"


async def test_iam_user_remove_exports_then_deletes_in_order() -> None:
    present = {"user": True}
    nosuch = type("E", (Exception,), {})()
    nosuch.response = {"Error": {"Code": "NoSuchEntity"}}  # type: ignore[attr-defined]
    ops: dict[str, Any] = {
        "get_user": lambda kw: {"User": {"UserId": "AIDA1", "Arn": f"arn:aws:iam::{ACCOUNT}:user/zac.yang"}} if present["user"] else nosuch,
        "list_attached_user_policies": {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/IAMUserChangePassword"}], "IsTruncated": False},
        "list_user_policies": {"PolicyNames": ["Inline1"], "IsTruncated": False},
        "get_user_policy": {"PolicyDocument": {"Version": "2012-10-17", "Statement": []}},
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIA4TUID66BSJVHISUV", "Status": "Active"}], "IsTruncated": False},
        "list_groups_for_user": {"Groups": [], "IsTruncated": False},
        "list_mfa_devices": {"MFADevices": [], "IsTruncated": False},
        "list_service_specific_credentials": {"ServiceSpecificCredentials": [{"ServiceSpecificCredentialId": "ACCASXH2SWMPIVLF24GIB"}]},
        "list_ssh_public_keys": {"SSHPublicKeys": [{"SSHPublicKeyId": "APKAEIBAERJR2EXAMPLE"}], "IsTruncated": False},
        "list_signing_certificates": {"Certificates": [], "IsTruncated": False},
        "delete_service_specific_credential": {}, "delete_ssh_public_key": {},
        "get_login_profile": {"LoginProfile": {"UserName": "zac.yang"}},
        "delete_access_key": {}, "delete_login_profile": {}, "delete_user_policy": {}, "detach_user_policy": {},
        "delete_user": lambda kw: present.update(user=False) or {},
    }
    iam = FakeClient("iam", ops)
    ctx, binding = _ctx(_Exec({"iam": iam}), IAM_USER)
    desired = IamUserRemoveConfiguration(kind="iam_user_remove", confirm_user_name="zac.yang")
    plan = await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, None, desired_configuration=desired)
    before = plan.provider_mutations[0]["before"]
    assert before["inline_policies"]["Inline1"]["Version"] == "2012-10-17" and before["login_profile"] is True
    receipt = await AwsChangeExecutor().execute(ctx, plan)
    assert receipt.ran == "ran" and receipt.health_checks[0].passed is True and receipt.after_state["present"] is False
    order = [c[0] for c in iam.calls if c[0].startswith(("delete_", "detach_"))]
    assert order == ["delete_access_key", "delete_service_specific_credential", "delete_ssh_public_key", "delete_login_profile", "delete_user_policy", "detach_user_policy", "delete_user"]
    # the plan's before-state is scrubbed, but dispatch used the real key id
    assert ("delete_access_key", {"UserName": "zac.yang", "AccessKeyId": "AKIA4TUID66BSJVHISUV"}) in iam.calls


async def test_identity_center_and_eks_removals_verify_absence() -> None:
    assignments = {"rows": [{"PrincipalType": "USER", "PrincipalId": PRINCIPAL}]}
    sso = FakeClient("sso-admin", {
        "list_account_assignments": lambda kw: {"AccountAssignments": list(assignments["rows"])},
        "delete_account_assignment": lambda kw: assignments.update(rows=[]) or {"AccountAssignmentDeletionStatus": {"RequestId": "r1", "Status": "SUCCEEDED"}},
    })
    ctx, binding = _ctx(_Exec({"sso-admin": sso}), IDC)
    desired = IdentityCenterAssignmentRemoveConfiguration(kind="identity_center_assignment_remove", target_account_id="222222222222", permission_set_arn=PS, principal_type="USER", principal_id=PRINCIPAL)
    plan = await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, None, desired_configuration=desired)
    receipt = await AwsChangeExecutor().execute(ctx, plan)
    assert receipt.ran == "ran" and receipt.health_checks[0].passed is True and "r1" in receipt.provider_operation_ids
    entries = {"rows": [f"arn:aws:iam::{ACCOUNT}:user/terraform-mainnet"]}
    eks = FakeClient("eks", {
        "list_access_entries": lambda kw: {"accessEntries": list(entries["rows"])},
        "list_associated_access_policies": {"associatedAccessPolicies": [{"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", "accessScope": {"type": "cluster"}}]},
        "delete_access_entry": lambda kw: entries.update(rows=[]) or {},
    })
    ctx2, binding2 = _ctx(_Exec({"eks": eks}), EKS)
    desired2 = EksAccessEntryRemoveConfiguration(kind="eks_access_entry_remove", principal_arn=f"arn:aws:iam::{ACCOUNT}:user/terraform-mainnet")
    plan2 = await AwsChangeExecutor().prepare(ctx2, ctx2.catalog.service("aws-mgmt").spec, binding2, _op(), "configure", None, None, desired_configuration=desired2)
    assert plan2.provider_mutations[0]["before"]["associated_access_policies"][0]["policyArn"].endswith("AmazonEKSClusterAdminPolicy")
    receipt2 = await AwsChangeExecutor().execute(ctx2, plan2)
    assert receipt2.ran == "ran" and receipt2.health_checks[0].passed is True
    # absent before prepare: refused, nothing dispatched
    with pytest.raises(OpsError, match="not present"):
        await AwsChangeExecutor().prepare(ctx2, ctx2.catalog.service("aws-mgmt").spec, binding2, _op(), "configure", None, None, desired_configuration=desired2)


async def test_wrong_account_or_missing_execution_credential_is_refused_before_any_read() -> None:
    r53 = FakeClient("route53", {})
    adapter = _Exec({"route53": r53}, account="999999999999")
    ctx, binding = _ctx(adapter, ZONE)
    desired = Route53RecordConfiguration(kind="route53_record", action="upsert", name="a.example.com.", record_type="A", ttl=60, values=["10.0.0.1"])
    with pytest.raises(OpsError, match="different account"):
        await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, None, desired_configuration=desired)
    assert r53.calls == []
    no_exec = _Exec({"route53": r53})
    no_exec.has_execution_credential = lambda: False  # type: ignore[method-assign]
    ctx2, binding2 = _ctx(no_exec, ZONE)
    with pytest.raises(OpsError, match="no execution credential"):
        await AwsChangeExecutor().prepare(ctx2, ctx2.catalog.service("aws-mgmt").spec, binding2, _op(), "configure", None, None, desired_configuration=desired)


async def test_reconcile_reports_not_applied_and_absence(tmp_path: Path) -> None:
    plan = ActionPlan(plan_id="p", plan_hash="h", service_id="aws-mgmt", binding_id="b", action="configure", environment="mgmt", executor="aws_change", mechanism="m", target={}, target_fingerprint="x",
                      provider_mutations=[{"op": "eks_access_entry_remove", "cluster_name": "network-api", "region": "us-east-1", "principal_arn": f"arn:aws:iam::{ACCOUNT}:user/terraform-mainnet"}], health_checks=["aws_configuration_matches"], unavailable_health_checks=[], timeout_seconds=30,
                      expected_disruption="", rollback={"supported": False}, dependencies=[], dependents=[], locks=["l"], preconditions=[], pre_reads=[], post_reads=[], notes=[], catalog_revision="r", implementation_version="v", prepared_by="p", prepared_at=__import__("local_ops.models", fromlist=["utcnow"]).utcnow(), expires_at=__import__("local_ops.models", fromlist=["utcnow"]).utcnow())
    eks = FakeClient("eks", {"list_access_entries": {"accessEntries": [f"arn:aws:iam::{ACCOUNT}:user/terraform-mainnet"]}, "list_associated_access_policies": {"associatedAccessPolicies": []}})
    ctx, _ = _ctx(_Exec({"eks": eks}), EKS)
    status, detail = await AwsChangeExecutor().reconcile(ctx, plan, [{"result": {"status": "not_applied"}}])
    assert status is ExecutionStatus.FAILED and detail["ran"] == "not_started"
    status, detail = await AwsChangeExecutor().reconcile(ctx, plan, [{"result": {"status": "uncertain"}}], uncertain_if_absent=True)
    assert status is ExecutionStatus.OUTCOME_UNKNOWN
    status, _ = await AwsChangeExecutor().reconcile(ctx, plan, [{"result": {"status": "uncertain"}}])
    assert status is ExecutionStatus.FAILED
    gone = FakeClient("eks", {"list_access_entries": {"accessEntries": []}})
    ctx2, _ = _ctx(_Exec({"eks": gone}), EKS)
    status, detail = await AwsChangeExecutor().reconcile(ctx2, plan, [{"result": {"status": "uncertain"}}])
    assert status is ExecutionStatus.SUCCEEDED and detail["checks"][0]["passed"] is True


async def test_polling_failure_after_an_accepted_change_is_uncertain_not_rejected() -> None:
    state: dict[str, Any] = {"records": []}
    denied = type("E", (Exception,), {})()
    denied.response = {"Error": {"Code": "AccessDenied"}}  # type: ignore[attr-defined]

    def change(kw: dict[str, Any]) -> dict[str, Any]:
        return {"ChangeInfo": {"Id": "/change/C9", "Status": "PENDING"}}  # accepted; not yet visible

    r53 = FakeClient("route53", {"get_hosted_zone": {"HostedZone": {"Name": "example.com."}}, "list_resource_record_sets": lambda kw: {"ResourceRecordSets": list(state["records"]), "IsTruncated": False}, "change_resource_record_sets": change, "get_change": denied})
    ctx, binding = _ctx(_Exec({"route53": r53}), ZONE)
    desired = Route53RecordConfiguration(kind="route53_record", action="upsert", name="_acme.example.com.", record_type="CNAME", ttl=300, values=["_x.acm-validations.aws."])
    plan = await AwsChangeExecutor().prepare(ctx, ctx.catalog.service("aws-mgmt").spec, binding, _op(), "configure", None, None, desired_configuration=desired)
    receipt = await AwsChangeExecutor().execute(ctx, plan)
    assert receipt.ran == "uncertain" and receipt.health_checks[0].passed is None
    assert ctx.db.rows[-1]["result"]["status"] == "accepted"  # type: ignore[attr-defined]
    assert sum(1 for c in r53.calls if c[0] == "change_resource_record_sets") == 1
