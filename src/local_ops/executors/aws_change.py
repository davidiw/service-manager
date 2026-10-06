"""Reviewed, bounded AWS changes (D35): Route53 records, IAM credential state, IAM user removal, Identity
Center assignment removal and EKS access-entry removal.

Same lifecycle as every executor: `prepare` reads the exact current state through the provider's execution
credential (after proving it resolves to the bound account), freezes it in an immutable plan; `execute`
re-reads, refuses a stale target, records the intent, performs one controlled change, re-reads and judges
`aws_configuration_matches`; `reconcile` re-reads after an uncertain dispatch and never resends. The
`AwsTarget` on the binding fences what may be touched; the typed configuration says what the change is."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from local_ops.aws_change_contracts import (
    AwsTarget,
    EksAccessEntryRemoveConfiguration,
    IamCredentialStateConfiguration,
    IamUserRemoveConfiguration,
    IdentityCenterAssignmentRemoveConfiguration,
    Route53RecordConfiguration,
    aws_configuration_matches_target,
)
from local_ops.catalog import Binding, OperationConfig, ServiceSpec
from local_ops.executors.base import intent_record, new_plan, receipt_from
from local_ops.models import (
    ActionPlan,
    ErrorCode,
    ExecutionStatus,
    HealthCheckResult,
    OpsError,
    Receipt,
    utcnow,
)
from local_ops.operations.base import OperationContext

CHECK = "aws_configuration_matches"
# Provider error codes that mean "nothing was applied"; anything else after dispatch is uncertain.
_NOT_APPLIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ValidationError", "ValidationException", "InvalidInput", "InvalidChangeBatch", "NoSuchHostedZone", "NoSuchEntity", "NoSuchEntityException", "ResourceNotFoundException", "ConflictException", "DeleteConflict", "InvalidParameterException"}
_MAX_PAGES = 50
_GLOBAL_REGION = "us-east-1"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(obj: Any) -> str:
    return hashlib.sha256(_canonical(obj).encode()).hexdigest()


def _error_code(exc: BaseException) -> str | None:
    inner = getattr(exc, "exc", exc)
    resp = getattr(inner, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code")
        return str(code) if code else None
    return None


class AwsChangeExecutor:
    name = "aws_change"

    # ------------------------------------------------------------------ scope
    def _adapter(self, ctx: OperationContext, binding: Binding) -> Any:
        adapter = ctx.providers.get(binding.provider_id)
        if adapter is None or getattr(adapter, "kind", None) != "aws":
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} does not reference an AWS provider")
        return adapter

    def _target(self, binding: Binding) -> AwsTarget:
        target = getattr(binding, "aws_target", None)
        if target is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} has no AWS target")
        return target

    async def _verify_account(self, adapter: Any, target: AwsTarget) -> dict[str, Any]:
        if not getattr(adapter, "has_execution_credential", lambda: False)():
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"provider {adapter.provider_id} has no execution credential; AWS changes never run through the read credential")
        ident = await adapter.verified_identity(execution=True)
        if not ident.get("approved"):
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"provider {adapter.provider_id} has no expected_account_id; refusing to change an unverified account")
        if str(ident.get("account")) != target.account_id:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "execution credential resolves to a different account than the bound AWS target", private_detail=f"target={target.account_id} actual={ident.get('account')}")
        return ident

    @staticmethod
    def _region(target: AwsTarget) -> str:
        return target.region or _GLOBAL_REGION

    # ------------------------------------------------------------------ provider I/O (bounded, metadata only)
    async def _pages(self, client: Any, op: str, key: str, **kw: Any) -> list[dict[str, Any]]:
        """Collect every item of a list operation. Raises if the provider's pagination does not terminate
        within the bound: a partial view never authorizes a change."""
        items: list[dict[str, Any]] = []
        token_in, token_out = ("NextToken", "NextToken")
        if op in ("list_resource_record_sets",):
            token_in, token_out = ("StartRecordName", "NextRecordName")
        elif op in ("list_attached_user_policies", "list_user_policies", "list_access_keys", "list_groups_for_user", "list_mfa_devices", "list_ssh_public_keys", "list_signing_certificates"):
            token_in, token_out = ("Marker", "Marker")
        token: Any = None
        for _ in range(_MAX_PAGES):
            args = dict(kw)
            if token is not None:
                args[token_in] = token
                if op == "list_resource_record_sets" and isinstance(token, dict):
                    args.update(token)
            resp = await getattr(client, op)(**args)
            items.extend(resp.get(key) or [])
            if op == "list_resource_record_sets":
                if not resp.get("IsTruncated"):
                    return items
                token = {"StartRecordName": resp.get("NextRecordName"), "StartRecordType": resp.get("NextRecordType"), **({"StartRecordIdentifier": resp["NextRecordIdentifier"]} if resp.get("NextRecordIdentifier") else {})}
                continue
            token = resp.get(token_out) if resp.get("IsTruncated", resp.get(token_out) is not None) else None
            if not token:
                return items
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"{op} did not terminate within {_MAX_PAGES} pages; refusing to act on a partial listing")

    @staticmethod
    def _record_key(r: dict[str, Any]) -> tuple[str, str, str | None]:
        return (str(r.get("Name", "")).lower(), str(r.get("Type", "")), r.get("SetIdentifier"))

    @staticmethod
    def _project_record(r: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"Name": str(r.get("Name", "")).lower(), "Type": r.get("Type")}
        for k in ("TTL", "SetIdentifier", "Weight"):
            if r.get(k) is not None:
                out[k] = r[k]
        if r.get("ResourceRecords"):
            out["ResourceRecords"] = [{"Value": x.get("Value")} for x in r["ResourceRecords"]]
        if r.get("AliasTarget"):
            a = r["AliasTarget"]
            out["AliasTarget"] = {"HostedZoneId": a.get("HostedZoneId"), "DNSName": str(a.get("DNSName", "")).lower(), "EvaluateTargetHealth": bool(a.get("EvaluateTargetHealth"))}
        return out

    async def _read(self, adapter: Any, target: AwsTarget, desired: Any) -> dict[str, Any]:
        """Exact current state of the one resource the change names, as a scrub-safe projection."""
        rt, region = target.resource_type, self._region(target)
        if isinstance(desired, Route53RecordConfiguration):
            async with adapter.execution_client("route53", region) as r53:
                zone = await r53.get_hosted_zone(Id=target.zone_id)
                zone_name = str((zone.get("HostedZone") or {}).get("Name", "")).lower()
                if zone_name != target.zone_name:
                    raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "hosted zone name does not match the bound AWS target", private_detail=f"expected={target.zone_name} actual={zone_name}")
                rows = await self._pages(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=target.zone_id, StartRecordName=desired.name, StartRecordType=desired.record_type, MaxItems="100")
            want = (desired.name, desired.record_type, desired.set_identifier)
            match = next((self._project_record(r) for r in rows if self._record_key(r) == want), None)
            return {"resource_type": rt, "zone_id": target.zone_id, "zone_name": zone_name, "present": match is not None, "record": match}
        if isinstance(desired, IamCredentialStateConfiguration):
            async with adapter.execution_client("iam", region) as iam:
                if desired.credential_kind == "access_key":
                    keys = await self._pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=desired.user_name)
                    found = next((k for k in keys if k.get("AccessKeyId") == desired.credential_id), None)
                else:
                    resp = await iam.list_service_specific_credentials(UserName=desired.user_name)
                    found = next((k for k in resp.get("ServiceSpecificCredentials") or [] if k.get("ServiceSpecificCredentialId") == desired.credential_id), None)
            return {"resource_type": rt, "user_name": desired.user_name, "credential_kind": desired.credential_kind, "credential_id": desired.credential_id, "present": found is not None, "status": found.get("Status") if found else None}
        if isinstance(desired, IamUserRemoveConfiguration):
            async with adapter.execution_client("iam", region) as iam:
                try:
                    user = (await iam.get_user(UserName=desired.confirm_user_name)).get("User") or {}
                except Exception as e:  # noqa: BLE001
                    if _error_code(e) in ("NoSuchEntity", "NoSuchEntityException"):
                        return {"resource_type": rt, "user_name": desired.confirm_user_name, "present": False}
                    raise
                attached = [p.get("PolicyArn") for p in await self._pages(iam, "list_attached_user_policies", "AttachedPolicies", UserName=desired.confirm_user_name)]
                inline_names = [str(n) for n in await self._pages(iam, "list_user_policies", "PolicyNames", UserName=desired.confirm_user_name)]
                inline = {}
                for n in inline_names:
                    doc = await iam.get_user_policy(UserName=desired.confirm_user_name, PolicyName=n)
                    inline[n] = doc.get("PolicyDocument")
                keys = [{"AccessKeyId": k.get("AccessKeyId"), "Status": k.get("Status")} for k in await self._pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=desired.confirm_user_name)]
                groups = [g.get("GroupName") for g in await self._pages(iam, "list_groups_for_user", "Groups", UserName=desired.confirm_user_name)]
                mfa = [m.get("SerialNumber") for m in await self._pages(iam, "list_mfa_devices", "MFADevices", UserName=desired.confirm_user_name)]
                # AWS refuses DeleteUser while any of these exist (DeleteConflict); read them so they are removed first.
                ssc = [c.get("ServiceSpecificCredentialId") for c in (await iam.list_service_specific_credentials(UserName=desired.confirm_user_name)).get("ServiceSpecificCredentials") or []]
                ssh = [k.get("SSHPublicKeyId") for k in await self._pages(iam, "list_ssh_public_keys", "SSHPublicKeys", UserName=desired.confirm_user_name)]
                certs = [c.get("CertificateId") for c in await self._pages(iam, "list_signing_certificates", "Certificates", UserName=desired.confirm_user_name)]
                try:
                    await iam.get_login_profile(UserName=desired.confirm_user_name)
                    login = True
                except Exception as e:  # noqa: BLE001
                    if _error_code(e) not in ("NoSuchEntity", "NoSuchEntityException"):
                        raise
                    login = False
            return {"resource_type": rt, "user_name": desired.confirm_user_name, "present": True, "user_id": user.get("UserId"), "arn": user.get("Arn"), "attached_policy_arns": attached, "inline_policies": inline, "access_keys": keys, "groups": groups, "mfa_devices": mfa, "service_specific_credentials": ssc, "ssh_public_keys": ssh, "signing_certificates": certs, "login_profile": login}
        if isinstance(desired, IdentityCenterAssignmentRemoveConfiguration):
            async with adapter.execution_client("sso-admin", region) as sso:
                rows = await self._pages(sso, "list_account_assignments", "AccountAssignments", InstanceArn=target.instance_arn, AccountId=desired.target_account_id, PermissionSetArn=desired.permission_set_arn)
            present = any(a.get("PrincipalType") == desired.principal_type and a.get("PrincipalId") == desired.principal_id for a in rows)
            return {"resource_type": rt, "instance_arn": target.instance_arn, "target_account_id": desired.target_account_id, "permission_set_arn": desired.permission_set_arn, "principal_type": desired.principal_type, "principal_id": desired.principal_id, "present": present}
        if isinstance(desired, EksAccessEntryRemoveConfiguration):
            async with adapter.execution_client("eks", region) as eks:
                entries = await self._pages(eks, "list_access_entries", "accessEntries", clusterName=target.cluster_name)
                present = desired.principal_arn in [str(e) for e in entries]
                policies: list[dict[str, Any]] = []
                if present:
                    for pol in await self._pages(eks, "list_associated_access_policies", "associatedAccessPolicies", clusterName=target.cluster_name, principalArn=desired.principal_arn):
                        policies.append({"policyArn": pol.get("policyArn"), "accessScope": pol.get("accessScope")})
            return {"resource_type": rt, "cluster_name": target.cluster_name, "region": region, "principal_arn": desired.principal_arn, "present": present, "associated_access_policies": policies}
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported AWS change")

    # ------------------------------------------------------------------ plan shape
    def _mutation(self, target: AwsTarget, desired: Any, current: dict[str, Any]) -> dict[str, Any]:
        if isinstance(desired, Route53RecordConfiguration):
            if desired.action == "delete" and not current["present"]:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "record to delete is not present")
            rrs: dict[str, Any] = {"Name": desired.name, "Type": desired.record_type}
            if desired.set_identifier is not None:
                rrs["SetIdentifier"] = desired.set_identifier
                rrs["Weight"] = desired.weight
            if desired.values is not None:
                rrs["TTL"] = desired.ttl
                rrs["ResourceRecords"] = [{"Value": v} for v in desired.values]
            else:
                assert desired.alias is not None
                rrs["AliasTarget"] = {"HostedZoneId": desired.alias.hosted_zone_id, "DNSName": desired.alias.dns_name, "EvaluateTargetHealth": desired.alias.evaluate_target_health}
            if desired.action == "delete":
                live = current["record"]
                if self._project_record(rrs) != live:
                    raise OpsError(ErrorCode.INVALID_ARGUMENT, "a delete must name the record exactly as it exists (Route53 refuses otherwise)")
            return {"op": "route53_change", "zone_id": target.zone_id, "action": desired.action.upper(), "record": rrs}
        if isinstance(desired, IamCredentialStateConfiguration):
            if not current["present"]:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "credential is not present on the user")
            return {"op": "iam_credential_state", "user_name": desired.user_name, "credential_kind": desired.credential_kind, "credential_id": desired.credential_id, "status": desired.status, "status_before": current["status"]}
        if isinstance(desired, IamUserRemoveConfiguration):
            if not current["present"]:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "IAM user is not present")
            return {"op": "iam_user_remove", "user_name": desired.confirm_user_name, "steps": ["delete access keys", "delete service-specific credentials", "delete SSH public keys", "delete signing certificates", "delete login profile", "deactivate and delete MFA devices", "delete inline policies", "detach managed policies", "remove from groups", "delete user"]}
        if isinstance(desired, IdentityCenterAssignmentRemoveConfiguration):
            if not current["present"]:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "account assignment is not present")
            return {"op": "identity_center_assignment_remove", "instance_arn": target.instance_arn, "target_account_id": desired.target_account_id, "permission_set_arn": desired.permission_set_arn, "principal_type": desired.principal_type, "principal_id": desired.principal_id}
        if isinstance(desired, EksAccessEntryRemoveConfiguration):
            if not current["present"]:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "access entry is not present on the cluster")
            return {"op": "eks_access_entry_remove", "cluster_name": target.cluster_name, "region": self._region(target), "principal_arn": desired.principal_arn}
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported AWS change")

    @staticmethod
    def _matches(mutation: dict[str, Any], after: dict[str, Any]) -> bool:
        op = mutation["op"]
        if op == "route53_change":
            if mutation["action"] == "DELETE":
                return not after["present"]
            return after["present"] and after["record"] == AwsChangeExecutor._project_record(mutation["record"])
        if op == "iam_credential_state":
            return after["present"] and after["status"] == mutation["status"]
        if op in ("iam_user_remove", "identity_center_assignment_remove", "eks_access_entry_remove"):
            return not after["present"]
        return False

    @staticmethod
    def _lock(target: AwsTarget, mutation: dict[str, Any]) -> str:
        ident = mutation.get("record", {}).get("Name") or mutation.get("credential_id") or mutation.get("user_name") or mutation.get("principal_id") or mutation.get("principal_arn") or ""
        return f"aws:{target.account_id}:{target.resource_type}:{ident}"

    @staticmethod
    def _reverse_note(mutation: dict[str, Any]) -> str:
        op = mutation["op"]
        if op == "route53_change":
            return "reversal is a separate reviewed route53_record plan: DELETE what was upserted, or re-create the deleted record from the retained before-state"
        if op == "iam_credential_state":
            return f"reversal is a separate reviewed iam_credential_state plan setting status back to {mutation['status_before']}"
        if op == "iam_user_remove":
            return "no reversal: the user, keys and login profile are gone; policies are retained in the before-state for a deliberate re-creation"
        if op == "identity_center_assignment_remove":
            return "reversal is a new assignment through Identity Center, a separate reviewed change"
        return "reversal is a new access entry with the retained associated policies, a separate reviewed change"

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None, *, desired_configuration: Any = None) -> ActionPlan:
        if action != "configure" or desired_artifact is not None or desired_configuration is None:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "AWS changes require a typed desired_configuration and no artifact")
        target = self._target(binding)
        if not aws_configuration_matches_target(desired_configuration, target):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "desired_configuration does not match the bound AWS target")
        adapter = self._adapter(ctx, binding)
        ident = await self._verify_account(adapter, target)
        current = await self._read(adapter, target, desired_configuration)
        mutation = self._mutation(target, desired_configuration, current)
        fp = _fingerprint(current)
        plan_target = {"provider_id": binding.provider_id, "account_id": target.account_id, "resource_type": target.resource_type, "region": self._region(target), "zone_id": target.zone_id, "zone_name": target.zone_name, "user_name": target.user_name, "instance_arn": target.instance_arn, "cluster_name": target.cluster_name, "execution_principal": ident.get("arn")}
        disruption = {"route53_change": "DNS answer changes after propagation; no workload restarts", "iam_credential_state": "callers using this credential start failing (Inactive) or succeeding (Active) immediately", "iam_user_remove": "every credential of the user stops working immediately", "identity_center_assignment_remove": "the principal loses the permission set on the account at next session refresh", "eks_access_entry_remove": "the principal loses Kubernetes API access to the cluster immediately"}[mutation["op"]]
        return new_plan(ctx, service_id=service.id, binding_id=binding.id, action="configure", environment=binding.environment, executor=self.name, mechanism=f"AWS {mutation['op']} through the execution credential", target=plan_target, target_fingerprint=fp, current_artifact=None, requested_artifact=None, provider_mutations=[{**mutation, "before": ctx.scrub(current)}], health_checks=[CHECK], unavailable_health_checks=[], timeout_seconds=op.readiness_timeout_seconds, expected_disruption=disruption, rollback={"supported": False, "note": self._reverse_note(mutation)}, dependencies=service.depends_on, dependents=ctx.catalog.dependents_of(service.id), locks=[self._lock(target, mutation)], preconditions=["execution credential resolves in the bound account", f"current state fingerprint == {fp[:16]}"], pre_reads=["execution account identity", "exact current resource state"], post_reads=["exact resource state re-read"], notes=["one controlled change; uncertain provider outcomes are reconciled by re-reading, never resent"])

    # ------------------------------------------------------------------ dispatch
    async def _dispatch(self, adapter: Any, target: AwsTarget, mutation: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        region, op = self._region(target), mutation["op"]
        if op == "route53_change":
            async with adapter.execution_client("route53", region) as r53:
                resp = await r53.change_resource_record_sets(HostedZoneId=mutation["zone_id"], ChangeBatch={"Changes": [{"Action": mutation["action"], "ResourceRecordSet": mutation["record"]}]})
                info = resp.get("ChangeInfo") or {}
                change_id, status = info.get("Id"), info.get("Status")
                # The change is accepted from here on: a polling failure means "unconfirmed", never "not applied".
                try:
                    deadline = asyncio.get_running_loop().time() + min(timeout_seconds, 300)
                    while status == "PENDING" and change_id and asyncio.get_running_loop().time() < deadline:
                        await asyncio.sleep(5)
                        status = ((await r53.get_change(Id=change_id)).get("ChangeInfo") or {}).get("Status")
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    status = "unconfirmed"
            return {"change_id": change_id, "status": status}
        if op == "iam_credential_state":
            async with adapter.execution_client("iam", region) as iam:
                if mutation["credential_kind"] == "access_key":
                    await iam.update_access_key(UserName=mutation["user_name"], AccessKeyId=mutation["credential_id"], Status=mutation["status"])
                else:
                    await iam.update_service_specific_credential(UserName=mutation["user_name"], ServiceSpecificCredentialId=mutation["credential_id"], Status=mutation["status"])
            return {"applied": True}
        if op == "iam_user_remove":
            u, before = mutation["user_name"], mutation["before"]
            done: list[str] = []
            async with adapter.execution_client("iam", region) as iam:
                for k in before.get("access_keys") or []:
                    await iam.delete_access_key(UserName=u, AccessKeyId=k["AccessKeyId"])
                done.append("access_keys")
                for cid in before.get("service_specific_credentials") or []:
                    await iam.delete_service_specific_credential(UserName=u, ServiceSpecificCredentialId=cid)
                done.append("service_specific_credentials")
                for kid in before.get("ssh_public_keys") or []:
                    await iam.delete_ssh_public_key(UserName=u, SSHPublicKeyId=kid)
                done.append("ssh_public_keys")
                for cert in before.get("signing_certificates") or []:
                    await iam.delete_signing_certificate(UserName=u, CertificateId=cert)
                done.append("signing_certificates")
                if before.get("login_profile"):
                    await iam.delete_login_profile(UserName=u)
                done.append("login_profile")
                for serial in before.get("mfa_devices") or []:
                    await iam.deactivate_mfa_device(UserName=u, SerialNumber=serial)
                    if str(serial).startswith("arn:aws:iam::"):
                        await iam.delete_virtual_mfa_device(SerialNumber=serial)
                done.append("mfa_devices")
                for name in (before.get("inline_policies") or {}):
                    await iam.delete_user_policy(UserName=u, PolicyName=name)
                done.append("inline_policies")
                for arn in before.get("attached_policy_arns") or []:
                    await iam.detach_user_policy(UserName=u, PolicyArn=arn)
                done.append("attached_policies")
                for g in before.get("groups") or []:
                    await iam.remove_user_from_group(UserName=u, GroupName=g)
                done.append("groups")
                await iam.delete_user(UserName=u)
                done.append("user")
            return {"steps_completed": done}
        if op == "identity_center_assignment_remove":
            async with adapter.execution_client("sso-admin", region) as sso:
                resp = await sso.delete_account_assignment(InstanceArn=mutation["instance_arn"], TargetId=mutation["target_account_id"], TargetType="AWS_ACCOUNT", PermissionSetArn=mutation["permission_set_arn"], PrincipalType=mutation["principal_type"], PrincipalId=mutation["principal_id"])
                st = resp.get("AccountAssignmentDeletionStatus") or {}
                req_id, status = st.get("RequestId"), st.get("Status")
                try:
                    deadline = asyncio.get_running_loop().time() + min(timeout_seconds, 300)
                    while status == "IN_PROGRESS" and req_id and asyncio.get_running_loop().time() < deadline:
                        await asyncio.sleep(3)
                        status = ((await sso.describe_account_assignment_deletion_status(InstanceArn=mutation["instance_arn"], AccountAssignmentDeletionRequestId=req_id)).get("AccountAssignmentDeletionStatus") or {}).get("Status")
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    status = "unconfirmed"
            return {"request_id": req_id, "status": status}
        if op == "eks_access_entry_remove":
            async with adapter.execution_client("eks", region) as eks:
                await eks.delete_access_entry(clusterName=mutation["cluster_name"], principalArn=mutation["principal_arn"])
            return {"applied": True}
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported AWS change")

    def _desired_from_plan(self, plan: ActionPlan) -> Any:
        """Rebuild the typed configuration from the frozen mutation so execute/reconcile read the same resource."""
        m = plan.provider_mutations[0]
        op = m["op"]
        if op == "route53_change":
            r = m["record"]
            alias = r.get("AliasTarget")
            return Route53RecordConfiguration(kind="route53_record", action=str(m["action"]).lower(), name=r["Name"], record_type=r["Type"], ttl=r.get("TTL"), values=[x["Value"] for x in r["ResourceRecords"]] if r.get("ResourceRecords") else None, alias={"hosted_zone_id": alias["HostedZoneId"], "dns_name": alias["DNSName"], "evaluate_target_health": alias["EvaluateTargetHealth"]} if alias else None, set_identifier=r.get("SetIdentifier"), weight=r.get("Weight"))  # type: ignore[arg-type]
        if op == "iam_credential_state":
            return IamCredentialStateConfiguration(kind="iam_credential_state", user_name=m["user_name"], credential_kind=m["credential_kind"], credential_id=m["credential_id"], status=m["status"])
        if op == "iam_user_remove":
            return IamUserRemoveConfiguration(kind="iam_user_remove", confirm_user_name=m["user_name"])
        if op == "identity_center_assignment_remove":
            return IdentityCenterAssignmentRemoveConfiguration(kind="identity_center_assignment_remove", target_account_id=m["target_account_id"], permission_set_arn=m["permission_set_arn"], principal_type=m["principal_type"], principal_id=m["principal_id"])
        return EksAccessEntryRemoveConfiguration(kind="eks_access_entry_remove", principal_arn=m["principal_arn"])

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt:
        started = utcnow()
        doc = ctx.catalog.service(plan.service_id)
        binding = doc.spec.binding(plan.binding_id) if doc else None
        if binding is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "binding no longer exists")
        target, adapter = self._target(binding), self._adapter(ctx, binding)
        await self._verify_account(adapter, target)
        desired = self._desired_from_plan(plan)
        mutation = plan.provider_mutations[0]
        current = await self._read(adapter, target, desired)
        if _fingerprint(current) != plan.target_fingerprint:
            raise OpsError(ErrorCode.PLAN_STALE, "AWS resource changed since the plan was prepared; prepare a new plan", private_detail=f"plan={plan.target_fingerprint[:16]} live={_fingerprint(current)[:16]}")
        before = ctx.scrub(current)
        intent_id = await ctx.record_intent("dispatching", plan.locks[0], f"AWS {mutation['op']}", intent_record(plan, {k: v for k, v in mutation.items() if k != "before"}))
        dispatched = utcnow()
        try:
            # Dispatch from the fresh, unscrubbed re-read (its fingerprint equals the plan's), never from the
            # plan's scrubbed before-state: scrubbing redacts identifiers such as access-key ids.
            result = await self._dispatch(adapter, target, {**mutation, "before": current}, plan.timeout_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            code = _error_code(exc)
            if code in _NOT_APPLIED and mutation["op"] != "iam_user_remove":
                await ctx.db.complete_intent(intent_id, {"status": "not_applied", "error": code})
                return receipt_from(plan, ctx, before=before, after=before, before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="not_started", outcome=f"AWS rejected the change before applying it ({code})", checks=[HealthCheckResult(check_id=CHECK, kind=CHECK, passed=False, detail=f"provider rejected the change: {code}")])
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "error": code or type(exc).__name__})
            status, detail = await self.reconcile(ctx, plan, await ctx.db.intents(ctx.request_id), uncertain_if_absent=True)
            return receipt_from(plan, ctx, before=before, after=detail.get("observed", {}), before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="ran" if status == ExecutionStatus.SUCCEEDED else "uncertain", outcome=detail.get("summary", "AWS change outcome unknown"), checks=[HealthCheckResult.model_validate(c) for c in detail.get("checks", [])], notes=["change was not replayed after an uncertain provider response"])
        await ctx.db.complete_intent(intent_id, {**{("provider_status" if k == "status" else k): v for k, v in result.items() if isinstance(v, (str, int, bool, list))}, "status": "accepted"})
        after = await self._read(adapter, target, desired)
        passed = self._matches(mutation, after)
        unfinished = result.get("status") in ("PENDING", "IN_PROGRESS", "unconfirmed")
        ids = [intent_id] + [str(v) for k, v in result.items() if k in ("change_id", "request_id") and v]
        if not passed and unfinished:
            # Accepted by AWS but not yet visible: the outcome is unknown, not failed; reconcile later by re-reading.
            check = HealthCheckResult(check_id=CHECK, kind=CHECK, passed=None, detail=f"change accepted but completion was not confirmed ({result.get('status')})", observed=ctx.scrub(after))
            return receipt_from(plan, ctx, before=before, after=ctx.scrub(after), before_artifact=None, after_artifact=None, provider_ids=ids, started_at=started, dispatched_at=dispatched, ran="uncertain", outcome="AWS accepted the change; completion not yet confirmed", checks=[check], notes=["reconcile by re-reading; the change is never resent"])
        check = HealthCheckResult(check_id=CHECK, kind=CHECK, passed=passed, detail="resource state matches the reviewed change" if passed else "resource state does not match the reviewed change after dispatch", observed=ctx.scrub(after))
        return receipt_from(plan, ctx, before=before, after=ctx.scrub(after), before_artifact=None, after_artifact=None, provider_ids=ids, started_at=started, dispatched_at=dispatched, ran="ran", outcome="AWS change verified" if passed else "AWS change verification failed", checks=[check])

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]:
        mutation = plan.provider_mutations[0]
        if any(((i.get("result") or {}).get("status") == "not_applied") for i in intents):
            return ExecutionStatus.FAILED, {"summary": "provider definitively rejected the change before applying it", "observed": {}, "checks": [], "ran": "not_started"}
        try:
            doc = ctx.catalog.service(plan.service_id)
            binding = doc.spec.binding(plan.binding_id) if doc else None
            if binding is None:
                return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "binding no longer exists", "observed": {}}
            target, adapter = self._target(binding), self._adapter(ctx, binding)
            await self._verify_account(adapter, target)
            after = await self._read(adapter, target, self._desired_from_plan(plan))
        except Exception as exc:  # reconciliation remains read-only  # noqa: BLE001
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": f"resource could not be inspected: {type(exc).__name__}", "observed": {}}
        applied = self._matches(mutation, after)
        observed = ctx.scrub(after)
        if not applied:
            return (ExecutionStatus.OUTCOME_UNKNOWN if uncertain_if_absent else ExecutionStatus.FAILED), {"summary": "resource does not show the change after interrupted dispatch", "observed": observed, "checks": [{"check_id": CHECK, "kind": CHECK, "passed": False, "detail": "state does not match the reviewed change"}]}
        return ExecutionStatus.SUCCEEDED, {"summary": "resource shows the change after interrupted dispatch", "observed": observed, "checks": [{"check_id": CHECK, "kind": CHECK, "passed": True, "detail": "state matches the reviewed change"}]}
