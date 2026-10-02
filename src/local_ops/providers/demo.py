"""In-process demo provider.

It is explicitly a fixture source: every resource type is prefixed `demo/` and every result carries
`fixture: true`. It exists so the review/disclosure pipeline, discovery matching and the investigation
rules can be exercised end to end without any live credential. It never masquerades as a live provider.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, UnavailableScope, iso, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    SupportedOperation,
)

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext

DEMO_ACCOUNT = "000000000000"
DEMO_REGION = "local-1"


def demo_audit_events(scenario: str, base: datetime | None = None) -> list[dict[str, Any]]:
    """Deterministic CloudTrail-shaped events. `suspicious` includes activity by a departed identity,
    credential creation, trust-policy change, logging disablement, a deployment outside the recorded
    mechanism and a failed-auth burst followed by success. `benign` contains lookalikes."""
    t0 = base or datetime(2026, 9, 30, 10, 0, 0, tzinfo=utcnow().tzinfo)

    def ev(minute: int, name: str, actor: str, *, actor_type: str = "IAMUser", resource: str | None = None, outcome: str = "success", ip: str = "203.0.113.10", ua: str = "aws-cli/2.0", extra: dict[str, Any] | None = None, session: str | None = None) -> dict[str, Any]:
        at = t0 + timedelta(minutes=minute)
        return {
            "eventID": f"evt-{scenario}-{minute:04d}-{name}", "eventName": name, "eventTime": iso(at), "eventSource": "iam.amazonaws.com" if name in ("CreateAccessKey", "UpdateAssumeRolePolicy", "AttachUserPolicy", "CreateUser", "DeleteUser", "CreateLoginProfile") else "cloudtrail.amazonaws.com" if name in ("StopLogging", "DeleteTrail", "UpdateTrail") else "eks.amazonaws.com" if name.startswith("Eks") else "signin.amazonaws.com" if name == "ConsoleLogin" else "sts.amazonaws.com",
            "userIdentity": {"type": actor_type, "userName": actor, "arn": f"arn:aws:iam::{DEMO_ACCOUNT}:user/{actor}" if actor_type == "IAMUser" else f"arn:aws:sts::{DEMO_ACCOUNT}:assumed-role/{actor}", "sessionContext": {"sessionIssuer": {"userName": session}} if session else None},
            "sourceIPAddress": ip, "userAgent": ua, "errorCode": None if outcome == "success" else outcome, "requestParameters": extra or {}, "resources": [{"ARN": resource}] if resource else [], "awsRegion": DEMO_REGION, "recipientAccountId": DEMO_ACCOUNT,
        }

    if scenario == "benign":
        return [
            ev(0, "DescribeInstances", "alice", resource=None),
            ev(5, "ConsoleLogin", "alice", actor_type="IAMUser", ip="198.51.100.7", ua="Mozilla/5.0"),
            ev(9, "ConsoleLogin", "bob", outcome="Failed authentication", ip="198.51.100.9"),
            ev(12, "ConsoleLogin", "bob", ip="198.51.100.9"),
            ev(30, "CreateAccessKey", "ci-deployer", resource=f"arn:aws:iam::{DEMO_ACCOUNT}:user/ci-deployer", extra={"userName": "ci-deployer", "note": "scheduled rotation"}),
            ev(45, "UpdateTrail", "alice", resource=f"arn:aws:cloudtrail:{DEMO_REGION}:{DEMO_ACCOUNT}:trail/main", extra={"name": "main", "isMultiRegionTrail": True}),
            ev(60, "EksDescribeCluster", "alice", resource=f"arn:aws:eks:{DEMO_REGION}:{DEMO_ACCOUNT}:cluster/demo-cluster"),
        ]
    return [
        ev(0, "DescribeInstances", "alice"),
        ev(3, "ConsoleLogin", "carol-departed", outcome="Failed authentication", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(4, "ConsoleLogin", "carol-departed", outcome="Failed authentication", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(5, "ConsoleLogin", "carol-departed", outcome="Failed authentication", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(6, "ConsoleLogin", "carol-departed", outcome="Failed authentication", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(7, "ConsoleLogin", "carol-departed", outcome="Failed authentication", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(8, "ConsoleLogin", "carol-departed", ip="192.0.2.44", ua="Mozilla/5.0"),
        ev(10, "CreateAccessKey", "carol-departed", resource=f"arn:aws:iam::{DEMO_ACCOUNT}:user/svc-backup", ip="192.0.2.44", extra={"userName": "svc-backup"}),
        ev(12, "UpdateAssumeRolePolicy", "carol-departed", resource=f"arn:aws:iam::{DEMO_ACCOUNT}:role/eks-admin", ip="192.0.2.44", extra={"roleName": "eks-admin", "policyDocument": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\"}]}"}),
        ev(14, "AttachUserPolicy", "carol-departed", resource=f"arn:aws:iam::{DEMO_ACCOUNT}:user/svc-backup", ip="192.0.2.44", extra={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "svc-backup"}),
        ev(16, "StopLogging", "carol-departed", resource=f"arn:aws:cloudtrail:{DEMO_REGION}:{DEMO_ACCOUNT}:trail/main", ip="192.0.2.44", extra={"name": "main"}),
        ev(20, "AssumeRole", "eks-admin", actor_type="AssumedRole", resource=f"arn:aws:iam::{DEMO_ACCOUNT}:role/eks-admin", ip="192.0.2.44", session="svc-backup"),
        ev(25, "EksDescribeCluster", "eks-admin", actor_type="AssumedRole", resource=f"arn:aws:eks:{DEMO_REGION}:{DEMO_ACCOUNT}:cluster/demo-cluster", ip="192.0.2.44", session="svc-backup"),
        ev(40, "DescribeInstances", "alice"),
    ]


def demo_kube_audit_events(scenario: str, base: datetime | None = None) -> list[dict[str, Any]]:
    t0 = base or datetime(2026, 9, 30, 10, 0, 0, tzinfo=utcnow().tzinfo)
    if scenario == "benign":
        return [{"auditID": "k8s-b-1", "verb": "get", "user": {"username": "alice"}, "objectRef": {"resource": "pods", "namespace": "demo"}, "requestReceivedTimestamp": iso(t0 + timedelta(minutes=2)), "sourceIPs": ["198.51.100.7"], "responseStatus": {"code": 200}}]
    return [
        {"auditID": "k8s-s-1", "verb": "patch", "user": {"username": "system:serviceaccount:kube-system:eks-admin-sa", "groups": ["system:masters"]}, "objectRef": {"resource": "deployments", "namespace": "demo", "name": "demo-app"}, "requestReceivedTimestamp": iso(t0 + timedelta(minutes=27)), "sourceIPs": ["192.0.2.44"], "responseStatus": {"code": 200}, "requestObject": {"spec": {"template": {"spec": {"containers": [{"name": "app", "image": "registry.example.invalid/unknown/miner:latest"}]}}}}},
        {"auditID": "k8s-s-2", "verb": "get", "user": {"username": "system:serviceaccount:kube-system:eks-admin-sa"}, "objectRef": {"resource": "secrets", "namespace": "demo", "name": "demo-app-credentials"}, "requestReceivedTimestamp": iso(t0 + timedelta(minutes=28)), "sourceIPs": ["192.0.2.44"], "responseStatus": {"code": 200}},
        {"auditID": "k8s-s-3", "verb": "create", "user": {"username": "system:serviceaccount:kube-system:eks-admin-sa"}, "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "demo", "name": "demo-app-7d9f-abcde"}, "requestReceivedTimestamp": iso(t0 + timedelta(minutes=29)), "sourceIPs": ["192.0.2.44"], "responseStatus": {"code": 101}},
        {"auditID": "k8s-s-4", "verb": "create", "user": {"username": "system:serviceaccount:kube-system:eks-admin-sa"}, "objectRef": {"resource": "clusterrolebindings", "name": "backdoor-admin"}, "requestReceivedTimestamp": iso(t0 + timedelta(minutes=30)), "sourceIPs": ["192.0.2.44"], "responseStatus": {"code": 201}},
    ]


def demo_github_events(scenario: str, base: datetime | None = None) -> list[dict[str, Any]]:
    t0 = base or datetime(2026, 9, 30, 10, 0, 0, tzinfo=utcnow().tzinfo)
    if scenario == "benign":
        return [{"@timestamp": int((t0 + timedelta(minutes=15)).timestamp() * 1000), "action": "workflows.completed_workflow_run", "actor": "alice", "repo": "example/demo-app", "workflow_run_id": 100, "conclusion": "success", "head_sha": "abc123"}]
    return [
        {"@timestamp": int((t0 + timedelta(minutes=22)).timestamp() * 1000), "action": "repo.remove_branch_protection", "actor": "carol-departed", "repo": "example/demo-app", "actor_ip": "192.0.2.44"},
        {"@timestamp": int((t0 + timedelta(minutes=23)).timestamp() * 1000), "action": "workflows.created_workflow", "actor": "carol-departed", "repo": "example/demo-app", "workflow": ".github/workflows/deploy-hotfix.yml", "actor_ip": "192.0.2.44"},
        {"@timestamp": int((t0 + timedelta(minutes=24)).timestamp() * 1000), "action": "workflows.completed_workflow_run", "actor": "carol-departed", "repo": "example/demo-app", "workflow_run_id": 101, "conclusion": "success", "head_sha": "deadbeef"},
    ]


def demo_guardduty_findings(scenario: str) -> list[dict[str, Any]]:
    if scenario == "benign":
        return []
    return [{"Id": "gd-1", "Type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", "Severity": 5.0, "Title": "Console login from unusual location", "Resource": {"ResourceType": "AccessKey", "AccessKeyDetails": {"UserName": "carol-departed"}}, "Service": {"Action": {"ActionType": "AWS_API_CALL"}, "Count": 1}, "UpdatedAt": "2026-09-30T10:09:00Z", "Region": DEMO_REGION}]


class DemoProvider:
    kind = "demo"

    def __init__(self, config: ProviderConfig, server: ServerConfig):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.calls: list[dict[str, Any]] = []
        self.simulate_delay: float = 0.0
        self.fail_next: bool = False

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=[
            SupportedOperation(name="discover", effect=Effect.READ, description="Fixture cloud account with an EKS cluster, EC2, RDS, ECR and DNS resources.", limitations=["fixture data"]),
            SupportedOperation(name="cloudtrail_events", effect=Effect.READ, description="Fixture CloudTrail-shaped events (scenario=benign|suspicious).", provider_side_filters=["scenario"], local_filters=["event_names", "actors", "time_range"], limitations=["fixture data"]),
            SupportedOperation(name="kubernetes_audit", effect=Effect.READ, description="Fixture Kubernetes audit log events.", limitations=["fixture data"]),
            SupportedOperation(name="github_audit", effect=Effect.READ, description="Fixture GitHub audit-log events.", limitations=["fixture data"]),
            SupportedOperation(name="guardduty_findings", effect=Effect.READ, description="Fixture GuardDuty findings.", limitations=["fixture data"]),
            SupportedOperation(name="demo_logs", effect=Effect.READ, description="Fixture application logs including secret-shaped strings for sanitizer tests.", limitations=["fixture data"]),
        ], required_credentials=[], credential_configured=True, limitations=["All results are fixtures labeled fixture=true. Never evidence about a live system."])

    async def check_availability(self, *, live: bool = False) -> Availability:
        return Availability(available=True, reason="fixture", detail="in-process fixture provider", identity={"account": DEMO_ACCOUNT, "fixture": True}, checked_live=live)

    async def _maybe_slow(self) -> None:
        if self.simulate_delay:
            await asyncio.sleep(self.simulate_delay)
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated provider failure (token=secret-should-not-leak-AKIAIOSFODNN7EXAMPLE)")

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        self.calls.append({"op": "discover", "scope": scope.model_dump()})
        await self._maybe_slow()
        regions = scope.regions or [DEMO_REGION]
        report = DiscoveryReport(provider_id=self.provider_id, identity={"account": DEMO_ACCOUNT, "fixture": True})
        for region in regions:
            if region != DEMO_REGION:
                report.unavailable.append({"source": f"{self.provider_id}/{region}", "reason": "region_not_enabled", "detail": "fixture account only has local-1"})
                continue
            eid = await ctx.store_evidence(self.provider_id, "demo_discovery", {"fixture": True, "region": region}, summary="demo fixture discovery")
            base = {"account": DEMO_ACCOUNT, "region": region, "fixture": True}
            obs = [
                Observation(provider_id=self.provider_id, resource_key=f"demo:eks:{region}:demo-cluster", resource_type="demo/eks_cluster", identity={**base, "arn": f"arn:aws:eks:{region}:{DEMO_ACCOUNT}:cluster/demo-cluster", "name": "demo-cluster"}, attributes={"version": "1.37", "endpoint": "https://demo-cluster.fixture.invalid", "logging": {"api": True, "audit": False, "authenticator": True}, "created_at": "2026-01-01T00:00:00Z"}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
                Observation(provider_id=self.provider_id, resource_key=f"demo:ec2:{region}:i-0demo1", resource_type="demo/ec2_instance", identity={**base, "instance_id": "i-0demo1"}, attributes={"name": "demo-cluster-node-1", "type": "m6i.large", "state": "running", "tags": {"eks:cluster-name": "demo-cluster"}}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid, relationships=[{"kind": "member_of", "target": f"demo:eks:{region}:demo-cluster"}]),
                Observation(provider_id=self.provider_id, resource_key=f"demo:ec2:{region}:i-0orphan", resource_type="demo/ec2_instance", identity={**base, "instance_id": "i-0orphan"}, attributes={"name": "unlabeled-box", "type": "t3.medium", "state": "running", "tags": {}}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
                Observation(provider_id=self.provider_id, resource_key=f"demo:rds:{region}:demo-db", resource_type="demo/rds_instance", identity={**base, "identifier": "demo-db", "arn": f"arn:aws:rds:{region}:{DEMO_ACCOUNT}:db:demo-db"}, attributes={"engine": "postgres", "class": "db.t4g.medium", "endpoint": "demo-db.fixture.invalid:5432", "backup_retention_days": 7}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
                Observation(provider_id=self.provider_id, resource_key=f"demo:ecr:{region}:demo-app", resource_type="demo/ecr_repository", identity={**base, "name": "demo-app", "uri": f"{DEMO_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/demo-app"}, attributes={"latest_tags": ["v1", "v2"], "image_count": 2}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
                Observation(provider_id=self.provider_id, resource_key="demo:route53:zone:demo.example.invalid", resource_type="demo/route53_zone", identity={"account": DEMO_ACCOUNT, "fixture": True, "zone": "demo.example.invalid"}, attributes={"records": [{"name": "api.demo.example.invalid", "type": "CNAME", "value": "demo-lb.fixture.invalid"}, {"name": "old.demo.example.invalid", "type": "A", "value": "203.0.113.5"}]}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
                Observation(provider_id=self.provider_id, resource_key=f"demo:acm:{region}:cert-1", resource_type="demo/acm_certificate", identity={**base, "arn": f"arn:aws:acm:{region}:{DEMO_ACCOUNT}:certificate/cert-1"}, attributes={"domain": "api.demo.example.invalid", "not_after": "2026-11-15T00:00:00Z", "status": "ISSUED"}, scope_key=f"{self.provider_id}/{region}", evidence_id=eid),
            ]
            report.observations.extend(obs)
            report.expiries.append({"resource_key": f"demo:acm:{region}:cert-1", "kind": "certificate", "expires_at": "2026-11-15T00:00:00Z"})
            report.completed_scopes.append(f"{self.provider_id}/{region}")
        return report

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        self.calls.append({"op": "query", "query": query})
        await self._maybe_slow()
        qtype = query.get("query_type")
        filters = query.get("filters", {}) or {}
        scenario = filters.get("scenario", "suspicious")
        limits = query.get("limits", {}) or {}
        max_events = int(limits.get("max_events", 500))
        tr = query.get("time_range") or {}
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["management"], time_range_requested={"start": tr.get("start"), "end": tr.get("end")}, source_retention_known=True, source_retention_note="fixture: complete", filters_provider_side=["scenario"], completed_scopes=[f"{self.provider_id}/{DEMO_REGION}"], accounts_expected=[DEMO_ACCOUNT], accounts_reached=[DEMO_ACCOUNT], regions_requested=[DEMO_REGION], regions_completed=[DEMO_REGION])
        if qtype == "cloudtrail_events":
            raw = demo_audit_events(scenario)
            names = filters.get("event_names")
            if names:
                raw = [e for e in raw if e["eventName"] in names]
                cov.filters_local.append("event_names")
            truncated = len(raw) > max_events
            raw = raw[:max_events]
            cov.truncated = truncated
            eid = await ctx.store_evidence(self.provider_id, "cloudtrail_events", {"fixture": True, "events": raw}, summary=f"{len(raw)} fixture CloudTrail events ({scenario})")
            events = [normalize_cloudtrail(e, self.provider_id, eid) for e in raw]
            if events:
                cov.time_range_observed = {"first_event": events[0]["occurred_at"], "last_event": events[-1]["occurred_at"]}
            cov.conclusion_scope = "Fixture data; nothing about any live account."
            return EvidenceResult(items=[{"fixture": True, **e} for e in events], events=events, coverage=cov, raw_evidence_ids=[eid], query_description={"scenario": scenario, "fixture": True})
        if qtype == "kubernetes_audit":
            raw = demo_kube_audit_events(scenario)[:max_events]
            eid = await ctx.store_evidence(self.provider_id, "kubernetes_audit", {"fixture": True, "events": raw}, summary=f"{len(raw)} fixture k8s audit events")
            events = [normalize_k8s_audit(e, self.provider_id, eid) for e in raw]
            cov.event_categories = ["kubernetes_audit"]
            return EvidenceResult(items=[{"fixture": True, **e} for e in events], events=events, coverage=cov, raw_evidence_ids=[eid], query_description={"scenario": scenario, "fixture": True})
        if qtype == "github_audit":
            raw = demo_github_events(scenario)[:max_events]
            eid = await ctx.store_evidence(self.provider_id, "github_audit", {"fixture": True, "events": raw}, summary=f"{len(raw)} fixture GitHub audit events")
            events = [normalize_github_audit(e, self.provider_id, eid) for e in raw]
            cov.event_categories = ["github_audit"]
            return EvidenceResult(items=[{"fixture": True, **e} for e in events], events=events, coverage=cov, raw_evidence_ids=[eid], query_description={"scenario": scenario, "fixture": True})
        if qtype == "guardduty_findings":
            raw = demo_guardduty_findings(scenario)
            eid = await ctx.store_evidence(self.provider_id, "guardduty_findings", {"fixture": True, "findings": raw}, summary=f"{len(raw)} fixture GuardDuty findings")
            cov.event_categories = ["security_findings"]
            return EvidenceResult(items=[{"fixture": True, **f} for f in raw], coverage=cov, raw_evidence_ids=[eid], query_description={"scenario": scenario, "fixture": True})
        if qtype == "demo_logs":
            lines = [
                "2026-09-30T10:00:01Z INFO demo-app started version=1.0.0",
                "2026-09-30T10:00:02Z WARN upstream db timeout host=demo-db.fixture.invalid",
                "2026-09-30T10:00:03Z DEBUG connecting with password=hunter2hunter2 and token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "2026-09-30T10:00:04Z INFO signed url https://bucket.s3.amazonaws.com/obj?X-Amz-Signature=abcdef0123456789&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE",
                "2026-09-30T10:00:05Z ERROR <script>alert('xss')</script> rendering must escape this",
                "2026-09-30T10:00:06Z INFO aws key AKIAIOSFODNN7EXAMPLE seen in config dump",
            ]
            eid = await ctx.store_evidence(self.provider_id, "demo_logs", {"fixture": True, "lines": lines}, summary=f"{len(lines)} fixture log lines")
            cov.event_categories = ["logs"]
            return EvidenceResult(items=[{"fixture": True, "line": ln} for ln in lines], coverage=cov, raw_evidence_ids=[eid], query_description={"fixture": True})
        cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="unsupported_query_type", detail=str(qtype)))
        cov.conclusion_scope = "Unsupported query; no evidence collected."
        return EvidenceResult(coverage=cov)


_IDENTITYSTORE_ARN_RE = re.compile(r"identitystore/(d-[a-z0-9]+)", re.IGNORECASE)


def _identity_store_id(identity_store_arn: str | None) -> str | None:
    if not identity_store_arn:
        return None
    m = _IDENTITYSTORE_ARN_RE.search(identity_store_arn)
    return m.group(1) if m else None


def normalize_cloudtrail(
    e: dict[str, Any],
    source_id: str,
    evidence_id: str | None,
    account: str | None = None,
    region: str | None = None,
    identity_center_user_names: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Normalize one CloudTrail `LookupEvents` record.

    AWS IAM Identity Center (`userIdentity.type == "IdentityCenterUser"`) events -- `Federate`,
    `GetRoleCredentials`, `Authenticate` and similar sign-in events -- never carry a `userName`, `arn` or
    `principalId` on `userIdentity` the way an IAM principal does; the identity is instead
    `userIdentity.onBehalfOf.userId`, an opaque Identity Center user id scoped to the identity store named
    in `userIdentity.onBehalfOf.identityStoreArn`. Without this, `actor` came back `None` for every one of
    these events. `actor` is set to the stable, documented form `identitycenter:<identity_store_id>:<user_id>`
    (falling back to `identitycenter:unknown:<user_id>` if the ARN cannot be parsed) so these events still
    join to other activity by the same person and so `fields.identity_center_user_id` (the raw user id) and
    `fields.identity_store_arn` are always available for a caller who wants to resolve it another way.

    `fields.identity_center_user_name` is populated only when `identity_center_user_names` -- a caller-
    supplied `identity_store_id -> user_id -> display name` map built from `aws/identitystore_user`
    observations already released to the requesting principal (never fetched here, and never from AWS;
    see `AwsAdapter._identity_center_user_names`) -- has an entry for this identity store and user id.
    Nesting by identity store id, not a single flat `user_id -> name` map, matters because a user id is
    only unique within its own identity store: two different organizations' stores could mint the same id.

    The target of a sign-in/credential request -- the account and permission set the user federated or
    requested credentials into -- is surfaced as `fields.target_account_id`/`fields.target_role_name`, read
    from `serviceEventDetails` (`Federate`) or `requestParameters` (`GetRoleCredentials`), whichever is
    present. `fields.request_parameters` keeps carrying the raw `requestParameters` unchanged, including any
    `credentialId`; the context sanitizer (`release.Sanitizer`) -- which this function does not run, and
    which every evidence/result path runs over its output -- redacts that and any other credential-shaped
    field wholesale before it is ever stored or disclosed.
    """
    ui = e.get("userIdentity") or {}
    on_behalf = (ui.get("onBehalfOf") or {}) if ui.get("type") == "IdentityCenterUser" else {}
    identity_center_user_id = on_behalf.get("userId")
    identity_store_arn = on_behalf.get("identityStoreArn")
    identity_store_id = _identity_store_id(identity_store_arn)
    actor: str | None
    if identity_center_user_id:
        actor = f"identitycenter:{identity_store_id or 'unknown'}:{identity_center_user_id}"
    else:
        actor = ui.get("userName") or ui.get("arn") or ui.get("principalId")
    sess = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName") if ui.get("sessionContext") else None
    resources = e.get("resources") or []
    service_event_details = e.get("serviceEventDetails") or {}
    request_parameters = e.get("requestParameters") or {}
    target_account_id = service_event_details.get("account_id") or request_parameters.get("accountId")
    target_role_name = service_event_details.get("role_name") or request_parameters.get("roleName")
    fields: dict[str, Any] = {"event_source": e.get("eventSource"), "error_code": e.get("errorCode"), "request_parameters": e.get("requestParameters"), "read_only": e.get("readOnly"), "mfa": ((ui.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated") if ui.get("sessionContext") else None}
    if identity_center_user_id:
        fields["identity_center_user_id"] = identity_center_user_id
        fields["identity_store_arn"] = identity_store_arn
        name = ((identity_center_user_names or {}).get(identity_store_id or "") or {}).get(identity_center_user_id)
        if name:
            fields["identity_center_user_name"] = name
    if target_account_id:
        fields["target_account_id"] = target_account_id
    if target_role_name:
        fields["target_role_name"] = target_role_name
    return {
        "event_key": f"cloudtrail:{account or e.get('recipientAccountId')}:{e.get('eventID')}", "provider": "aws", "source_id": source_id, "account": account or e.get("recipientAccountId"), "region": region or e.get("awsRegion"),
        "event_id": e.get("eventID"), "occurred_at": e.get("eventTime"), "collected_at": iso(utcnow()), "actor": actor, "actor_type": ui.get("type"), "session": sess,
        "action": e.get("eventName"), "resource": resources[0].get("ARN") if resources else (e.get("requestParameters") or {}).get("roleName") or (e.get("requestParameters") or {}).get("userName"),
        "resource_type": resources[0].get("resourceType") if resources else None, "source_ip": e.get("sourceIPAddress"), "user_agent": e.get("userAgent"),
        "outcome": "failure" if e.get("errorCode") else "success", "category": "management", "evidence_ref": evidence_id,
        "fields": fields,
    }


def normalize_k8s_audit(e: dict[str, Any], source_id: str, evidence_id: str | None, cluster: str | None = None) -> dict[str, Any]:
    obj = e.get("objectRef") or {}
    res = "/".join(x for x in [obj.get("namespace"), obj.get("resource"), obj.get("subresource"), obj.get("name")] if x)
    return {
        "event_key": f"k8saudit:{cluster or source_id}:{e.get('auditID')}", "provider": "kubernetes", "source_id": source_id, "account": None, "region": None,
        "event_id": e.get("auditID"), "occurred_at": e.get("requestReceivedTimestamp"), "collected_at": iso(utcnow()), "actor": (e.get("user") or {}).get("username"), "actor_type": "kubernetes_user",
        "session": None, "action": f"{e.get('verb')} {obj.get('resource')}{('/' + obj['subresource']) if obj.get('subresource') else ''}", "resource": res, "resource_type": obj.get("resource"),
        "source_ip": (e.get("sourceIPs") or [None])[0], "user_agent": e.get("userAgent"), "outcome": "success" if int((e.get("responseStatus") or {}).get("code", 0)) < 400 else "failure",
        "category": "kubernetes_audit", "evidence_ref": evidence_id, "fields": {"groups": (e.get("user") or {}).get("groups"), "request_object": e.get("requestObject"), "verb": e.get("verb"), "subresource": obj.get("subresource"), "cluster": cluster},
    }


def normalize_github_audit(e: dict[str, Any], source_id: str, evidence_id: str | None, org: str | None = None) -> dict[str, Any]:
    ts = e.get("@timestamp")
    at = iso(datetime.fromtimestamp(ts / 1000, tz=utcnow().tzinfo)) if isinstance(ts, int | float) else str(ts)
    return {
        "event_key": f"github:{org or source_id}:{e.get('_document_id') or (str(ts) + ':' + str(e.get('action')) + ':' + str(e.get('actor')))}", "provider": "github", "source_id": source_id, "account": org, "region": None,
        "event_id": e.get("_document_id"), "occurred_at": at, "collected_at": iso(utcnow()), "actor": e.get("actor"), "actor_type": "github_user", "session": None,
        "action": e.get("action"), "resource": e.get("repo") or e.get("org"), "resource_type": "repository" if e.get("repo") else "organization", "source_ip": e.get("actor_ip"), "user_agent": e.get("user_agent"),
        "outcome": "success", "category": "github_audit", "evidence_ref": evidence_id, "fields": {k: v for k, v in e.items() if k not in ("@timestamp", "action", "actor", "repo", "actor_ip")},
    }
