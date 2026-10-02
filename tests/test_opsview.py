"""Operational views (D25/D26) and the AWS access graph (D27) over a synthetic released estate.

Everything here is a pure projection: rows stand in for released observations, scans for released scan
coverage. The assertions pin the deterministic rules: bindings resolve only by exact key/tag/identity,
relationships only by exact provider identifiers, hubs are not expanded, stale/missing state is visible,
and the access guide never claims access is absent when coverage is incomplete."""

from __future__ import annotations

import textwrap
from datetime import timedelta
from pathlib import Path
from typing import Any

from local_ops.access import AccessGraph, guide_markdown
from local_ops.catalog import load_catalog
from local_ops.models import iso, utcnow
from local_ops.opsview import (
    CoverageIndex,
    ObservationIndex,
    Snapshot,
    environments,
    inventory,
    resource_view,
    service_view,
    unmapped_summary,
)

A, B = "111111111111", "222222222222"
R = "us-west-2"
P, PB, K = "aws-a", "aws-b", "kube-a"
NOW = utcnow()
FRESH = iso(NOW - timedelta(hours=1))
OLD = iso(NOW - timedelta(days=3))
STORE = "d-123"
INST = "arn:aws:sso:::instance/ssoins-1"


def arn(kind: str, rid: str, acct: str = A) -> str:
    return f"arn:aws:ec2:{R}:{acct}:{kind}/{rid}"


def row(provider: str, key: str, rtype: str, identity: dict[str, Any], attributes: dict[str, Any] | None = None, rels: list[dict[str, str]] | None = None, *, seen: str | None = FRESH, missing: str | None = None, scope: str | None = None) -> dict[str, Any]:
    attrs = dict(attributes or {})
    attrs["relationships"] = rels or []
    return {"id": "obs_" + key[-12:], "provider_id": provider, "resource_key": key, "resource_type": rtype, "identity": identity, "attributes": attrs, "evidence_id": "evd_1", "scope_key": scope or f"{provider}/{identity.get('account', A)}/{identity.get('region', R)}/{rtype.split('/')[-1]}", "first_seen_at": seen, "last_seen_at": seen, "missing_since": missing, "scan_request_id": "req_scan", "released_to": ["p1"], "match_service_id": None, "match_binding_id": None, "match_basis": None, "match_confidence": None}


def instance(iid: str, tags: dict[str, str], *, ip: str, public: str | None = None, seen: str | None = FRESH, missing: str | None = None) -> dict[str, Any]:
    rels = [{"kind": "network_in", "target": arn("subnet", "subnet-1")}, {"kind": "network_in", "target": arn("vpc", "vpc-1")}, {"kind": "network_in", "target": arn("security-group", "sg-1")}, {"kind": "uses_volume", "target": arn("volume", f"vol-{iid}")}, {"kind": "uses_instance_profile", "target": f"arn:aws:iam::{A}:instance-profile/node"}] + ([{"kind": "owner", "target": f"aws:{A}:{R}:autoscaling:asg-val"}] if tags.get("Role") == "validator" else [])
    return row(P, arn("instance", iid), "aws/ec2_instance", {"account": A, "region": R, "arn": arn("instance", iid), "instance_id": iid}, {"name": tags.get("Name"), "state": "running", "tags": tags, "private_ip": ip, "public_ip": public, "type": "m6i.large", "launch_time": "2026-09-01T00:00:00Z", "subnet_id": "subnet-1", "vpc_id": "vpc-1"}, rels, seen=seen, missing=missing)


def estate() -> list[dict[str, Any]]:
    rows = [
        instance("i-1", {"Name": "val-1", "Role": "validator"}, ip="10.0.0.1", public="1.2.3.4"),
        instance("i-2", {"Name": "val-2", "Role": "validator"}, ip="10.0.0.2", seen=OLD),
        instance("i-3", {"Name": "idx-1", "Role": "indexer"}, ip="10.0.0.3"),
        row(P, arn("subnet", "subnet-1"), "aws/subnet", {"account": A, "region": R, "subnet_id": "subnet-1", "vpc_id": "vpc-1"}),
        row(P, arn("vpc", "vpc-1"), "aws/vpc", {"account": A, "region": R, "vpc_id": "vpc-1"}),
        row(P, arn("security-group", "sg-1"), "aws/security_group", {"account": A, "region": R, "group_id": "sg-1", "name": "nodes"}),
        row(P, arn("volume", "vol-i-1"), "aws/ebs_volume", {"account": A, "region": R, "arn": arn("volume", "vol-i-1"), "volume_id": "vol-i-1"}, {}, [{"kind": "attached_to", "target": arn("instance", "i-1")}]),
        row(P, f"arn:aws:iam::{A}:instance-profile/node", "aws/iam_instance_profile", {"account": A, "region": "global", "arn": f"arn:aws:iam::{A}:instance-profile/node", "name": "node"}, {"role_arns": [f"arn:aws:iam::{A}:role/node"]}, [{"kind": "contains_role", "target": f"arn:aws:iam::{A}:role/node"}]),
        row(P, f"arn:aws:iam::{A}:role/node", "aws/iam_role", {"account": A, "region": "global", "arn": f"arn:aws:iam::{A}:role/node", "name": "node"}, {"role_class": "standard", "trust_principals": {"services": ["ec2.amazonaws.com"], "aws": [], "federated": []}}),
        row(P, f"arn:aws:autoscaling:{R}:{A}:autoScalingGroup:x:autoScalingGroupName/asg-val", "aws/autoscaling_group", {"account": A, "region": R, "arn": f"arn:aws:autoscaling:{R}:{A}:autoScalingGroup:x:autoScalingGroupName/asg-val", "name": "asg-val", "name_key": f"aws:{A}:{R}:autoscaling:asg-val"}, {"desired_capacity": 2}, [{"kind": "contains", "target": arn("instance", "i-1")}, {"kind": "contains", "target": arn("instance", "i-2")}]),
        row(P, f"arn:aws:elasticloadbalancing:{R}:{A}:targetgroup/val/abc", "aws/target_group", {"account": A, "region": R, "arn": f"arn:aws:elasticloadbalancing:{R}:{A}:targetgroup/val/abc", "name": "val"}, {"targets": [{"id": "i-1", "health_state": "healthy"}]}, [{"kind": "routes_to", "target": arn("instance", "i-1")}, {"kind": "serves", "target": f"arn:aws:elasticloadbalancing:{R}:{A}:loadbalancer/app/val-lb/123"}]),
        row(P, f"arn:aws:elasticloadbalancing:{R}:{A}:loadbalancer/app/val-lb/123", "aws/load_balancer", {"account": A, "region": R, "arn": f"arn:aws:elasticloadbalancing:{R}:{A}:loadbalancer/app/val-lb/123", "name": "val-lb"}, {"dns_name": "val-lb-123.us-west-2.elb.amazonaws.com"}),
        # Route53 lives in another account: alias DNS and A-record public IPs still resolve exactly.
        row(PB, f"aws:{B}:global:route53:Z1:api.example.com.:A", "aws/route53_record", {"account": B, "region": "global", "zone_id": "Z1", "name": "api.example.com.", "type": "A"}, {"alias_target": "dualstack.val-lb-123.us-west-2.elb.amazonaws.com."}, [{"kind": "dns", "target": "dualstack.val-lb-123.us-west-2.elb.amazonaws.com."}]),
        row(PB, f"aws:{B}:global:route53:Z1:node1.example.com.:A", "aws/route53_record", {"account": B, "region": "global", "zone_id": "Z1", "name": "node1.example.com.", "type": "A"}, {"values": ["1.2.3.4"]}),
        row(PB, f"aws:{B}:global:route53:Z1:priv.example.com.:A", "aws/route53_record", {"account": B, "region": "global", "zone_id": "Z1", "name": "priv.example.com.", "type": "A"}, {"values": ["10.0.0.1"]}),
        row(P, f"arn:aws:cloudwatch:{R}:{A}:alarm:val-cpu", "aws/cloudwatch_alarm", {"account": A, "region": R, "arn": f"arn:aws:cloudwatch:{R}:{A}:alarm:val-cpu", "name": "val-cpu"}, {"state": "OK", "namespace": "AWS/EC2", "metric_name": "CPUUtilization", "actions": ["arn:aws:sns:x"]}, [{"kind": "monitors", "target": "aws:metric:AWS/EC2:CPUUtilization:InstanceId=i-1"}]),
        row(K, "k8s:uid-c:indexer:Deployment:uid-d", "k8s/Deployment", {"cluster_identity": "uid-c", "namespace": "indexer", "kind": "Deployment", "name": "processor", "uid": "uid-d"}, {"desired_images": [{"container": "app", "image": "repo/proc:1"}], "rollout": {"ready": 1}}),
        # identity: Identity Center in account A, assignments into A and B; a legacy IAM user in A
        row(P, INST, "aws/sso_instance", {"account": A, "region": R, "arn": INST, "instance_id": "ssoins-1", "identity_store_id": STORE, "name": "org"}, {"owner_account_id": A, "status": "ACTIVE"}),
        row(P, f"{INST}/ps-ro", "aws/sso_permission_set", {"account": A, "region": R, "arn": f"{INST}/ps-ro", "name": "ReadOnly", "instance_arn": INST}, {"managed_policies": [{"name": "ViewOnlyAccess", "arn": "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"}], "provisioned_account_ids": [A, B]}),
        row(P, f"{INST}/ps-admin", "aws/sso_permission_set", {"account": A, "region": R, "arn": f"{INST}/ps-admin", "name": "Admin", "instance_arn": INST}, {"managed_policies": [{"name": "AdministratorAccess", "arn": "x"}], "provisioned_account_ids": [A]}),
        row(P, f"identitystore:{STORE}:user:u-alice", "aws/identitystore_user", {"account": A, "region": R, "identity_store_id": STORE, "user_id": "u-alice", "user_name": "alice@example.invalid"}, {"display_name": "Alice", "external_id_issuers": ["https://scim.example.invalid"]}),
        row(P, f"identitystore:{STORE}:user:u-bob", "aws/identitystore_user", {"account": A, "region": R, "identity_store_id": STORE, "user_id": "u-bob", "user_name": "bob@example.invalid"}, {"display_name": "Bob", "external_id_issuers": []}),
        row(P, f"identitystore:{STORE}:group:g-eng", "aws/identitystore_group", {"account": A, "region": R, "identity_store_id": STORE, "group_id": "g-eng", "name": "engineers"}, {"member_count": 1, "members_complete": True}),
        row(P, f"identitystore:{STORE}:membership:m-1", "aws/identitystore_group_membership", {"account": A, "region": R, "identity_store_id": STORE, "membership_id": "m-1", "group_id": "g-eng", "user_id": "u-alice"}, {}, [{"kind": "member", "target": f"identitystore:{STORE}:user:u-alice"}, {"kind": "group", "target": f"identitystore:{STORE}:group:g-eng"}]),
        row(P, f"sso:ssoins-1:assignment:{B}:{INST}/ps-ro:GROUP:g-eng", "aws/sso_account_assignment", {"account": A, "region": R, "instance_arn": INST, "target_account_id": B, "permission_set_arn": f"{INST}/ps-ro", "principal_type": "GROUP", "principal_id": "g-eng"}, {"permission_set_name": "ReadOnly"}, [{"kind": "assigns", "target": f"identitystore:{STORE}:group:g-eng"}]),
        row(P, f"sso:ssoins-1:assignment:{A}:{INST}/ps-admin:USER:u-bob", "aws/sso_account_assignment", {"account": A, "region": R, "instance_arn": INST, "target_account_id": A, "permission_set_arn": f"{INST}/ps-admin", "principal_type": "USER", "principal_id": "u-bob"}, {"permission_set_name": "Admin"}, [{"kind": "assigns", "target": f"identitystore:{STORE}:user:u-bob"}]),
        row(P, f"arn:aws:iam::{A}:user/carol", "aws/iam_user", {"account": A, "region": "global", "arn": f"arn:aws:iam::{A}:user/carol", "name": "carol"}, {"password_last_used": "2026-09-01T00:00:00Z", "access_keys": [{"access_key_hash": "h", "access_key_suffix": "WXYZ", "status": "Active", "last_used_at": None}], "service_specific_credentials": [{"credential_id_hash": "h3", "credential_id_suffix": "ZZZZ", "status": "Active", "service_name": "bedrock.amazonaws.com", "created_at": "2026-01-01T00:00:00Z", "expiration_date": None}], "group_names": ["legacy-admins"]}),
        row(P, f"arn:aws:iam::{A}:user/deployer", "aws/iam_user", {"account": A, "region": "global", "arn": f"arn:aws:iam::{A}:user/deployer", "name": "deployer"}, {"password_last_used": None, "access_keys": [{"access_key_hash": "h2", "access_key_suffix": "ABCD", "status": "Active"}]}),
        row(P, f"arn:aws:organizations::{A}:account/o-1/{B}", "aws/org_account", {"account": A, "region": "global", "account_id": B, "name": "mainnet"}),
        row(P, f"arn:aws:organizations::{A}:account/o-1/{A}", "aws/org_account", {"account": A, "region": "global", "account_id": A, "name": "management"}),
        # EKS access entry for the AWSReservedSSO_Admin_* role: the Admin permission set on account A
        # also reaches the "prod" cluster through this access entry.
        row(P, f"arn:aws:eks:{R}:{A}:cluster/prod/access-entry/admin-sso", "aws/eks_access_entry", {"account": A, "region": R, "cluster": "prod", "principal_arn": f"arn:aws:iam::{A}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abcdef0123456789"}, {"permission_set_name": "Admin", "kubernetes_groups": ["system:masters"], "username": None, "access_scope_types": ["cluster"]}, [{"kind": "grants_cluster_access", "target": f"arn:aws:eks:{R}:{A}:cluster/prod"}, {"kind": "principal", "target": f"arn:aws:iam::{A}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abcdef0123456789"}]),
    ]
    return rows


def write_catalog(root: Path, services: dict[str, str]) -> None:
    (root / "services").mkdir(parents=True, exist_ok=True)
    (root / "catalog.yaml").write_text("name: ops-test\nexecution_allowed: false\n", encoding="utf-8")
    for sid, body in services.items():
        (root / "services" / f"{sid}.md").write_text("---\n" + textwrap.dedent(body).strip() + "\n---\nnotes\n", encoding="utf-8")


SERVICES = {
    "validator": f"""
        id: validator
        name: Validators
        purpose: Consensus validators
        environments: [mainnet]
        bindings:
          - id: nodes
            environment: mainnet
            provider_id: {P}
            region: {R}
            selector: {{resource_types: [aws/ec2_instance], tags: {{Role: validator}}}}
        operations:
          restart: {{executor: kubernetes_native, kind: rollout_restart, binding_id: nodes}}
        unknowns: [who is on call]
    """,
    "indexer": f"""
        id: indexer
        name: Indexer
        environments: [mainnet]
        bindings:
          - id: host
            environment: mainnet
            provider_id: {P}
            resource_keys: ["{arn('instance', 'i-3')}"]
          - id: processor
            environment: mainnet
            provider_id: {K}
            cluster_identity: uid-c
            namespace: indexer
            workload_kind: Deployment
            workload_name: processor
          - id: gone
            environment: mainnet
            provider_id: {P}
            resource_keys: ["{arn('instance', 'i-404')}"]
    """,
    "orphan": """
        id: orphan
        name: Orphan
    """,
}


def coverage(iam_complete: bool = True, ic_complete: bool = True) -> tuple[CoverageIndex, list[dict[str, Any]]]:
    completed = [f"{P}/{A}/{R}/ec2_instance", f"{P}/{A}/global/iam", f"{P}/{A}/global/iam/access_keys", f"{P}/{A}/global/iam/groups", f"{P}/{A}/global/iam/policy_refs", f"{P}/{A}/global/iam/instance_profiles", f"{P}/{A}/global/iam/service_specific_credentials"]
    unavailable = [] if iam_complete else [{"source": f"{P}/{A}/global/iam/groups", "reason": "permission_denied"}]
    if not iam_complete:
        completed.remove(f"{P}/{A}/global/iam/groups")
    scans = [{"request_id": "req_scan", "provider_ids": [P, PB, K], "completed_scopes": completed, "unavailable": unavailable, "finished_at": FRESH}]
    child = {k: "complete" for k in ("permission_sets", "assignments", "users", "groups", "memberships")}
    if not ic_complete:
        child["memberships"] = "partial"
    results = [{"request_id": "req_scan", "finished_at": FRESH, "provider_ids": [P], "aws_coverage": {"per_provider": {P: {"identity_center": [{"account": A, "region": R, "status": "complete", "instances": [INST], "child_scopes": child}, {"account": A, "region": "us-east-1", "status": "no_instance_in_this_account_region", "instances": [], "child_scopes": {}}]}}}}]
    return CoverageIndex(scans), results


def snapshot(tmp_path: Path, rows: list[dict[str, Any]] | None = None, **cov: bool) -> Snapshot:
    write_catalog(tmp_path / "cat", SERVICES)
    ci, results = coverage(**cov)
    return Snapshot(catalog=load_catalog(tmp_path / "cat"), index=ObservationIndex(rows if rows is not None else estate()), coverage=ci, released_results=results, provider_kinds={P: "aws", PB: "aws", K: "kubernetes"}, pending_release=3, now=NOW)


def keys(cards: list[dict[str, Any]]) -> set[str]:
    return {c["resource_key"] for c in cards}


# ---------------------------------------------------------------------------- service view
def test_environment_grouping_and_warnings(tmp_path: Path) -> None:
    envs = {e["environment"]: e for e in environments(snapshot(tmp_path))}
    assert set(envs) == {"mainnet", "(no environment recorded)"}
    by_id = {s["service_id"]: s for s in envs["mainnet"]["services"]}
    assert by_id["validator"]["resources"] == 2 and by_id["validator"]["running_instances"] == 2
    assert by_id["validator"]["freshness"] == {"current": 1, "stale": 1}
    assert any("gone resolves to no released observation" in w for w in by_id["indexer"]["warnings"])
    assert any("where it runs is unknown" in w for w in envs["(no environment recorded)"]["services"][0]["warnings"])


def test_bindings_resolve_only_exact_keys_tags_and_identity(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    v = service_view(snap.catalog.services["validator"], snap)
    assert keys(v["bindings"][0]["resources"]) == {arn("instance", "i-1"), arn("instance", "i-2")}
    assert v["bindings"][0]["resources"][0]["basis"] == "tag selector Role=validator"
    ix = service_view(snap.catalog.services["indexer"], snap)
    by_binding = {b["binding"]["id"]: b for b in ix["bindings"]}
    assert keys(by_binding["host"]["resources"]) == {arn("instance", "i-3")}
    assert [c["resource_type"] for c in by_binding["processor"]["resources"]] == ["k8s/Deployment"]
    assert by_binding["gone"]["resolved"] == 0
    assert any(u["kind"] == "binding_unresolved" for u in ix["unknowns"])
    # where it runs groups provider -> account -> region -> cluster/ns -> type
    assert set(ix["where"]) == {P, K}
    assert list(ix["where"][K]["uid-c"]["?"]["uid-c/indexer"]) == ["k8s/Deployment"]


def test_provider_mismatch_never_resolves(tmp_path: Path) -> None:
    rows = [r if r["resource_key"] != arn("instance", "i-3") else {**r, "provider_id": PB} for r in estate()]
    snap = snapshot(tmp_path, rows)
    ix = service_view(snap.catalog.services["indexer"], snap)
    assert next(b for b in ix["bindings"] if b["binding"]["id"] == "host")["resolved"] == 0


def test_relationships_are_exact_and_cross_account_dns_resolves(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    i1 = snap.index.get(P, arn("instance", "i-1"))
    assert i1 is not None
    n = {(e["kind"], e["direction"], e["row"]["resource_type"] if e["row"] else None) for e in snap.index.neighbours(i1)}
    assert {("network_in", "out", "aws/subnet"), ("network_in", "out", "aws/vpc"), ("network_in", "out", "aws/security_group"), ("uses_volume", "out", "aws/ebs_volume"), ("uses_instance_profile", "out", "aws/iam_instance_profile"), ("owner", "out", "aws/autoscaling_group")} <= n
    assert {("routes_to", "in", "aws/target_group"), ("monitors", "in", "aws/cloudwatch_alarm"), ("contains", "in", "aws/autoscaling_group")} <= n
    # A-record equal to the public IP resolves across accounts; a private IP in another account does not.
    assert ("resolves_to", "in", "aws/route53_record") in n
    resolving = [e["row"]["identity"]["name"] for e in snap.index.neighbours(i1) if e["kind"] == "resolves_to"]
    assert resolving == ["node1.example.com."]
    lb = snap.index.get(P, f"arn:aws:elasticloadbalancing:{R}:{A}:loadbalancer/app/val-lb/123")
    assert lb is not None
    assert [e["basis"] for e in snap.index.neighbours(lb) if e["kind"] == "dns"] == ["alias DNS name"]


def test_related_follows_chains_but_never_expands_hubs(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    v = service_view(snap.catalog.services["validator"], snap)
    related = {c["resource_type"]: c for c in v["related"]}
    assert "aws/load_balancer" in related and "aws/route53_record" in related  # instance <- TG -> LB <- alias record
    assert "aws/iam_role" in related  # instance -> profile -> role
    # i-3 shares the subnet/VPC/SG hubs and the role hub, but is not pulled into the validator page
    assert arn("instance", "i-3") not in keys(v["related"])
    chain = next(c["chain"] for c in v["related"] if c["resource_type"] == "aws/load_balancer")
    assert [s["kind"] for s in chain] == ["routes_to", "serves"]


def test_logs_metrics_alerts_and_unmapped_states(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    v = service_view(snap.catalog.services["validator"], snap)
    assert v["logs"]["unmapped"] is True and v["logs"]["observed_log_groups"] == []
    assert [a["name"] for a in v["alerts"]["alarms"]] == ["val-cpu"] and v["alerts"]["unmapped"] is False
    dims = {(m["namespace"], m["dimension"], m["value"]) for m in v["metrics"]["cloudwatch_identifiers"]}
    assert dims == {("AWS/EC2", "InstanceId", "i-1"), ("AWS/EC2", "InstanceId", "i-2")}
    assert v["metrics"]["unmapped"] is True  # identifiers are not an approved metrics source


def test_operations_are_display_only(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    v = service_view(snap.catalog.services["validator"], snap)
    assert v["operations"]["operations"] == [{"name": "restart", "executor": "kubernetes_native", "kind": "rollout_restart", "binding_id": "nodes", "health_checks": [], "executable": False}]


def test_freshness_stale_missing_and_coverage(tmp_path: Path) -> None:
    rows = estate()
    rows[0]["missing_since"] = FRESH
    snap = snapshot(tmp_path, rows)
    v = service_view(snap.catalog.services["validator"], snap)
    states = {c["resource_key"]: c["freshness"]["state"] for c in v["bindings"][0]["resources"]}
    assert states == {arn("instance", "i-1"): "missing", arn("instance", "i-2"): "stale"}
    cov = {c["resource_key"]: c["coverage"]["status"] for c in v["bindings"][0]["resources"]}
    assert set(cov.values()) == {"complete"}
    assert snap.coverage.status(P, f"{P}/{A}/{R}/lambda")["status"] == "partial_or_not_attempted"
    assert snap.coverage.status("other", "x")["status"] == "never_scanned"


def test_no_observations_at_all(tmp_path: Path) -> None:
    snap = snapshot(tmp_path, [])
    v = service_view(snap.catalog.services["validator"], snap)
    assert v["bindings"][0]["resolved"] == 0 and v["related"] == [] and v["edges"] == []
    assert v["access"]["coverage"]["identity_center_complete"] is True  # coverage is from scans, not rows
    assert unmapped_summary(snap) == []


def test_resource_view_and_inventory(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    rv = resource_view(snap.index.get(P, arn("instance", "i-1")) or {}, snap)
    assert rv["services"] == [{"service_id": "validator", "binding_id": "nodes", "environment": "mainnet", "basis": "tag selector Role=validator"}]
    assert "relationships" not in rv["attributes"]
    inv = inventory(snap, resource_type="aws/ec2_instance")
    assert inv["total"] == 3 and not inv["truncated"]
    un = {(u["provider_id"], u["account"]): u["types"] for u in unmapped_summary(snap)}
    assert "aws/ec2_instance" not in un[(P, A)]  # all three instances are bound


# ---------------------------------------------------------------------------- access graph
def test_group_and_direct_assignment_paths(tmp_path: Path) -> None:
    g = AccessGraph.build(snapshot(tmp_path))
    alice = g.find_person("alice@example.invalid")["identity_center_users"][0]
    assert alice["groups"] == ["engineers"]
    assert [(a["account_name"], a["permission_set"], a["via"]) for a in alice["effective_access"]] == [("mainnet", "ReadOnly", "group engineers")]
    bob = g.find_person("Bob")["identity_center_users"][0]  # display name, exact and case-insensitive
    assert [(a["account_name"], a["permission_set"], a["via"]) for a in bob["effective_access"]] == [("management", "Admin", "direct assignment")]
    model = g.access_model()
    assert model["group_assignment_count"] == 1 and model["direct_user_assignment_count"] == 1
    assert model["external_identity_sources"] == ["https://scim.example.invalid"]
    assert g.find_person("ali")["identity_center_users"] == []  # never partial matching


def test_eks_access_entries_surface_kubernetes_access_for_a_permission_set(tmp_path: Path) -> None:
    g = AccessGraph.build(snapshot(tmp_path))
    bob = g.find_person("Bob")["identity_center_users"][0]
    assert bob["effective_access"][0]["eks_clusters"] == [{"cluster": "prod", "kubernetes_groups": ["system:masters"], "username": None}]
    alice = g.find_person("alice@example.invalid")["identity_center_users"][0]
    assert alice["effective_access"][0]["eks_clusters"] == []  # ReadOnly has no EKS access entry
    assert g.eks_access_by_permission_set() == {"Admin": ["prod"]}
    steps = "\n".join(g.onboarding()["steps"])
    assert "Kubernetes access via EKS access entries" in steps and "Admin: prod" in steps


def test_legacy_iam_user_and_mixed_offboarding(tmp_path: Path) -> None:
    g = AccessGraph.build(snapshot(tmp_path))
    carol = g.find_person("carol")
    assert carol["identity_center_users"] == [] and [u["name"] for u in carol["iam_users"]] == ["carol"]
    off = g.offboarding(carol, [], ["Shared"])
    kinds = [i["kind"] for i in off["checklist"]]
    assert kinds == ["iam_user", "access_key", "service_specific_credential", "iam_group_membership"]
    assert "WXYZ" in off["checklist"][1]["action"]
    assert "bedrock.amazonaws.com" in off["checklist"][2]["action"] and "ZZZZ" in off["checklist"][2]["action"]
    assert any("1Password vault membership is not observed" in f for f in off["follow_up"])
    alice = g.find_person("alice@example.invalid")
    off = g.offboarding(alice, [], [])
    assert [i["kind"] for i in off["checklist"]] == ["identity_center_group_membership", "identity_center_user"]
    assert off["checklist"][0]["effect"] == ["ReadOnly on mainnet"]
    assert "in its source (https://scim.example.invalid)" in off["checklist"][1]["action"]
    assert off["limits"] == []
    bob = g.find_person("Bob")
    off_bob = g.offboarding(bob, [], [])
    direct = next(i for i in off_bob["checklist"] if i["kind"] == "identity_center_direct_assignment")
    assert "Admin on management" in direct["action"] and "EKS cluster(s) prod via access entry" in direct["action"]


def test_incomplete_coverage_never_claims_removal(tmp_path: Path) -> None:
    g = AccessGraph.build(snapshot(tmp_path, ic_complete=False, iam_complete=False))
    assert g.ic_complete() is False
    cov = g.coverage_summary()
    assert any("memberships" in w and "partial" in w for w in cov["warnings"])
    assert any(f"IAM in account {A}" in w and "groups=unavailable" in w for w in cov["warnings"])
    off = g.offboarding(g.find_person("nobody"), [], [])
    assert any("cannot establish that access is removed" in x for x in off["limits"])
    assert any("not evidence that the person has no access" in x for x in off["limits"])
    md = guide_markdown(g.onboarding(), off, "nobody")
    assert "Identity Center coverage complete: **False**" in md and "removed" not in md.split("LIMIT")[0].split("## How a person loses")[1]


def test_no_identity_center_observed_is_not_absence(tmp_path: Path) -> None:
    rows = [r for r in estate() if not r["resource_type"].startswith(("aws/sso", "aws/identitystore"))]
    snap = snapshot(tmp_path, rows)
    snap.released_results = []
    g = AccessGraph.build(snap)
    assert any("is unknown" in w for w in g.coverage_summary()["warnings"])
    assert g.onboarding()["steps"][0].startswith("No Identity Center instance is observed")


def test_machine_identities_are_separate_from_people(tmp_path: Path) -> None:
    g = AccessGraph.build(snapshot(tmp_path))
    m = g.machine_identities()
    assert [r["name"] for r in m["service_roles"]] == ["node"]
    assert [u["name"] for u in m["iam_users_with_keys_and_no_observed_console_use"]] == ["deployer"]
    assert [u["name"] for u in g.access_model()["iam_users_with_console_use"]] == ["carol"]
    acct = g.account_access(B)
    assert acct["identity_center"] == [{"permission_set": "ReadOnly", "principals": [{"principal": "group engineers", "principal_type": "GROUP", "group_members": ["alice@example.invalid"]}]}]


def test_scan_time_matching_uses_the_same_exact_rules(tmp_path: Path) -> None:
    from local_ops.discovery import observation_rows
    from local_ops.providers.base import DiscoveryReport, Observation

    snap = snapshot(tmp_path)
    obs = [Observation(provider_id=r["provider_id"], resource_key=r["resource_key"], resource_type=r["resource_type"], identity=r["identity"], attributes={k: v for k, v in r["attributes"].items() if k != "relationships"}) for r in estate() if r["resource_type"] == "aws/ec2_instance"]
    rows = {r["resource_key"]: r for r in observation_rows(DiscoveryReport(provider_id=P, observations=obs), snap.catalog)}
    assert (rows[arn("instance", "i-1")]["match_service_id"], rows[arn("instance", "i-1")]["match_basis"]) == ("validator", "tag selector Role=validator")
    assert (rows[arn("instance", "i-3")]["match_service_id"], rows[arn("instance", "i-3")]["match_confidence"]) == ("indexer", "observed")


def test_selector_requires_types_and_tags() -> None:
    import pytest
    from pydantic import ValidationError

    from local_ops.catalog import BindingSelector

    with pytest.raises(ValidationError):
        BindingSelector(resource_types=[], tags={"Role": "x"})
    with pytest.raises(ValidationError):
        BindingSelector(resource_types=["aws/ec2_instance"], tags={})


def test_member_account_views_of_an_org_instance_do_not_reduce_coverage(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    member = {"account": B, "region": R, "status": "partial", "instances": [INST], "child_scopes": {"permission_sets": "partial", "assignments": "partial", "users": "complete", "groups": "complete", "memberships": "partial"}}
    snap.released_results[0]["aws_coverage"]["per_provider"][PB] = {"identity_center": [member]}
    g = AccessGraph.build(snap)
    cov = g.coverage_summary()
    assert g.ic_complete() is True and not [w for w in cov["warnings"] if "Identity Center" in w]
    assert any(f"completely listed from account {A}" in n for n in cov["notes"]) and any("1 other accounts" in n for n in cov["notes"])
    # with only the member view, the same instance is incomplete
    snap.released_results[0]["aws_coverage"]["per_provider"][P] = {"identity_center": []}
    g2 = AccessGraph.build(snap)
    assert g2.ic_complete() is False and any("has no complete view" in w for w in g2.coverage_summary()["warnings"])


def test_iam_coverage_ignores_billing_views_from_other_accounts(tmp_path: Path) -> None:
    rows = [*estate(), row(PB, f"aws:{A}:global:billing:ec2", "aws/billing_service_cost", {"account": A, "region": "global", "service": "EC2"}, {"amount": 1}, scope=f"{PB}/{B}/global/billing")]
    g = AccessGraph.build(snapshot(tmp_path, rows))
    assert g.accounts[A]["providers"] == [P]
    assert set(g.iam_coverage[A].values()) == {"complete"}


def test_billing_usage_cost_summary_shows_service_usage_type_category_and_amount() -> None:
    from local_ops.opsview import summary

    usage = row(P, "aws:111111111111:global:billing:usage:ec2:box", "aws/billing_usage_cost", {"account": A, "region": "global", "id": "ec2:box", "service": "Amazon Elastic Compute Cloud - Compute", "usage_type": "USW2-BoxUsage:t3.micro"}, {"amount": 40.5, "unit": "USD", "usage_category": "instance", "billing_source_account": A})
    assert summary(usage) == [("service", "Amazon Elastic Compute Cloud - Compute"), ("usage type", "USW2-BoxUsage:t3.micro"), ("category", "instance"), ("amount", 40.5)]


def test_labels_use_own_id_and_self_references_are_dropped(tmp_path: Path) -> None:
    from local_ops.opsview import label

    sg = row(P, arn("security-group", "sg-9"), "aws/security_group", {"account": A, "region": R, "group_id": "sg-9", "vpc_id": "vpc-1", "name": "web"})
    assert label(sg) == "web (sg-9)"
    lb = row(P, "arn:lb", "aws/load_balancer", {"account": A, "region": R, "arn": "arn:lb", "name": "x"}, {"dns_name": "x-1.elb.amazonaws.com"}, [{"kind": "dns", "target": "x-1.elb.amazonaws.com"}])
    snap = snapshot(tmp_path, [lb])
    assert snap.index.neighbours(lb) == []


def test_ec2_summary_fields_cover_volumes_snapshots_images_and_security_groups() -> None:
    from local_ops.opsview import summary

    vol = row(P, arn("volume", "vol-1"), "aws/ebs_volume", {"account": A, "region": R, "arn": arn("volume", "vol-1"), "volume_id": "vol-1"}, {"size_gib": 40, "volume_type": "gp3", "state": "in-use", "encrypted": True, "availability_zone": f"{R}a", "attachments": [{"instance_id": "i-1", "device": "/dev/xvda", "state": "attached"}]})
    vs = dict(summary(vol))
    assert vs["volume"] == "vol-1" and vs["size GiB"] == 40 and vs["type"] == "gp3" and vs["state"] == "in-use"
    assert vs["attachments"] == [{"instance_id": "i-1", "device": "/dev/xvda", "state": "attached"}]

    snap = row(P, arn("snapshot", "snap-1"), "aws/ebs_snapshot", {"account": A, "region": R, "arn": arn("snapshot", "snap-1"), "snapshot_id": "snap-1"}, {"volume_id": "vol-1", "volume_size_gib": 40, "state": "completed", "start_time": "2026-01-01T00:00:00Z", "description": "backup", "encrypted": True})
    ss = dict(summary(snap))
    assert ss["snapshot"] == "snap-1" and ss["size GiB"] == 40 and ss["state"] == "completed" and ss["description"] == "backup"

    image = row(P, arn("image", "ami-1"), "aws/ec2_image", {"account": A, "region": R, "arn": arn("image", "ami-1"), "image_id": "ami-1"}, {"name": "golden", "state": "available", "creation_date": "2026-01-02T00:00:00Z", "public": False, "root_device_name": "/dev/xvda"})
    si = dict(summary(image))
    assert si["image"] == "ami-1" and si["name"] == "golden" and si["state"] == "available" and si["root device"] == "/dev/xvda"
    assert si["public"] is False  # an explicit False is shown; only None/[]/{}/"" are dropped

    open_sg = row(P, arn("security-group", "sg-open"), "aws/security_group", {"account": A, "region": R, "group_id": "sg-open", "vpc_id": "vpc-1", "name": "web"}, {"ingress_rule_count": 2, "egress_rule_count": 1, "ingress_open_to_world": True, "world_open_ports": ["22/tcp", "443/tcp"]})
    so = dict(summary(open_sg))
    assert so["name"] == "web" and so["VPC"] == "vpc-1" and so["ingress rules"] == 2 and so["egress rules"] == 1
    assert so["open to world"] is True and so["world-open ports"] == ["22/tcp", "443/tcp"]

    closed_sg = row(P, arn("security-group", "sg-closed"), "aws/security_group", {"account": A, "region": R, "group_id": "sg-closed", "vpc_id": "vpc-1", "name": "db"}, {"ingress_rule_count": 1, "egress_rule_count": 0, "ingress_open_to_world": False, "world_open_ports": []})
    sc = dict(summary(closed_sg))
    assert sc["open to world"] is False
    assert "world-open ports" not in sc  # an empty list carries nothing to show
