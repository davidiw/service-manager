"""Operational views: approved catalog knowledge rendered over released observations (DECISIONS D25/D26).

This module is a read-time projection. It never calls a provider, never writes state, and never decides
what belongs together: a resource appears under a service only when an approved binding names it exactly
(`discovery.deterministic_binding_match`), and two resources are related only when a provider returned an
exact identifier linking them (an ARN, an AWS resource id, an alias DNS name, a CloudWatch dimension value,
or an A-record value equal to an observed IP). Correlating unbound resources into logical services is the
assistant's job, proposed through `catalog_propose` and approved by a human.

Only observations that passed the release gate are used (`Database.released_observations`); pending and
withheld rows are invisible here, and evidence is linked only when it was released.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from local_ops.catalog import Binding, Catalog, ServiceDoc
from local_ops.discovery import deterministic_binding_match
from local_ops.models import utcnow
from local_ops.storage import Database

STALE_AFTER = timedelta(hours=24)
MAX_RELATED = 300
RELATED_DEPTH = 3
# Shared infrastructure is shown as a neighbour and followed only along its own outgoing references
# (instance profile -> role, subnet -> VPC). Following what points *at* a VPC, a shared role or a shared
# instance profile would pull every sibling resource in the account into one service's page.
HUB_TYPES = {
    "aws/vpc", "aws/subnet", "aws/security_group", "aws/kms_key", "aws/iam_role", "aws/route53_zone",
    "aws/sso_instance", "aws/sso_permission_set", "aws/identitystore_group", "aws/identitystore_user",
    "aws/iam_group", "aws/iam_user", "aws/eks_cluster", "aws/ecs_cluster", "aws/org_account",
    "aws/cloudformation_stack", "aws/nat_gateway", "aws/backup_vault", "aws/iam_instance_profile",
}
LOG_TYPES = {"aws/cloudwatch_log_group"}
ALARM_TYPES = {"aws/cloudwatch_alarm"}
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")

# Safe, normalized fields shown for each resource type (label, where, key). `where` is identity|attributes.
SUMMARY_FIELDS: dict[str, list[tuple[str, str, str]]] = {
    "aws/ec2_instance": [("instance", "identity", "instance_id"), ("state", "attributes", "state"), ("private IP", "attributes", "private_ip"), ("public IP", "attributes", "public_ip"), ("private DNS", "attributes", "private_dns_name"), ("public DNS", "attributes", "public_dns_name"), ("type", "attributes", "type"), ("launched", "attributes", "launch_time"), ("image", "attributes", "image_id"), ("zone", "attributes", "availability_zone"), ("subnet", "attributes", "subnet_id"), ("VPC", "attributes", "vpc_id"), ("security groups", "attributes", "security_groups"), ("volumes", "attributes", "volume_ids"), ("instance profile", "attributes", "iam_instance_profile")],
    "aws/eks_cluster": [("status", "attributes", "status"), ("version", "attributes", "version"), ("endpoint", "attributes", "endpoint"), ("public endpoint", "attributes", "endpoint_public_access"), ("created", "attributes", "created_at"), ("control-plane logging", "attributes", "logging"), ("role", "attributes", "role")],
    "aws/load_balancer": [("DNS", "attributes", "dns_name"), ("scheme", "attributes", "scheme"), ("type", "attributes", "type"), ("state", "attributes", "state"), ("listeners", "attributes", "listeners"), ("created", "attributes", "created_at")],
    "aws/target_group": [("protocol", "attributes", "protocol"), ("port", "attributes", "port"), ("target type", "attributes", "target_type"), ("targets", "attributes", "targets"), ("health check path", "attributes", "health_check_path")],
    "aws/autoscaling_group": [("desired", "attributes", "desired_capacity"), ("min", "attributes", "min_size"), ("max", "attributes", "max_size"), ("instances", "attributes", "instance_ids"), ("launch template", "attributes", "launch_template"), ("created", "attributes", "created_at")],
    "aws/rds_instance": [("engine", "attributes", "engine"), ("version", "attributes", "engine_version"), ("class", "attributes", "class"), ("status", "attributes", "status"), ("endpoint", "attributes", "endpoint"), ("multi-AZ", "attributes", "multi_az"), ("backup retention days", "attributes", "backup_retention_days"), ("created", "attributes", "created_at")],
    "aws/rds_cluster": [("engine", "attributes", "engine"), ("version", "attributes", "engine_version"), ("status", "attributes", "status"), ("endpoint", "attributes", "endpoint"), ("reader endpoint", "attributes", "reader_endpoint"), ("members", "attributes", "members"), ("created", "attributes", "created_at")],
    "aws/lambda_function": [("runtime", "attributes", "runtime"), ("last modified", "attributes", "last_modified"), ("role", "attributes", "role"), ("log group", "attributes", "log_group")],
    "aws/cloudwatch_log_group": [("retention days", "attributes", "retention_days"), ("stored bytes", "attributes", "stored_bytes"), ("created", "attributes", "created_at")],
    "aws/cloudwatch_alarm": [("state", "attributes", "state"), ("namespace", "attributes", "namespace"), ("metric", "attributes", "metric_name"), ("dimensions", "attributes", "dimensions"), ("threshold", "attributes", "threshold"), ("actions", "attributes", "actions")],
    "aws/s3_bucket": [("region", "identity", "region"), ("created", "attributes", "created_at")],
    "aws/route53_record": [("type", "identity", "type"), ("values", "attributes", "values"), ("alias target", "attributes", "alias_target"), ("TTL", "attributes", "ttl")],
    "aws/ecs_service": [("status", "attributes", "status"), ("desired", "attributes", "desired_count"), ("running", "attributes", "running_count"), ("task definition", "attributes", "task_definition"), ("created", "attributes", "created_at")],
    "aws/iam_role": [("class", "attributes", "role_class"), ("trusted principals", "attributes", "trust_principals"), ("attached policies", "attributes", "attached_policies"), ("last used", "attributes", "last_used_at")],
    "aws/iam_service_specific_credential": [("user", "identity", "user"), ("service", "identity", "service_name"), ("status", "attributes", "status"), ("created", "attributes", "created_at")],
    "aws/eks_access_entry": [("cluster", "identity", "cluster"), ("principal", "identity", "principal_arn"), ("policies", "attributes", "associated_policies"), ("scope", "attributes", "access_scope_types")],
    "aws/ebs_volume": [("volume", "identity", "volume_id"), ("size GiB", "attributes", "size_gib"), ("type", "attributes", "volume_type"), ("state", "attributes", "state"), ("encrypted", "attributes", "encrypted"), ("attachments", "attributes", "attachments"), ("zone", "attributes", "availability_zone")],
    "aws/ebs_snapshot": [("snapshot", "identity", "snapshot_id"), ("volume", "attributes", "volume_id"), ("size GiB", "attributes", "volume_size_gib"), ("state", "attributes", "state"), ("started", "attributes", "start_time"), ("description", "attributes", "description"), ("encrypted", "attributes", "encrypted")],
    "aws/ec2_image": [("image", "identity", "image_id"), ("name", "attributes", "name"), ("state", "attributes", "state"), ("created", "attributes", "creation_date"), ("public", "attributes", "public"), ("root device", "attributes", "root_device_name")],
    "aws/security_group": [("name", "identity", "name"), ("VPC", "identity", "vpc_id"), ("ingress rules", "attributes", "ingress_rule_count"), ("egress rules", "attributes", "egress_rule_count"), ("open to world", "attributes", "ingress_open_to_world"), ("world-open ports", "attributes", "world_open_ports")],
    "aws/billing_usage_cost": [("service", "identity", "service"), ("usage type", "identity", "usage_type"), ("category", "attributes", "usage_category"), ("amount", "attributes", "amount")],
}

# CloudWatch metric identity for a resource type: AWS-defined namespace and dimension, never a guessed metric.
CLOUDWATCH_DIMENSIONS: dict[str, list[tuple[str, str, str, str]]] = {
    # resource type: [(namespace, dimension, where, key)]
    "aws/ec2_instance": [("AWS/EC2", "InstanceId", "identity", "instance_id")],
    "aws/autoscaling_group": [("AWS/EC2", "AutoScalingGroupName", "identity", "name")],
    "aws/rds_instance": [("AWS/RDS", "DBInstanceIdentifier", "identity", "identifier")],
    "aws/rds_cluster": [("AWS/RDS", "DBClusterIdentifier", "identity", "identifier")],
    "aws/lambda_function": [("AWS/Lambda", "FunctionName", "identity", "name")],
    "aws/dynamodb_table": [("AWS/DynamoDB", "TableName", "identity", "name")],
}


def _get(row: dict[str, Any], where: str, key: str) -> Any:
    return (row.get(where) or {}).get(key)


def _parse(ts: Any) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _norm_dns(name: Any) -> str | None:
    """AWS alias targets carry a trailing dot and an optional `dualstack.` prefix; both name the same endpoint."""
    if not name:
        return None
    s = str(name).strip().lower().rstrip(".")
    return s.removeprefix("dualstack.") or None


def _elb_suffix(arn: str, marker: str) -> str | None:
    # arn:aws:elasticloadbalancing:region:acct:loadbalancer/app/name/id -> app/name/id (CloudWatch LoadBalancer dimension)
    _, sep, rest = arn.partition(f":{marker}/")
    return rest if sep else None


def label(row: dict[str, Any]) -> str:
    ident = row.get("identity") or {}
    attrs = row.get("attributes") or {}
    tags = attrs.get("tags") if isinstance(attrs.get("tags"), dict) else {}
    name = attrs.get("name") or (tags or {}).get("Name") or ident.get("name") or ident.get("user_name") or ident.get("identifier")
    # the resource's own id, not a parent id it also carries (a security group or subnet also names its VPC)
    rid = ident.get("instance_id") or ident.get("volume_id") or ident.get("subnet_id") or (ident.get("group_id") if row.get("resource_type") == "aws/security_group" else None) or ident.get("key_id") or ident.get("vpc_id")
    if name and rid and name != rid:
        return f"{name} ({rid})"
    return str(name or rid or row.get("resource_key"))


def account_of(row: dict[str, Any]) -> str | None:
    ident = row.get("identity") or {}
    return str(ident.get("account") or ident.get("cluster_identity") or "") or None


def region_of(row: dict[str, Any]) -> str | None:
    ident = row.get("identity") or {}
    return ident.get("region")


def summary(row: dict[str, Any]) -> list[tuple[str, Any]]:
    rt = row.get("resource_type", "")
    out: list[tuple[str, Any]] = []
    if rt.startswith("k8s/"):
        a = row.get("attributes") or {}
        out = [("namespace", _get(row, "identity", "namespace")), ("kind", _get(row, "identity", "kind")), ("images", [d.get("image") for d in a.get("desired_images") or []]), ("rollout", a.get("rollout")), ("running", [f"{r.get('pod')} ready={r.get('ready')} restarts={r.get('restart_count')}" for r in a.get("running") or []]), ("ownership", (a.get("ownership") or {}).get("mechanism"))]
    else:
        for lbl, where, key in SUMMARY_FIELDS.get(rt, []):
            out.append((lbl, _get(row, where, key)))
        if not out:
            a = row.get("attributes") or {}
            for k in ("status", "state", "created_at"):
                if a.get(k) is not None:
                    out.append((k, a.get(k)))
    tags = (row.get("attributes") or {}).get("tags")
    if isinstance(tags, dict) and tags:
        out.append(("tags", tags))
    return [(k, v) for k, v in out if v not in (None, [], {}, "")]


def freshness(row: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    seen = _parse(row.get("last_seen_at"))
    missing = row.get("missing_since")
    age = (now - seen) if seen else None
    if missing:
        state = "missing"
    elif age is None:
        state = "unknown"
    elif age > STALE_AFTER:
        state = "stale"
    else:
        state = "current"
    return {"state": state, "last_seen_at": row.get("last_seen_at"), "first_seen_at": row.get("first_seen_at"), "missing_since": missing, "age_hours": round(age.total_seconds() / 3600, 1) if age else None, "scan_request_id": row.get("scan_request_id")}


# ---------------------------------------------------------------------------- coverage
@dataclass
class CoverageIndex:
    """Completeness of scope keys from released scans, most recent first. A scope is `complete` only when
    the latest released scan that covered its provider listed it as completed; an unavailable source at or
    under the scope makes it `unavailable`; otherwise the latest scan left it `partial_or_not_attempted`."""

    scans: list[dict[str, Any]] = field(default_factory=list)

    def status(self, provider_id: str, scope_key: str | None) -> dict[str, Any]:
        if not scope_key:
            return {"status": "unknown", "detail": "observation has no scope key"}
        for s in self.scans:
            if provider_id not in (s.get("provider_ids") or []):
                continue
            completed = set(s.get("completed_scopes") or [])
            if scope_key in completed:
                return {"status": "complete", "scan_request_id": s["request_id"], "finished_at": s.get("finished_at")}
            bad = [u for u in s.get("unavailable") or [] if str(u.get("source", "")) == scope_key or str(u.get("source", "")).startswith(scope_key + "/")]
            if bad:
                return {"status": "unavailable" if any(str(u.get("source")) == scope_key for u in bad) else "partial", "scan_request_id": s["request_id"], "finished_at": s.get("finished_at"), "reasons": sorted({str(u.get("reason")) for u in bad})}
            return {"status": "partial_or_not_attempted", "scan_request_id": s["request_id"], "finished_at": s.get("finished_at")}
        return {"status": "never_scanned"}


# ---------------------------------------------------------------------------- index
class ObservationIndex:
    def __init__(self, rows: list[dict[str, Any]]):
        self.rows = rows
        self.by_pk: dict[tuple[str, str], dict[str, Any]] = {}
        self.by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.alias: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)  # (account, alias)
        self.ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.dns: dict[str, list[dict[str, Any]]] = defaultdict(list)  # endpoint DNS names are globally unique
        for r in rows:
            self.by_pk[(r["provider_id"], r["resource_key"])] = r
            self.by_key[r["resource_key"]].append(r)
            acct = account_of(r) or ""
            for a in self._aliases(r):
                self.alias[(acct, a)].append(r)
                if a.startswith("dns:"):
                    self.dns[a.removeprefix("dns:")].append(r)
            if r["resource_type"] == "aws/ec2_instance":
                for k in ("private_ip", "public_ip"):
                    ip = _get(r, "attributes", k)
                    if ip:
                        self.ip[str(ip)].append(r)
        self._edges: dict[tuple[str, str], list[dict[str, Any]]] | None = None
        self._reverse: dict[tuple[str, str], list[dict[str, Any]]] | None = None

    @staticmethod
    def _aliases(r: dict[str, Any]) -> set[str]:
        ident = r.get("identity") or {}
        attrs = r.get("attributes") or {}
        rt = r["resource_type"]
        out: set[str] = set()
        if ident.get("arn"):
            out.add(str(ident["arn"]))
        for k in ("instance_id", "volume_id", "vpc_id", "subnet_id", "key_id", "nat_gateway_id", "zone_id", "instance_profile_id"):
            if ident.get(k):
                out.add(str(ident[k]))
        if rt == "aws/security_group" and ident.get("group_id"):
            out.add(str(ident["group_id"]))
        if ident.get("name_key"):
            out.add(str(ident["name_key"]))
        if rt == "aws/cloudwatch_log_group":
            arn = str(ident.get("arn") or r["resource_key"])
            out.add(arn.removesuffix(":*"))
            if ident.get("name"):
                out.add(f"loggroup:{ident['name']}")
        if rt == "aws/lambda_function" and ident.get("name"):
            out.add(f"lambda:{ident['name']}")
        if rt == "aws/rds_instance" and ident.get("identifier"):
            out.add(f"rds:db:{ident['identifier']}")
        if rt == "aws/rds_cluster" and ident.get("identifier"):
            out.add(f"rds:cluster:{ident['identifier']}")
        if rt == "aws/dynamodb_table" and ident.get("name"):
            out.add(f"dynamodb:{ident['name']}")
        if rt == "aws/autoscaling_group" and ident.get("name"):
            out.add(f"asg:{ident['name']}")
        if rt == "aws/load_balancer":
            if (sfx := _elb_suffix(str(ident.get("arn") or ""), "loadbalancer")):
                out.add(f"elb:{sfx}")
            if (d := _norm_dns(attrs.get("dns_name"))):
                out.add(f"dns:{d}")
        if rt == "aws/target_group" and (sfx := _elb_suffix(str(ident.get("arn") or ""), "targetgroup")):
            out.add(f"tg:targetgroup/{sfx}")
        if rt == "aws/cloudfront_distribution" and (d := _norm_dns(attrs.get("domain_name"))):
            out.add(f"dns:{d}")
        if rt == "aws/rds_instance" and attrs.get("endpoint"):
            out.add(f"dns:{_norm_dns(str(attrs['endpoint']).rsplit(':', 1)[0])}")
        return out

    def get(self, provider_id: str, resource_key: str) -> dict[str, Any] | None:
        return self.by_pk.get((provider_id, resource_key))

    def resolve(self, target: str, source: dict[str, Any]) -> list[dict[str, Any]]:
        """Observations an exact relationship target names, preferring the source's provider/account."""
        if not target:
            return []
        exact = self.by_key.get(target) or []
        if exact:
            same = [r for r in exact if r["provider_id"] == source["provider_id"]]
            return same or exact
        acct = account_of(source) or ""
        hits = self.alias.get((acct, target)) or self.alias.get((acct, target.removesuffix(":*"))) or []
        if not hits and target.startswith("arn:"):
            # an ARN names its own account; resolve it there (cross-account references)
            parts = target.split(":")
            if len(parts) > 4:
                hits = self.alias.get((parts[4], target)) or []
        if not hits and target.startswith("/"):
            # ECS awslogs-group and log-alarm identifiers name a log group (unique per account/region)
            hits = [r for r in self.alias.get((acct, f"loggroup:{target}")) or [] if region_of(r) == region_of(source)]
        return hits

    def _resolve_metric(self, target: str, source: dict[str, Any]) -> list[dict[str, Any]]:
        # aws:metric:<namespace>:<metric>:<Dimension>=<value>
        _, _, rest = target.partition("aws:metric:")
        _ns, _, rest = rest.partition(":")
        _metric, _, dim = rest.partition(":")
        dname, _, dval = dim.partition("=")
        acct = account_of(source) or ""
        key = {
            "InstanceId": dval, "AutoScalingGroupName": f"asg:{dval}", "DBInstanceIdentifier": f"rds:db:{dval}",
            "DBClusterIdentifier": f"rds:cluster:{dval}", "FunctionName": f"lambda:{dval}", "TableName": f"dynamodb:{dval}",
            "LoadBalancer": f"elb:{dval}", "TargetGroup": f"tg:{dval}",
        }.get(dname)
        if key is None or (dname == "InstanceId" and not dval.startswith("i-")):
            return []
        return [r for r in self.alias.get((acct, key)) or [] if region_of(r) == region_of(source)]

    def edges(self) -> dict[tuple[str, str], list[dict[str, Any]]]:
        """Resolved outgoing edges per observation: [{kind, target, basis, row|None}]."""
        if self._edges is not None:
            return self._edges
        out: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        rev: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for r in self.rows:
            src = (r["provider_id"], r["resource_key"])
            for rel in (r.get("attributes") or {}).get("relationships") or []:
                kind, target = str(rel.get("kind")), str(rel.get("target"))
                if target.startswith("aws:metric:"):
                    hits, basis = self._resolve_metric(target, r), "CloudWatch dimension value"
                else:
                    hits, basis = self.resolve(target, r), "provider identifier"
                    if not hits and kind == "dns":
                        hits, basis = self.dns.get(_norm_dns(target) or "", []), "alias DNS name"
                if any(h is r for h in hits):
                    hits = [h for h in hits if h is not r]  # a resource naming its own endpoint is not a relationship
                    if not hits:
                        continue
                if hits:
                    for h in hits:
                        e = {"kind": kind, "target": target, "basis": basis, "row": h}
                        out[src].append(e)
                        rev[(h["provider_id"], h["resource_key"])].append({"kind": kind, "target": target, "basis": basis, "row": r})
                else:
                    out[src].append({"kind": kind, "target": target, "basis": "unresolved: not among released observations", "row": None})
            if r["resource_type"] == "aws/route53_record" and _get(r, "identity", "type") in ("A", "AAAA"):
                for v in _get(r, "attributes", "values") or []:
                    for h in self.ip.get(str(v), []):
                        if h.get("attributes", {}).get("private_ip") == v and account_of(h) != account_of(r):
                            continue  # private addresses are only comparable inside one account
                        out[src].append({"kind": "resolves_to", "target": str(v), "basis": "A-record value equals observed instance IP", "row": h})
                        rev[(h["provider_id"], h["resource_key"])].append({"kind": "resolves_to", "target": str(v), "basis": "A-record value equals observed instance IP", "row": r})
        self._edges, self._reverse = out, rev
        return out

    def reverse(self) -> dict[tuple[str, str], list[dict[str, Any]]]:
        self.edges()
        assert self._reverse is not None
        return self._reverse

    def neighbours(self, row: dict[str, Any]) -> list[dict[str, Any]]:
        pk = (row["provider_id"], row["resource_key"])
        return [{**e, "direction": "out"} for e in self.edges().get(pk, [])] + [{**e, "direction": "in"} for e in self.reverse().get(pk, [])]

    def related(self, roots: list[dict[str, Any]], depth: int = RELATED_DEPTH) -> list[dict[str, Any]]:
        """Resources reachable from the roots through resolved provider relationships (both directions),
        following shared hubs outward only. Each entry records the chain of edges that connects it."""
        seen = {(r["provider_id"], r["resource_key"]) for r in roots}
        frontier: list[tuple[dict[str, Any], list[dict[str, Any]]]] = [(r, []) for r in roots]
        found: list[dict[str, Any]] = []
        for _ in range(depth):
            nxt: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
            for row, path in frontier:
                hub = row["resource_type"] in HUB_TYPES and bool(path)
                for e in self.neighbours(row):
                    h = e["row"]
                    if h is None or (hub and e["direction"] == "in"):
                        # a shared hub's own references (profile -> role, subnet -> VPC) are followed; the
                        # other resources that point at it are siblings, not part of this service
                        continue
                    pk = (h["provider_id"], h["resource_key"])
                    if pk in seen:
                        continue
                    seen.add(pk)
                    chain = [*path, {"from": label(row), "kind": e["kind"], "direction": e["direction"], "basis": e["basis"]}]
                    found.append({"row": h, "chain": chain})
                    nxt.append((h, chain))
                    if len(found) >= MAX_RELATED:
                        return found
            frontier = nxt
        return found


# ---------------------------------------------------------------------------- snapshot
@dataclass
class Snapshot:
    catalog: Catalog
    index: ObservationIndex
    coverage: CoverageIndex
    released_results: list[dict[str, Any]]
    provider_kinds: dict[str, str]
    pending_release: int = 0
    now: datetime = field(default_factory=utcnow)


async def load_snapshot(db: Database, catalog: Catalog, provider_kinds: dict[str, str], *, audience: str | None = None, result_scans: int = 10) -> Snapshot:
    """Released observations (to `audience`, or to anyone for the local operator) plus released scan coverage."""
    rows = await db.released_observations(audience=audience)
    scans: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for s in await db.scans(200):
        if not s.get("finished_at"):
            continue
        req = await db.request(s["request_id"])
        if not req or req["response_status"] != "released":
            continue
        if audience is not None and audience != req["principal_id"] and audience not in req["audience"]:
            continue
        scans.append(s)
        if len(results) < result_scans:
            res = await db.result(s["request_id"])
            released = (res or {}).get("released") or {}
            results.append({"request_id": s["request_id"], "finished_at": s.get("finished_at"), "provider_ids": s.get("provider_ids") or [], "aws_coverage": released.get("aws_coverage") or {}, "summary": released.get("summary") or {}})
    total = await db.fetchone("SELECT COUNT(*) AS n FROM observations WHERE released_to = '[]'")
    return Snapshot(catalog=catalog, index=ObservationIndex(rows), coverage=CoverageIndex(scans), released_results=results, provider_kinds=provider_kinds, pending_release=int((total or {}).get("n") or 0))


# ---------------------------------------------------------------------------- bindings and services
def resolve_binding(b: Binding, index: ObservationIndex) -> list[tuple[dict[str, Any], str]]:
    out = []
    for r in index.rows:
        m = deterministic_binding_match(b, r["provider_id"], r["resource_key"], r["resource_type"], r.get("identity") or {}, r.get("attributes") or {})
        if m:
            out.append((r, m[0]))
    return out


def _resource_card(row: dict[str, Any], snap: Snapshot, basis: str | None = None, binding_id: str | None = None) -> dict[str, Any]:
    return {
        "provider_id": row["provider_id"], "resource_key": row["resource_key"], "resource_type": row["resource_type"], "label": label(row),
        "account": account_of(row), "region": region_of(row), "summary": summary(row), "freshness": freshness(row, snap.now),
        "coverage": snap.coverage.status(row["provider_id"], row.get("scope_key")), "evidence_id": row.get("evidence_id"),
        "basis": basis, "binding_id": binding_id,
        "cluster": _get(row, "identity", "cluster_identity"), "namespace": _get(row, "identity", "namespace"),
    }


def environments(snap: Snapshot) -> list[dict[str, Any]]:
    envs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sid, doc in sorted(snap.catalog.services.items()):
        s = doc.spec
        names = sorted(set(s.environments) | {b.environment for b in s.bindings}) or ["(no environment recorded)"]
        bound = {b.id: resolve_binding(b, snap.index) for b in s.bindings}
        for env in names:
            env_bindings = [b for b in s.bindings if b.environment == env] if env != "(no environment recorded)" else []
            rows = [r for b in env_bindings for r, _ in bound[b.id]]
            states: dict[str, int] = defaultdict(int)
            for r in rows:
                states[freshness(r, snap.now)["state"]] += 1
            running = sum(1 for r in rows if r["resource_type"] == "aws/ec2_instance" and _get(r, "attributes", "state") == "running")
            warnings = []
            for b in env_bindings:
                if not bound[b.id]:
                    warnings.append(f"binding {b.id} resolves to no released observation")
            if states.get("stale") or states.get("missing"):
                warnings.append(f"{states.get('stale', 0)} stale, {states.get('missing', 0)} missing resources")
            if not env_bindings:
                warnings.append("no binding in this environment; where it runs is unknown")
            if not s.owner:
                warnings.append("owner unknown")
            if s.unknowns:
                warnings.append(f"{len(s.unknowns)} recorded unknowns")
            envs[env].append({"service_id": sid, "name": s.name, "disposition": s.disposition, "owner": s.owner, "purpose": s.purpose, "resources": len(rows), "running_instances": running, "freshness": dict(states), "warnings": warnings})
    return [{"environment": e, "services": v} for e, v in sorted(envs.items())]


def unmapped_summary(snap: Snapshot) -> list[dict[str, Any]]:
    """Released observations no approved binding names, counted by provider/account/type (inventory)."""
    bound: set[tuple[str, str]] = set()
    for doc in snap.catalog.services.values():
        for b in doc.spec.bindings:
            bound |= {(r["provider_id"], r["resource_key"]) for r, _ in resolve_binding(b, snap.index)}
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in snap.index.rows:
        if (r["provider_id"], r["resource_key"]) not in bound:
            counts[(r["provider_id"], account_of(r) or "")][r["resource_type"]] += 1
    return [{"provider_id": p, "account": a, "types": dict(sorted(t.items(), key=lambda kv: -kv[1]))} for (p, a), t in sorted(counts.items())]


def service_view(doc: ServiceDoc, snap: Snapshot) -> dict[str, Any]:
    s = doc.spec
    cat = snap.catalog
    bindings: list[dict[str, Any]] = []
    bound_rows: list[dict[str, Any]] = []
    for b in s.bindings:
        hits = resolve_binding(b, snap.index)
        bound_rows += [r for r, _ in hits]
        bindings.append({"binding": b.model_dump(mode="json"), "resources": [_resource_card(r, snap, basis, b.id) for r, basis in hits], "resolved": len(hits)})
    # Where it runs: provider -> account -> region -> cluster/namespace -> type
    where: dict[str, dict[str, dict[str, dict[str, dict[str, list[dict[str, Any]]]]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list)))))
    for bv in bindings:
        for card in bv["resources"]:
            loc = "/".join(x for x in (card.get("cluster"), card.get("namespace")) if x) or "-"
            where[card["provider_id"]][card.get("account") or "?"][card.get("region") or "?"][loc][card["resource_type"]].append(card)
    related = snap.index.related(bound_rows)
    rel_cards = [{**_resource_card(x["row"], snap), "chain": x["chain"]} for x in related]
    in_scope = bound_rows + [x["row"] for x in related]
    edges = []
    for r in bound_rows:
        for e in snap.index.neighbours(r):
            edges.append({"from": label(r), "from_key": r["resource_key"], "kind": e["kind"], "direction": e["direction"], "to": label(e["row"]) if e["row"] else e["target"], "to_key": e["row"]["resource_key"] if e["row"] else None, "to_provider": e["row"]["provider_id"] if e["row"] else None, "basis": e["basis"]})
    return {
        "spec": s.model_dump(mode="json"), "path": doc.path, "notes": doc.body, "dependents": cat.dependents_of(s.id),
        "bindings": bindings, "where": _plain(where), "related": rel_cards, "edges": edges,
        "logs": _logs(s, bound_rows, in_scope, snap), "metrics": _metrics(s, bound_rows, snap), "alerts": _alerts(s, in_scope, snap),
        "access": _access(s, bound_rows, in_scope, snap), "operations": _operations(s, cat),
        "unknowns": _unknowns(s, bindings, cat), "freshness": _freshness_summary(bound_rows, snap),
    }


def _plain(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _plain(v) for k, v in d.items()}
    return d


def _logs(s: Any, bound: list[dict[str, Any]], scope: list[dict[str, Any]], snap: Snapshot) -> dict[str, Any]:
    approved = [o.model_dump(mode="json") for o in s.observability if o.kind in ("logs", "events")]
    queries = [q.model_dump(mode="json") for q in s.knowledge.queries if "log" in q.query_type]
    groups = []
    for r in scope:
        if r["resource_type"] in LOG_TYPES:
            groups.append({"name": _get(r, "identity", "name"), "resource_key": r["resource_key"], "provider_id": r["provider_id"], "retention_days": _get(r, "attributes", "retention_days"), "stored_bytes": _get(r, "attributes", "stored_bytes"), "freshness": freshness(r, snap.now)})
    declared = []
    for r in bound:
        if r["resource_type"] == "aws/eks_cluster":
            declared.append({"resource": label(r), "control_plane_logging": _get(r, "attributes", "logging"), "log_group": _get(r, "attributes", "control_plane_log_group")})
        if r["resource_type"] == "aws/lambda_function" and _get(r, "attributes", "log_group"):
            declared.append({"resource": label(r), "log_group": _get(r, "attributes", "log_group")})
        if r["resource_type"].startswith("k8s/"):
            declared.append({"resource": label(r), "note": "container logs live in the cluster; no log source is mapped unless the catalog records one"})
    unmapped = not approved and not groups and not queries
    return {"approved": approved, "saved_queries": queries, "observed_log_groups": groups, "declared_by_resource": declared, "unmapped": unmapped}


def _metrics(s: Any, bound: list[dict[str, Any]], snap: Snapshot) -> dict[str, Any]:
    approved = [o.model_dump(mode="json") for o in s.observability if o.kind in ("metrics", "dashboard")]
    queries = [q.model_dump(mode="json") for q in s.knowledge.queries if "metric" in q.query_type]
    ids = []
    for r in bound:
        for ns, dim, where, key in CLOUDWATCH_DIMENSIONS.get(r["resource_type"], []):
            v = _get(r, where, key)
            if v:
                ids.append({"resource": label(r), "provider_id": r["provider_id"], "namespace": ns, "dimension": dim, "value": v, "region": region_of(r)})
    return {"approved": approved, "saved_queries": queries, "cloudwatch_identifiers": ids, "unmapped": not approved and not queries}


def _alerts(s: Any, scope: list[dict[str, Any]], snap: Snapshot) -> dict[str, Any]:
    approved = [o.model_dump(mode="json") for o in s.observability if o.kind in ("alerts", "oncall")]
    alarms = []
    for r in scope:
        if r["resource_type"] in ALARM_TYPES:
            alarms.append({"name": _get(r, "identity", "name"), "resource_key": r["resource_key"], "provider_id": r["provider_id"], "state": _get(r, "attributes", "state"), "reason": _get(r, "attributes", "reason"), "metric": f"{_get(r, 'attributes', 'namespace')}/{_get(r, 'attributes', 'metric_name')}", "actions": _get(r, "attributes", "actions") or [], "freshness": freshness(r, snap.now)})
    checks = [h.model_dump(mode="json") for h in s.health_checks]
    return {"approved": approved, "alarms": alarms, "health_checks": checks, "unmapped": not approved and not alarms and not checks}


def _access(s: Any, bound: list[dict[str, Any]], scope: list[dict[str, Any]], snap: Snapshot) -> dict[str, Any]:
    from local_ops.access import AccessGraph

    graph = AccessGraph.build(snap)
    accounts = sorted({a for r in bound if (a := _get(r, "identity", "account")) and str(r["provider_id"]) in snap.provider_kinds and snap.provider_kinds[str(r["provider_id"])] == "aws"})
    machine = []
    for r in scope:
        if r["resource_type"] == "aws/iam_role" and _get(r, "attributes", "role_class") != "identity_center":
            machine.append({"role": label(r), "resource_key": r["resource_key"], "trusted": _get(r, "attributes", "trust_principals")})
    refs = []
    for c in s.credential_refs:
        observed = [r for r in snap.index.rows if r["resource_type"] == "onepassword/item" and (c.id in (r["resource_key"], _get(r, "identity", "item_id")) or (c.resolver_id and c.resolver_id in (r["resource_key"], _get(r, "identity", "item_id"))))]
        refs.append({**c.model_dump(mode="json"), "observed": [{"title": _get(o, "identity", "title"), "vault_id": _get(o, "identity", "vault_id"), "freshness": freshness(o, snap.now)} for o in observed]})
    return {"accounts": [graph.account_access(a) for a in accounts], "machine_identities": machine, "credential_refs": refs, "coverage": graph.coverage_summary()}


def _operations(s: Any, cat: Catalog) -> dict[str, Any]:
    ops = []
    for name, op in s.operations.items():
        b = s.binding(op.binding_id)
        ops.append({"name": name, "executor": op.executor, "kind": op.kind, "binding_id": op.binding_id, "health_checks": op.health_checks, "executable": bool(b and b.execution_enabled and cat.meta.execution_allowed)})
    return {"restart_procedure": s.restart_procedure, "operations": ops, "note": "Displayed for reference only. Running an operation goes through the execution capability and its review gate; this page has no controls."}


def _unknowns(s: Any, bindings: list[dict[str, Any]], cat: Catalog) -> list[dict[str, Any]]:
    out = [{"kind": "recorded_unknown", "detail": u} for u in s.unknowns]
    out += [{"kind": "contradiction", "detail": f"{c.topic}: " + " | ".join(cl.statement for cl in c.claims)} for c in s.contradictions if c.status == "unresolved"]
    out += [{"kind": g["kind"], "detail": g["detail"]} for g in cat.gaps() if g.get("service_id") == s.id and g["kind"] not in ("unknown", "contradiction")]
    for bv in bindings:
        if not bv["resolved"]:
            out.append({"kind": "binding_unresolved", "detail": f"binding {bv['binding']['id']} names no released observation (not scanned, not released, or gone)"})
    return out


def _freshness_summary(rows: list[dict[str, Any]], snap: Snapshot) -> dict[str, Any]:
    states: dict[str, int] = defaultdict(int)
    newest = oldest = None
    for r in rows:
        f = freshness(r, snap.now)
        states[f["state"]] += 1
        ts = r.get("last_seen_at")
        if ts:
            newest = max(newest or ts, ts)
            oldest = min(oldest or ts, ts)
    return {"states": dict(states), "newest_observation": newest, "oldest_observation": oldest, "pending_release_rows": snap.pending_release}


def resource_view(row: dict[str, Any], snap: Snapshot) -> dict[str, Any]:
    services = []
    for sid, doc in snap.catalog.services.items():
        for b in doc.spec.bindings:
            m = deterministic_binding_match(b, row["provider_id"], row["resource_key"], row["resource_type"], row.get("identity") or {}, row.get("attributes") or {})
            if m:
                services.append({"service_id": sid, "binding_id": b.id, "environment": b.environment, "basis": m[0]})
    stored = None
    if row.get("match_service_id") and row.get("match_confidence") == "inferred":
        stored = {"service_id": row["match_service_id"], "binding_id": row.get("match_binding_id"), "basis": row.get("match_basis"), "note": "scan-time inferred candidate; not an approved binding"}
    neighbours = [{"kind": e["kind"], "direction": e["direction"], "basis": e["basis"], "target": e["target"], "row": _resource_card(e["row"], snap) if e["row"] else None} for e in snap.index.neighbours(row)]
    attrs = {k: v for k, v in (row.get("attributes") or {}).items() if k not in ("relationships", "also_matches")}
    return {"card": _resource_card(row, snap), "identity": row.get("identity") or {}, "attributes": attrs, "services": services, "inferred_candidate": stored, "neighbours": neighbours}


def inventory(snap: Snapshot, *, provider_id: str | None = None, resource_type: str | None = None, account: str | None = None, limit: int = 500) -> dict[str, Any]:
    counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    rows = []
    for r in snap.index.rows:
        counts[(r["provider_id"], account_of(r) or "")][r["resource_type"]] += 1
        if (provider_id is None or r["provider_id"] == provider_id) and (resource_type is None or r["resource_type"] == resource_type) and (account is None or account_of(r) == account):
            rows.append(r)
    listing = [_resource_card(r, snap) for r in rows[:limit]] if (provider_id or resource_type or account) else []
    return {"counts": [{"provider_id": p, "account": a, "types": dict(sorted(t.items()))} for (p, a), t in sorted(counts.items())], "rows": listing, "total": len(rows), "truncated": len(rows) > limit}
