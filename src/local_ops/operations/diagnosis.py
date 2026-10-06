"""Diagnosis operations: service_inspect, evidence_query (discriminated union) and investigation_run
(deterministic recipes and explainable rules). Observations, hypotheses, next queries and possible
remediation are kept separate; nothing here invokes a model."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from local_ops.audit import merge_coverage, run_rules
from local_ops.catalog import Catalog
from local_ops.config import ServerConfig
from local_ops.models import (
    Coverage,
    DataClass,
    Effect,
    ErrorCode,
    ExecutionStatus,
    Hypothesis,
    Limits,
    OpsError,
    PossibleAction,
    StrictModel,
    SuggestedQuery,
    TimeRange,
    UnavailableScope,
    iso,
    utcnow,
)
from local_ops.operations.base import OperationContext, OperationOutcome, OperationRegistry, OperationSpec
from local_ops.providers.base import EvidenceResult

QueryType = Literal["cloudtrail_events", "cloudwatch_logs", "cloudwatch_metrics", "loki_logs", "prometheus_metrics", "kubernetes_events", "container_logs", "github_audit", "github_workflow_runs", "github_commit", "github_runs_for_sha", "github_file", "onepassword_events", "kubernetes_audit", "guardduty_findings", "pagerduty_incidents", "pagerduty_configuration", "pagerduty_users", "demo_logs", "local_import", "registry_manifest", "s3_object_index"]
EFFECTS: dict[str, Effect] = {"cloudwatch_logs": Effect.READ_WITH_BOOKKEEPING, "loki_logs": Effect.READ}


# Scope shape every adapter of a query type needs, checked when a request is submitted so a malformed
# query fails synchronously instead of after review. Adapters keep their own checks for recipe calls.
# Each entry is (alternative key names, description); a metric query must name namespace and metric_name.
SCOPE_REQUIREMENTS: dict[str, list[tuple[tuple[str, ...], str]]] = {
    "cloudwatch_logs": [(("log_groups",), "log_groups: [name, ...]")],
    "cloudwatch_metrics": [(("queries",), "queries: [{namespace, metric_name, dimensions?: {name: value}, period?: seconds, stat?, id?}, ...] (at most 20)")],
    "kubernetes_events": [(("namespace",), "namespace")],
    "container_logs": [(("namespace",), "namespace"), (("pod", "workload_name"), "pod, or workload_name with workload_kind (default Deployment)")],
    "github_workflow_runs": [(("repository", "repo"), "repository: owner/name")],
    "github_commit": [(("repository", "repo"), "repository: owner/name"), (("sha",), "sha: full or prefix commit SHA")],
    "github_runs_for_sha": [(("repository", "repo"), "repository: owner/name"), (("sha",), "sha: full commit SHA")],
    "github_file": [(("repository", "repo"), "repository: owner/name"), (("path",), "path: one allowlisted in-repository path")],
    "registry_manifest": [(("image",), "image: repo[:tag][@sha256:digest]")],
    "s3_object_index": [(("bucket",), "bucket: one allowlisted bucket name (optional prefix, group_depth)")],
    "pagerduty_configuration": [(("resource_type",), "resource_type: schedule, escalation_policy, service, or user"), (("resource_id",), "resource_id: exact PagerDuty resource id")],
}
MAX_METRIC_QUERIES = 20
SCOPE_DESCRIPTION = "Provider scope, e.g. region/regions/namespace. Required per query_type: " + "; ".join(f"{qt}: " + ", ".join(d for _, d in reqs) for qt, reqs in SCOPE_REQUIREMENTS.items()) + "."


class EvidenceQueryArgs(StrictModel):
    source_id: str = Field(description="Configured provider id")
    query_type: QueryType
    scope: dict[str, Any] = Field(default_factory=dict, description=SCOPE_DESCRIPTION)
    time_range: TimeRange | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    limits: Limits = Field(default_factory=Limits)
    reason: str | None = None
    saved_query: str | None = Field(default=None, description="Set by the server when expanded from a catalog saved query: service/query@revision")

    @model_validator(mode="after")
    def _scope_shape(self) -> EvidenceQueryArgs:
        for keys, desc in SCOPE_REQUIREMENTS.get(self.query_type, []):
            if not any(self.scope.get(k) for k in keys):
                raise ValueError(f"{self.query_type} requires scope.{desc}")
        if self.query_type == "cloudwatch_metrics":
            queries = self.scope["queries"]
            if not isinstance(queries, list) or len(queries) > MAX_METRIC_QUERIES:
                raise ValueError(f"cloudwatch_metrics requires scope.queries as a list of at most {MAX_METRIC_QUERIES} metric queries")
            if not all(isinstance(q, dict) and q.get("namespace") and q.get("metric_name") for q in queries):
                raise ValueError("each cloudwatch_metrics scope.queries entry requires namespace and metric_name")
        if self.query_type == "pagerduty_configuration":
            if self.scope.get("resource_type") not in {"schedule", "escalation_policy", "service", "user", "incident"}:
                raise ValueError("pagerduty_configuration scope.resource_type must be schedule, escalation_policy, service, user, or incident")
            resource_id = self.scope.get("resource_id")
            if not isinstance(resource_id, str) or not resource_id or any(c in resource_id for c in "/?#"):
                raise ValueError("pagerduty_configuration scope.resource_id must be an exact PagerDuty resource id")
            if self.scope["resource_type"] == "schedule":
                if self.time_range is None or self.time_range.end - self.time_range.start > timedelta(days=31):
                    raise ValueError("pagerduty_configuration schedule requires an aware time_range of at most 31 days")
        return self


class ServiceInspectArgs(StrictModel):
    service_id: str
    binding_id: str | None = None
    lookback_minutes: int = Field(default=60, ge=1, le=1440)
    log_lines: int = Field(default=200, ge=1, le=5000)
    include_previous_logs: bool = True
    include_dependencies: bool = True
    reason: str | None = None


class InvestigationRunArgs(StrictModel):
    recipe: Literal["generic_workload", "health_checks", "identity_and_deployment_audit"]
    service_id: str | None = None
    binding_id: str | None = None
    sources: list[str] = Field(default_factory=list, description="Provider ids to collect audit evidence from")
    time_range: TimeRange | None = None
    lookback_minutes: int = Field(default=1440, ge=1, le=43200)
    limits: Limits = Field(default_factory=Limits)
    filters: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None


def _window(tr: TimeRange | None, lookback_minutes: int) -> TimeRange:
    if tr:
        return tr
    end = utcnow()
    return TimeRange(start=end - timedelta(minutes=lookback_minutes), end=end)


def expand_saved_query(catalog: Catalog, service_id: str, query_id: str, *, lookback_minutes: int | None = None, reason: str | None = None) -> EvidenceQueryArgs:
    """The one path from a catalog saved query to an evidence_query. The template comes from approved
    configuration only; the caller chooses nothing but the window and the reason."""
    doc = catalog.service(service_id)
    if doc is None:
        raise OpsError(ErrorCode.NOT_FOUND, f"service {service_id!r} not in catalog")
    q = next((x for x in doc.spec.knowledge.queries if x.id == query_id), None)
    if q is None:
        raise OpsError(ErrorCode.NOT_FOUND, f"service {service_id!r} has no saved query {query_id!r}")
    minutes = lookback_minutes or q.lookback_minutes or 60
    end = utcnow()
    try:
        return EvidenceQueryArgs.model_validate({
            "source_id": q.source_id, "query_type": q.query_type, "scope": q.scope, "filters": q.filters, "limits": q.limits,
            "time_range": {"start": end - timedelta(minutes=minutes), "end": end}, "reason": reason or q.description,
            "saved_query": f"{service_id}/{query_id}@{catalog.revision}",
        })
    except ValueError as e:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"saved query {service_id}/{query_id} does not fit the evidence_query schema: {str(e)[:300]}") from None


def validate_saved_query_template(template: dict[str, Any]) -> None:
    """Raise ValueError if a saved-query template could not expand to a valid evidence_query."""
    end = utcnow()
    EvidenceQueryArgs.model_validate({k: template.get(k, d) for k, d in (("source_id", ""), ("query_type", ""), ("scope", {}), ("filters", {}), ("limits", {}))} | {"time_range": {"start": end - timedelta(minutes=1), "end": end}})


def describe_query(args: EvidenceQueryArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    p = config.provider(args.source_id)
    tr = args.time_range
    return {
        "summary": f"{args.query_type} from {args.source_id}" + (f" ({p.kind})" if p else " (unknown provider)"),
        "source": {"id": args.source_id, "kind": p.kind if p else None, "credential": p.credential if p else None, "account_alias": p.account_alias if p else None, "regions_configured": p.regions if p else None},
        "scope": args.scope, "time_range": {"start": iso(tr.start), "end": iso(tr.end)} if tr else None, "filters": args.filters,
        "limits": args.limits.model_dump(), "effect": EFFECTS.get(args.query_type, Effect.READ).value,
        "provider_charges": {"cloudwatch_logs": "Logs Insights query charges per GB scanned; a query job is created", "cloudtrail_events": "LookupEvents is free for 90-day event history; limited to one attribute filter", "cloudwatch_metrics": "GetMetricData charges per metric requested"}.get(args.query_type, "metadata/read calls"),
        "known_coverage_limits": _coverage_limits(args.query_type), "reason": args.reason,
        "saved_query": args.saved_query,
    }


def _coverage_limits(qtype: str) -> list[str]:
    return {
        "cloudtrail_events": ["account/region specific", "management events only, last 90 days", "one server-side lookup attribute; other filters apply locally over the capped result"],
        "kubernetes_events": ["short-lived (~1h), not an audit log"],
        "container_logs": ["bounded tail of current/previous container only"],
        "github_audit": ["requires org/enterprise audit access; git events retained ~7 days"],
        "onepassword_events": ["Events API needs a separate token with event capabilities; no vault/item names"],
        "guardduty_findings": ["existing findings only; nothing is enabled"],
        "kubernetes_audit": ["requires control-plane audit logging to be enabled and delivered (e.g. EKS -> CloudWatch)"],
        "github_file": ["one explicit path per query; only configs/*.yaml|yml, backend.tf, .github/workflows/*.yml|yaml and catalog/services/*.yaml; no directory listing or recursive reads"],
        "github_commit": ["one commit by full SHA or an unambiguous prefix"],
        "github_runs_for_sha": ["requires the full head commit SHA"],
        "registry_manifest": ["never pulls image layers; config-blob labels only"],
        "s3_object_index": ["keys and metadata only, never object contents", "only buckets in the provider's s3_index_buckets allowlist"],
    }.get(qtype, [])


async def run_query(ctx: OperationContext, args: EvidenceQueryArgs) -> OperationOutcome:
    adapter = ctx.providers.get(args.source_id)
    if adapter is None:
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"source {args.source_id!r} is not configured")
    doc = ctx.catalog
    _ = doc
    query = args.model_dump(mode="json")
    async with ctx.providers.semaphore(args.source_id):
        res: EvidenceResult = await adapter.query(ctx, query, ctx.budget)
    inserted = dups = 0
    if res.events:
        res.events = [ctx.scrub(e) for e in res.events]
        inserted, dups = await ctx.db.upsert_audit_events(ctx.request_id, res.events)
        if res.cursor is not None:
            await ctx.db.save_cursor(args.source_id, str(args.scope), res.cursor, res.events[-1]["occurred_at"] if res.events else None)
    status = ExecutionStatus.SUCCEEDED if not res.coverage.unavailable_scopes else (ExecutionStatus.PARTIAL if res.coverage.completed_scopes else ExecutionStatus.FAILED)
    return OperationOutcome(status, {"query": res.query_description or {k: v for k, v in query.items() if k != "reason"}, "items": res.items, "event_count": len(res.events), "events_new": inserted, "events_duplicate": dups, "notes": res.notes}, coverage=res.coverage)


def describe_inspect(args: ServiceInspectArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    doc = catalog.service(args.service_id)
    bindings = [b for b in (doc.spec.bindings if doc else []) if not args.binding_id or b.id == args.binding_id]
    return {"summary": f"Inspect {args.service_id} ({len(bindings)} binding(s))", "service": {"id": args.service_id, "name": doc.spec.name if doc else None}, "bindings": [{"id": b.id, "provider_id": b.provider_id, "namespace": b.namespace, "workload": f"{b.workload_kind}/{b.workload_name}" if b.workload_name else f"{sum(k.startswith('k8s:') for k in b.resource_keys)} Kubernetes resource key(s)", "source_state": b.source_state} for b in bindings], "reads": ["get workload", "list pods/replicasets", "namespace events", f"container logs (last {args.log_lines} lines, previous={args.include_previous_logs})", "dependency health from released observations"], "time_window_minutes": args.lookback_minutes, "effect": "read", "reason": args.reason}


WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet")


async def _workload_targets(ctx: OperationContext, b: Any) -> list[dict[str, Any]]:
    """The workloads one Kubernetes binding names: its explicit namespace/kind/name, or each workload resource
    key (k8s:<cluster>:<namespace>:<Kind>:<uid>) resolved to a name through an observation of the binding's
    provider that was released to this principal. Keys that were never released resolve to nothing."""
    if b.namespace and b.workload_kind and b.workload_name:
        return [{"namespace": b.namespace, "workload_kind": b.workload_kind, "workload_name": b.workload_name, "uid": b.workload_uid}]
    keys = [k for k in b.resource_keys if k.startswith("k8s:") and len(k.split(":")) == 5 and k.split(":")[3] in WORKLOAD_KINDS]
    if not keys:
        return []
    released = {o["resource_key"]: o for o in await ctx.db.observations(provider_id=b.provider_id, audience=ctx.principal.id, include_missing=False, limit=100_000)}
    out = []
    for k in keys:
        _, _cluster, ns, kind, uid = k.split(":")
        o = released.get(k)
        name = (o or {}).get("identity", {}).get("name")
        if name:
            out.append({"namespace": ns, "workload_kind": kind, "workload_name": name, "uid": uid, "resource_key": k})
    return out


async def run_inspect(ctx: OperationContext, args: ServiceInspectArgs) -> OperationOutcome:
    doc = ctx.catalog.service(args.service_id)
    if doc is None:
        raise OpsError(ErrorCode.NOT_FOUND, f"service {args.service_id!r} is not in the catalog")
    s = doc.spec
    bindings = [b for b in s.bindings if not args.binding_id or b.id == args.binding_id]
    if args.binding_id and not bindings:
        raise OpsError(ErrorCode.NOT_FOUND, f"binding {args.binding_id!r} not found")
    observations: list[str] = []
    coverages: list[Coverage] = []
    runtime: list[dict[str, Any]] = []
    for b in bindings:
        adapter = ctx.providers.get(b.provider_id)
        targets = await _workload_targets(ctx, b) if adapter is not None and getattr(adapter, "kind", None) == "kubernetes" else []
        if not targets:
            cov = Coverage(requested_sources=[b.provider_id])
            cov.unavailable_scopes.append(UnavailableScope(source=b.provider_id, reason="binding_not_inspectable", detail="documentary binding without a kubernetes provider/workload identity"))
            runtime.append({"binding_id": b.id, "inspectable": False, "source_state": b.source_state, "documentary": {"region": b.region, "cluster_name": b.cluster_name, "reported_pod_names": b.reported_pod_names, "sources": b.sources}})
            observations.append(f"binding {b.id} is {b.source_state}; no live runtime inspection possible (provider {b.provider_id})")
            coverages.append(cov)
            continue
        for t in targets:
            cov = Coverage(requested_sources=[b.provider_id])
            kind, ns, name = t["workload_kind"], t["namespace"], t["workload_name"]
            try:
                async with ctx.providers.semaphore(b.provider_id):
                    info = await adapter.inspect_workload(ctx, kind, ns, name)  # type: ignore[union-attr]
                    events = await adapter.query(ctx, {"query_type": "kubernetes_events", "scope": {"namespace": ns}, "filters": {"since_seconds": args.lookback_minutes * 60, "involved_object": name}, "limits": {"max_events": 100}}, ctx.budget)  # type: ignore[union-attr]
                    logs = await adapter.query(ctx, {"query_type": "container_logs", "scope": {"namespace": ns, "workload_kind": kind, "workload_name": name, "container": b.container_name}, "filters": {"previous": False}, "limits": {"max_lines": args.log_lines, "max_pods": 3}}, ctx.budget)  # type: ignore[union-attr]
                    prev = await adapter.query(ctx, {"query_type": "container_logs", "scope": {"namespace": ns, "workload_kind": kind, "workload_name": name, "container": b.container_name}, "filters": {"previous": True}, "limits": {"max_lines": args.log_lines, "max_pods": 3}}, ctx.budget) if args.include_previous_logs else None  # type: ignore[union-attr]
            except OpsError as e:
                cov.unavailable_scopes.append(UnavailableScope(source=b.provider_id, reason=e.code.value, detail=e.message))
                coverages.append(cov)
                runtime.append({"binding_id": b.id, "target": t, "inspectable": False, "error": e.public()})
                continue
            cov.completed_scopes.append(f"{b.provider_id}/{ns}")
            coverages.append(cov)
            rs = info.get("rollout") or {}
            if info.get("found"):
                observations.append(f"{kind}/{name} uid={info['uid']} desired images {[(d['container'], d['image']) for d in info['desired_images']]}; rollout ready {rs.get('ready')}/{rs.get('desired')} converged={rs.get('converged')}; total restarts {info.get('total_restarts')}")
                if t.get("uid") and info.get("uid") != t["uid"]:
                    observations.append(f"{kind}/{name} was recreated: the binding names uid {t['uid']}, the cluster now has uid {info.get('uid')}")
                for r in info.get("running", []):
                    if r.get("state") != "running" or not r.get("ready"):
                        observations.append(f"pod {r['pod']} container {r['container']} state={r.get('state')} ready={r.get('ready')} restarts={r.get('restart_count')} detail={r.get('state_detail')}")
            else:
                observations.append(f"{kind}/{name} not found in {ns}")
            warn = [e for e in events.items if e.get("type") == "Warning"]
            if warn:
                observations.append(f"{len(warn)} warning events for {name}: " + "; ".join(f"{e['reason']} ({e['object']})" for e in warn[:5]))
            # recent deployment/config changes from this server's own receipts; only receipts whose owning
            # request was released to this principal are disclosed (cross-principal receipts are omitted)
            receipts = [r for r in await ctx.db.receipts_released_to(ctx.principal.id, 200) if r["body"].get("service_id") == s.id]
            runtime.append({"binding_id": b.id, "target": t, "inspectable": True, "workload": info, "events": events.items[:50], "logs": logs.items, "previous_logs": prev.items if prev else None, "recent_operations": [{"request_id": r["request_id"], "action": r["body"].get("action"), "outcome": r["body"].get("outcome"), "finished_at": r["body"].get("finished_at"), "after_artifact": r["body"].get("after_artifact")} for r in receipts[:10]], "expected_mechanism": [sr.deployment_mechanism for sr in s.source_repositories], "observed_ownership": info.get("ownership")})
    # dependencies from catalog + released observations
    deps = []
    if args.include_dependencies:
        for d in s.depends_on:
            dd = ctx.catalog.service(d)
            obs = await ctx.db.observations(service_id=d, audience=ctx.principal.id, include_missing=False)
            health = [o["attributes"].get("rollout") for o in obs if o["attributes"].get("rollout")]
            deps.append({"service_id": d, "known": dd is not None, "name": dd.spec.name if dd else None, "observed_rollouts": health, "note": "external dependency" if d.startswith("external:") else None})
    hyps, next_q, actions = _generic_workload_reasoning(s, runtime, args)
    result = {
        "service": {"id": s.id, "name": s.name, "purpose": s.purpose, "owner": s.owner, "knowledge_holders": [k.model_dump() for k in s.knowledge_holders], "runbooks": [o.model_dump() for o in s.observability], "contradictions": [c.model_dump() for c in s.contradictions], "unknowns": s.unknowns},
        "observations": observations, "dependencies": deps, "dependents": ctx.catalog.dependents_of(s.id),
        "hypotheses": [h.model_dump() for h in hyps], "next_queries": [q.model_dump() for q in next_q], "possible_actions": [a.model_dump() for a in actions],
        "items": runtime,  # per-workload runtime detail; the only copy, so request_result paging bounds it
    }
    cov = merge_coverage(coverages)
    cov.time_range_requested = {"start": iso(utcnow() - timedelta(minutes=args.lookback_minutes)), "end": iso(utcnow())}
    status = ExecutionStatus.SUCCEEDED if any(r.get("inspectable") for r in runtime) else ExecutionStatus.PARTIAL
    return OperationOutcome(status, result, coverage=cov)


def _terminated_since(container: dict[str, Any], since: datetime) -> bool:
    finished = ((container.get("last_state") or {}).get("terminated") or {}).get("finished_at")
    if not finished:
        return False
    try:
        at = datetime.fromisoformat(str(finished).replace("Z", "+00:00"))
    except ValueError:
        return True  # unparseable: do not hide a possible crash loop
    return (at if at.tzinfo else at.replace(tzinfo=since.tzinfo)) >= since


def _generic_workload_reasoning(s: Any, runtime: list[dict[str, Any]], args: ServiceInspectArgs) -> tuple[list[Hypothesis], list[SuggestedQuery], list[PossibleAction]]:
    hyps: list[Hypothesis] = []
    queries: list[SuggestedQuery] = []
    actions: list[PossibleAction] = []
    converged: list[str] = []
    window_start = utcnow() - timedelta(minutes=args.lookback_minutes)
    for r in runtime:
        if not r.get("inspectable"):
            queries.append(SuggestedQuery(description=f"Run discovery to bind {s.id}/{r['binding_id']} to a live workload", tool="discovery_scan", arguments={"providers": [], "scope": {}}))
            continue
        wl = r["workload"]
        label = f"{r['target']['workload_kind']}/{r['target']['workload_name']}"
        rs = wl.get("rollout") or {}
        running = wl.get("running", [])
        # Lifetime restart counts include restarts from months ago; only a back-off or a termination inside
        # the inspected window counts as a crash loop.
        crash = [x for x in running if (x.get("state") == "waiting" and str((x.get("state_detail") or {}).get("reason", "")).startswith("CrashLoop")) or ((x.get("restart_count") or 0) > 3 and _terminated_since(x, window_start))]
        not_ready = [x for x in running if not x.get("ready")]
        warn = [e for e in r.get("events", []) if e.get("type") == "Warning"]
        prev_lines = [ln for p in (r.get("previous_logs") or []) for ln in p.get("lines", [])]
        cur_lines = [ln for p in (r.get("logs") or []) for ln in p.get("lines", [])]
        err_lines = [ln for ln in prev_lines + cur_lines if any(k in ln.lower() for k in ("error", "panic", "fatal", "exception", "denied", "unauthorized", "no space", "oom", "migration"))]
        if crash:
            kinds = []
            if any("unauthorized" in ln.lower() or "denied" in ln.lower() or "invalid credential" in ln.lower() for ln in err_lines):
                kinds.append("invalid or expired credentials")
            if any("no space" in ln.lower() or "disk" in ln.lower() for ln in err_lines):
                kinds.append("storage exhaustion")
            if any("migration" in ln.lower() for ln in err_lines):
                kinds.append("failed schema migration")
            if any("connection refused" in ln.lower() or "timeout" in ln.lower() or "unreachable" in ln.lower() for ln in err_lines):
                kinds.append("missing/unreachable dependency")
            if any("oom" in str(e.get("reason", "")).lower() or "oomkill" in str(x.get("last_state") or {}).lower() for e in warn for x in running):
                kinds.append("memory limit (OOMKilled)")
            hyps.append(Hypothesis(statement=f"{s.id} {label} is crash-looping; likely cause: {', '.join(kinds) if kinds else 'not determinable from logs/events collected'}", support="moderate" if kinds else "weak", supporting_observations=[f"{len(crash)} container(s) crash-looping/restarting"] + err_lines[:5], contradicting_observations=[], missing_evidence=["exit code and last termination message", "resource usage metrics", "dependency health"]))
            actions.append(PossibleAction(action="restart", service_id=s.id, binding_id=r["binding_id"], rationale="a restart only helps for transient state; it is not a root-cause fix", inappropriate_when=["credentials are invalid (restart will not help)", "storage is exhausted", "a schema migration failed (may worsen)", "a dependency is down", "intrusion is suspected (evidence would be destroyed; decide containment first)"], executable="restart" in s.operations))
        elif not_ready:
            hyps.append(Hypothesis(statement=f"{s.id} {label}: {len(not_ready)} container(s) not ready; readiness probe or startup problem", support="weak", supporting_observations=[f"{x['pod']}/{x['container']} ready={x.get('ready')} state={x.get('state')}" for x in not_ready[:3]], missing_evidence=["probe configuration", "recent events for the pods"]))
        elif rs.get("converged"):
            converged.append(f"{label} ready {rs.get('ready')}/{rs.get('desired')}, {wl.get('total_restarts')} lifetime restarts")
        if wl.get("observed_ownership", {}).get("mechanism") not in (None, "native", "controller") and r.get("expected_mechanism") and all((wl.get("observed_ownership", {}).get("mechanism") or "") != str(m).lower() for m in r["expected_mechanism"] if m):
            hyps.append(Hypothesis(statement=f"{label}: observed ownership differs from the recorded deployment mechanism", support="moderate", supporting_observations=[f"observed {wl.get('observed_ownership')}, recorded {r['expected_mechanism']}"], missing_evidence=["catalog correction or deployment history"]))
        bind = next((b for b in s.bindings if b.id == r["binding_id"]), None)
        if bind:
            t = r["target"]
            queries.append(SuggestedQuery(description=f"Fetch more previous-container log lines for {t['workload_name']} (grep errors)", tool="evidence_query", arguments={"source_id": bind.provider_id, "query_type": "container_logs", "scope": {"namespace": t["namespace"], "workload_kind": t["workload_kind"], "workload_name": t["workload_name"]}, "filters": {"previous": True, "grep": "error"}, "limits": {"max_events": 2000}}))
            queries.append(SuggestedQuery(description=f"Namespace {t['namespace']} events for the last 6 hours", tool="evidence_query", arguments={"source_id": bind.provider_id, "query_type": "kubernetes_events", "scope": {"namespace": t["namespace"]}, "filters": {"since_seconds": 21600}}))
            for src in s.audit_sources:
                queries.append(SuggestedQuery(description=f"Check for identity/deployment changes in {src} before the failure", tool="investigation_run", arguments={"recipe": "identity_and_deployment_audit", "service_id": s.id, "sources": [src], "lookback_minutes": 1440}))
            for o in s.observability:
                if o.kind in ("metrics", "logs") and o.provider_id:
                    queries.append(SuggestedQuery(description=f"{o.kind} via {o.provider_id}: {o.note or o.query or o.url}", tool="evidence_query", arguments={"source_id": o.provider_id, "query_type": "loki_logs" if o.kind == "logs" else "prometheus_metrics", "scope": {}, "filters": {"query": o.query}}))
    if converged:
        inspected = sum(1 for r in runtime if r.get("inspectable"))
        hyps.append(Hypothesis(statement=f"{s.id}: {len(converged)} of {inspected} inspected workload(s) are converged and ready; if users report problems, look at dependencies, ingress/DNS, or application-level health", support="moderate", supporting_observations=converged, missing_evidence=["application metrics", "upstream/ingress errors"]))
    for q in s.knowledge.queries:
        queries.append(SuggestedQuery(description=f"saved query {q.id}: {q.description}", tool="saved_query_run", arguments={"service_id": s.id, "query_id": q.id}))
    return hyps, queries, actions


def describe_investigation(args: InvestigationRunArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    tr = _window(args.time_range, args.lookback_minutes)
    return {"summary": f"Investigation recipe {args.recipe}" + (f" for {args.service_id}" if args.service_id else ""), "sources": [{"id": s, "kind": (pc.kind if (pc := config.provider(s)) else "unknown")} for s in args.sources], "time_range": {"start": iso(tr.start), "end": iso(tr.end)}, "limits": args.limits.model_dump(), "filters": args.filters, "checks": ["R1 departed identity activity", "R2 privileged changes/root", "R3 logging changes", "R4 unexpected image/deployment", "R5 failed-auth bursts/credential pattern", "R6 k8s sensitive admin", "R7 provider findings", "R8 cross-source correlation"], "effect": "read", "reason": args.reason}


async def run_investigation(ctx: OperationContext, args: InvestigationRunArgs) -> OperationOutcome:
    tr = _window(args.time_range, args.lookback_minutes)
    coverages: list[Coverage] = []
    all_events: list[dict[str, Any]] = []
    security_findings: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    sources = list(args.sources)
    if args.service_id and not sources:
        doc = ctx.catalog.service(args.service_id)
        sources = list(doc.spec.audit_sources) if doc else []
    query_types_by_kind = {"demo": ["cloudtrail_events", "kubernetes_audit", "github_audit", "guardduty_findings"], "aws": ["cloudtrail_events", "guardduty_findings", "kubernetes_audit"], "github": ["github_audit"], "onepassword_events": ["onepassword_events"], "local_import": ["local_import"], "pagerduty": ["pagerduty_incidents"]}

    async def collect(src: str) -> None:
        adapter = ctx.providers.get(src)
        if adapter is None:
            coverages.append(Coverage(requested_sources=[src], unavailable_scopes=[UnavailableScope(source=src, reason="provider_not_configured")]))
            return
        base_filters = {k: v for k, v in args.filters.items() if k != "scope"}
        limits = args.limits.model_dump()
        if "max_events" not in args.limits.model_fields_set:
            limits["max_events"] = AUDIT_DEFAULT_MAX_EVENTS_PER_REGION
        if "max_pages" not in args.limits.model_fields_set:
            # CloudTrail returns at most 50 events per page; never let the page cap undercut max_events
            limits["max_pages"] = max(limits["max_pages"], -(-limits["max_events"] // 50))
        queries: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for qt in query_types_by_kind.get(adapter.kind, []):
            scope, filters = dict(args.filters.get("scope", {})), dict(base_filters)
            # No default CloudTrail narrowing: departed-identity activity and STS credential calls
            # (AssumeRole, GetSessionToken, ...) are recorded as read-only events, so a ReadOnly=false
            # default would silently blind those rules. Callers may opt in with filters.read_only.
            if qt == "kubernetes_audit" and adapter.kind == "aws" and not scope.get("cluster_name"):
                clusters = await _audited_eks_clusters(ctx, src, ctx.principal.id)
                if not clusters:
                    coverages.append(Coverage(requested_sources=[src], unavailable_scopes=[UnavailableScope(source=f"{src}/kubernetes_audit", reason="no_audited_cluster_observed", detail="no EKS cluster with audit logging enabled has been observed for this provider; run discovery first")]))
                for name, region in clusters:
                    queries.append((qt, {**scope, "cluster_name": name, "regions": [region]}, filters))
                continue
            queries.append((qt, scope, filters))
        for qt, scope, filters in queries:
            q = {"source_id": src, "query_type": qt, "scope": scope, "time_range": {"start": iso(tr.start), "end": iso(tr.end)}, "filters": filters, "limits": limits}
            try:
                async with ctx.providers.semaphore(src):
                    res = await adapter.query(ctx, q, ctx.budget)
            except OpsError as e:
                label = f"{src}/{qt}" + (f"/{scope['cluster_name']}" if scope.get("cluster_name") else "")
                coverages.append(Coverage(requested_sources=[src], unavailable_scopes=[UnavailableScope(source=label, reason=e.code.value, detail=e.message)]))
                continue
            coverages.append(res.coverage)
            evidence_ids.extend(res.raw_evidence_ids)
            if qt == "guardduty_findings":
                for f in res.items:
                    security_findings.append({**f, "evidence_ref": res.raw_evidence_ids[0] if res.raw_evidence_ids else None})
            if res.events:
                res.events = [ctx.scrub(e) for e in res.events]
                await ctx.db.upsert_audit_events(ctx.request_id, res.events)
                all_events.extend(res.events)

    await asyncio.gather(*(collect(s) for s in sources))
    expected_patterns = args.filters.get("expected_patterns") or {}
    # Identity Store user listings are released observations, not fetched here; a non-null `missing_since`
    # on one (set only for a complete, comparable-scope discovery scan) lets R1 flag CloudTrail activity by
    # an Identity Center user id no longer in the current listing.
    identity_center_observations = [o for o in await ctx.db.observations(audience=ctx.principal.id) if o.get("resource_type") == "aws/identitystore_user"]
    findings = run_rules(all_events, ctx.catalog, security_findings=security_findings, expected_patterns=expected_patterns, identity_center_observations=identity_center_observations)
    if args.service_id:
        findings = [f for f in findings if not f.affected_services or args.service_id in f.affected_services or True]  # keep all: cross-service context matters
    await ctx.db.insert_findings(ctx.request_id, [ctx.scrub(f.model_dump()) for f in findings])
    cov = merge_coverage(coverages)
    cov.time_range_requested = {"start": iso(tr.start), "end": iso(tr.end)}
    timeline = sorted(({"time": e["occurred_at"], "provider": e["provider"], "actor": e.get("actor"), "action": e["action"], "resource": e.get("resource"), "ip": e.get("source_ip"), "outcome": e.get("outcome"), "event_key": e["event_key"]} for e in all_events), key=lambda x: x["time"] or "")
    observations = [f"collected {len(all_events)} events from {len([c for c in coverages if c.completed_scopes])} completed source scopes; {len(cov.unavailable_scopes)} unavailable"]
    window_gaps = [g for g in cov.collection_gaps if "covered " in g or "capped" in g]
    if window_gaps:
        observations.append(f"The requested window {iso(tr.start)} .. {iso(tr.end)} was NOT fully read in {len(window_gaps)} source scopes (newest events first, capped); findings and their absence apply only to the covered part. See coverage.collection_gaps.")
    hypotheses: list[dict[str, Any]] = []
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(findings, key=lambda f: sev_order[f.severity])[:3]
    if any(f.severity in ("critical", "high") for f in findings):
        hypotheses.append(Hypothesis(statement="evidence is consistent with unauthorized activity; treat as suspected intrusion until benign explanations are confirmed", support="moderate" if any(f.rule_id.startswith("R8") for f in findings) else "weak", supporting_observations=[f.title for f in top], contradicting_observations=[], missing_evidence=[s["source"] for s in [u.model_dump() for u in cov.unavailable_scopes]]).model_dump())
    recipe_extra: dict[str, Any] = {}
    if args.recipe == "health_checks" and args.service_id:
        # Run every check the service file declares, read-only; no settle retries (this is a snapshot).
        sdoc = ctx.catalog.service(args.service_id)
        checks = list(sdoc.spec.health_checks) if sdoc else []
        results: list[dict[str, Any]] = []
        if checks:
            import httpx

            from local_ops.executors.health import http_check

            async with httpx.AsyncClient(timeout=ctx.config.limits.http_timeout_seconds) as http:
                for hc in checks:
                    r = await http_check(hc, http)
                    results.append(r.model_dump())
                    observations.append(f"health check {hc.id} ({hc.kind}): {'pass' if r.passed else ('FAIL' if r.passed is False else 'not run')} - {r.detail}")
        else:
            observations.append("no health checks are declared for this service")
        recipe_extra["health_checks"] = results
    if args.recipe == "generic_workload" and args.service_id:
        ins = await run_inspect(ctx, ServiceInspectArgs(service_id=args.service_id, binding_id=args.binding_id, lookback_minutes=min(args.lookback_minutes, 1440)))
        recipe_extra["workload"] = {k: ins.result.get(k) for k in ("observations", "hypotheses", "next_queries", "possible_actions")} | {"runtime": ins.result.get("items")}
        if ins.coverage:
            coverages.append(ins.coverage)
            cov = merge_coverage(coverages)
            cov.time_range_requested = {"start": iso(tr.start), "end": iso(tr.end)}
    result = {
        "recipe": args.recipe, "service_id": args.service_id, "observations": observations + [f for f in [*(recipe_extra.get("workload", {}).get("observations", []))]],
        "findings": [f.model_dump() for f in findings], "finding_count": len(findings), "timeline": timeline[:500], "items": [f.model_dump() for f in findings],
        "hypotheses": hypotheses + list(recipe_extra.get("workload", {}).get("hypotheses", [])), "contradictions": [c.model_dump() for c in _service_contradictions(ctx, args.service_id)],
        "next_queries": [q.model_dump() for q in _investigation_next_queries(findings, sources, cov)] + list(recipe_extra.get("workload", {}).get("next_queries", [])),
        "possible_actions": ([{"action": "preserve_evidence", "rationale": "suspected intrusion: snapshot logs/pods before any restart", "executable": False, "inappropriate_when": []}] if any(f.severity in ("critical", "high") for f in findings) else []) + list(recipe_extra.get("workload", {}).get("possible_actions", [])),
        "negative_result_statement": None if findings else "No suspicious events were identified in the evidence collected over the stated coverage. This is not a claim that no intrusion occurred." + (" The requested window was not fully covered." if window_gaps else ""),
        "window_fully_covered": not window_gaps and not cov.unavailable_scopes,
        **recipe_extra,
    }
    status = ExecutionStatus.SUCCEEDED if not cov.unavailable_scopes else (ExecutionStatus.PARTIAL if cov.completed_scopes else ExecutionStatus.FAILED)
    return OperationOutcome(status, result, coverage=cov)


AUDIT_DEFAULT_MAX_EVENTS_PER_REGION = 5000


async def _audited_eks_clusters(ctx: OperationContext, provider_id: str, audience: str) -> list[tuple[str, str]]:
    """EKS clusters of this provider, released to the requester, whose last observation shows audit logging
    enabled (name, region). Unreleased scan results never steer what an investigation reads."""
    out = []
    for o in await ctx.db.observations(provider_id=provider_id, audience=audience, include_missing=False, limit=100_000):
        if o["resource_type"] == "aws/eks_cluster" and ((o.get("attributes") or {}).get("logging") or {}).get("audit"):
            ident = o.get("identity") or {}
            if ident.get("name") and ident.get("region"):
                out.append((str(ident["name"]), str(ident["region"])))
    return sorted(set(out))


def _service_contradictions(ctx: OperationContext, service_id: str | None) -> list[Any]:
    if not service_id:
        return []
    doc = ctx.catalog.service(service_id)
    return list(doc.spec.contradictions) if doc else []


def _investigation_next_queries(findings: list[Any], sources: list[str], cov: Coverage) -> list[SuggestedQuery]:
    out: list[SuggestedQuery] = []
    for u in cov.unavailable_scopes:
        out.append(SuggestedQuery(description=f"Enable/obtain access to {u.source} ({u.reason}) and re-run", tool="investigation_run", arguments={"recipe": "identity_and_deployment_audit", "sources": [u.source.split("/")[0]]}))
    for f in findings[:5]:
        for q in f.next_queries[:2]:
            out.append(SuggestedQuery(description=q, tool="evidence_query", arguments={"source_id": sources[0] if sources else "", "query_type": "cloudtrail_events", "filters": {"actors": [a for a in f.observed_facts[:1]]}}))
    return out


def register(registry: OperationRegistry) -> None:
    registry.register(OperationSpec(name="service_inspect", data_class=DataClass.CONTENT, effect=Effect.READ, args_model=ServiceInspectArgs, handler=run_inspect, describe=describe_inspect, summary="Resolve a service to its running workload; collect artifact, readiness, restarts, events, bounded logs, recent changes and dependency health."))
    registry.register(OperationSpec(name="evidence_query", data_class=DataClass.CONTENT, effect=Effect.READ, args_model=EvidenceQueryArgs, handler=run_query, describe=describe_query, summary="Typed, bounded evidence query against one configured source (discriminated by query_type)."))
    registry.register(OperationSpec(name="investigation_run", data_class=DataClass.CONTENT, effect=Effect.READ, args_model=InvestigationRunArgs, handler=run_investigation, describe=describe_investigation, summary="Bounded evidence collection plus deterministic explainable checks; returns findings, timeline, coverage, hypotheses and next queries.", budget_seconds=300))


_ = (Annotated, datetime)
