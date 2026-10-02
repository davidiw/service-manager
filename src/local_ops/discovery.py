"""Discovery orchestration: run adapters within scope, persist observations, match them to catalog
bindings (candidate relationships, not verified ownership), compute gaps and denominators."""

from __future__ import annotations

from typing import Any

from local_ops.catalog import Binding, Catalog
from local_ops.config import ProviderConfig
from local_ops.models import ScanDenominators
from local_ops.providers.base import DiscoveryReport, Observation

RANK = {"verified": 0, "observed": 1, "inferred": 2}


def deterministic_binding_match(b: Binding, provider_id: str, resource_key: str, resource_type: str, identity: dict[str, Any], attributes: dict[str, Any]) -> tuple[str, str] | None:
    """(basis, confidence) when an approved binding names this observation exactly, else None (D25).

    This is the one canonical exact matcher, used at scan time (stored match) and at read time (service
    views over released observations). It never compares names for similarity: an exact resource key, an
    exact-tag selector, a workload UID, cluster identity + namespace + kind + name, or an EKS cluster name
    in the binding's region. The binding's provider is one verified account, so provider equality scopes
    every basis to that account.
    """
    if b.provider_id != provider_id:
        return None
    if resource_key in b.resource_keys:
        return "exact resource key", "observed"
    region = identity.get("region")
    if b.selector is not None and resource_type in b.selector.resource_types and (not b.region or b.region == region):
        tags = attributes.get("tags")
        if isinstance(tags, dict) and all(tags.get(k) == v for k, v in b.selector.tags.items()):
            return "tag selector " + ", ".join(f"{k}={v}" for k, v in sorted(b.selector.tags.items())), "observed"
    if resource_type.startswith("k8s/"):
        if b.workload_uid and identity.get("uid") == b.workload_uid:
            return "workload_uid", "verified"
        same_cluster = b.cluster_identity and b.cluster_identity in (identity.get("cluster_identity"), provider_id)
        if same_cluster and b.namespace and b.namespace == identity.get("namespace") and b.workload_kind and b.workload_kind == identity.get("kind") and b.workload_name and b.workload_name == identity.get("name"):
            return "cluster+namespace+kind+name", "observed"
    elif resource_type == "aws/eks_cluster" and b.cluster_name and b.region and identity.get("name") == b.cluster_name and region == b.region:
        return "eks cluster name + region", "observed"
    return None


def match_candidates(obs: Observation, catalog: Catalog) -> list[dict[str, Any]]:
    """All candidate matches, strongest first. The caller records the primary and the alternates."""
    found: list[dict[str, Any]] = []
    for sid in sorted(catalog.services):
        m = _match_one(obs, catalog, sid)
        if m:
            found.append(m)
    found.sort(key=lambda m: RANK.get(m["confidence"], 9))
    return found


def match_observation(obs: Observation, catalog: Catalog) -> dict[str, Any] | None:
    c = match_candidates(obs, catalog)
    return c[0] if c else None


def _match_one(obs: Observation, catalog: Catalog, sid: str) -> dict[str, Any] | None:
    """Best match of one observation against one service.

    Match bases, strongest first:
    - exact: workload UID or cluster-identity+namespace+kind+name equal to an approved binding
    - name: workload name equals binding workload_name but cluster/namespace unknown in binding
    - pod_prefix: observed pod names start with a reported_pod_name prefix
    - cluster_name: binding cluster_name equals observed cluster/EKS name
    """
    ident = obs.identity
    doc = catalog.services[sid]
    for b in doc.spec.bindings:
        exact = deterministic_binding_match(b, obs.provider_id, obs.resource_key, obs.resource_type, ident, obs.attributes)
        if exact:
            return {"service_id": sid, "binding_id": b.id, "basis": exact[0], "confidence": exact[1]}
    if True:
        for b in doc.spec.bindings:
            if obs.resource_type.startswith("k8s/"):
                if b.workload_uid and ident.get("uid") == b.workload_uid:
                    return {"service_id": sid, "binding_id": b.id, "basis": "workload_uid", "confidence": "verified"}
                same_cluster = b.cluster_identity and b.cluster_identity in (ident.get("cluster_identity"), obs.provider_id)
                same_ns = b.namespace and b.namespace == ident.get("namespace")
                same_kind = b.workload_kind and b.workload_kind == ident.get("kind")
                same_name = b.workload_name and b.workload_name == ident.get("name")
                if same_cluster and same_ns and same_kind and same_name:
                    return {"service_id": sid, "binding_id": b.id, "basis": "cluster+namespace+kind+name", "confidence": "observed"}
                if same_name and same_kind and (b.provider_id == obs.provider_id):
                    return {"service_id": sid, "binding_id": b.id, "basis": "provider+kind+name (namespace/cluster not confirmed)", "confidence": "inferred"}
                pods = obs.attributes.get("pod_names") or []
                for rp in b.reported_pod_names:
                    prefix = rp.rsplit("-", 1)[0]
                    if any(p.startswith(prefix) for p in pods):
                        return {"service_id": sid, "binding_id": b.id, "basis": f"pod name prefix {prefix!r}", "confidence": "inferred"}
            else:
                name = ident.get("name") or ident.get("identifier") or ""
                if b.cluster_name and obs.resource_type.endswith("eks_cluster") and name == b.cluster_name and (not b.region or b.region == ident.get("region")):
                    return {"service_id": sid, "binding_id": b.id, "basis": "eks cluster name" + (" + region" if b.region else ""), "confidence": "observed" if b.region else "inferred"}
                if b.cluster_name and name and (b.cluster_name in str(obs.attributes.get("tags", {}).values()) or name.startswith(b.cluster_name)):
                    return {"service_id": sid, "binding_id": b.id, "basis": "cluster name tag/prefix", "confidence": "inferred"}
    return None


def observation_rows(report: DiscoveryReport, catalog: Catalog) -> list[dict[str, Any]]:
    rows = []
    for obs in report.observations:
        cands = match_candidates(obs, catalog)
        m = cands[0] if cands else None
        also = [{"service_id": c["service_id"], "binding_id": c["binding_id"], "basis": c["basis"], "confidence": c["confidence"]} for c in cands[1:]]
        rows.append({
            "provider_id": obs.provider_id, "resource_key": obs.resource_key, "resource_type": obs.resource_type, "identity": obs.identity,
            "attributes": {**obs.attributes, "relationships": obs.relationships, "also_matches": also}, "evidence_id": obs.evidence_id, "scope_key": obs.scope_key,
            "match_service_id": m["service_id"] if m else None, "match_binding_id": m["binding_id"] if m else None,
            "match_basis": (m["basis"] + (f"; also matches {', '.join(a['service_id'] + '/' + a['binding_id'] for a in also)}" if also else "")) if m else None,
            "match_confidence": m["confidence"] if m else None,
        })
    return rows


def scope_regions(scope_key: str) -> list[str]:
    """Region candidates in a scope key. AWS keys are `provider/account/region/family[/...]` (D23)."""
    parts = scope_key.split("/")
    return [parts[2]] if len(parts) >= 4 else []


def denominators(
    reports: list[DiscoveryReport],
    scope: dict[str, Any],
    rows: list[dict[str, Any]],
    providers_requested: list[str],
    provider_configs: list[ProviderConfig] | None = None,
) -> ScanDenominators:
    """Count only the account, region, and cluster denominators relevant to this scan.

    Reports describe what answered, but cannot identify a requested Kubernetes provider
    that failed before it produced an identity, nor the configured AWS regions when the
    caller omitted a regional override.  The selected provider configuration supplies
    those denominators at the orchestration boundary.  The optional argument preserves
    the small standalone callers used by older provider tests.
    """
    completed = {s for r in reports for s in r.completed_scopes}
    unavailable = [u for r in reports for u in r.unavailable]
    if provider_configs is not None:
        requested_ids = set(providers_requested)
        aws_providers = [p for p in provider_configs if p.id in requested_ids and p.kind == "aws"]
        regional_override = set(scope.get("regions") or [])
        regions_requested = {
            region
            for provider in aws_providers
            for region in (regional_override or set(provider.regions))
            if region in provider.regions
        }
        clusters_requested = len({p.id for p in provider_configs if p.id in requested_ids and p.kind == "kubernetes"})
    else:
        regions_requested = set(scope.get("regions") or [])
        if not regions_requested:
            regions_requested = {
                str(region)
                for report in reports
                for region in report.aws_coverage.get("regions_requested", [])
                if region
            }
        clusters_requested = len({r.provider_id for r in reports if r.identity and r.identity.get("kube_system_uid")})
    regions_completed = {region for s in completed for region in scope_regions(s) if region in regions_requested}
    clusters_reached = {r.provider_id for r in reports if r.identity and r.identity.get("kube_system_uid")}
    accounts_expected = {r.identity.get("account") for r in reports if r.identity and r.identity.get("account")} | {u.get("account") for u in unavailable if u.get("account")}
    accounts_reached = {r.identity.get("account") for r in reports if r.identity and r.identity.get("account") and r.completed_scopes}
    workloads = [r for r in rows if r["resource_type"].startswith("k8s/") and r["resource_type"].split("/")[1] in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")]
    mapped = [w for w in workloads if w["match_service_id"]]
    return ScanDenominators(
        accounts_expected=len(accounts_expected), accounts_reached=len(accounts_reached - {None}),
        regions_requested=len(regions_requested), regions_completed=len(regions_completed),
        clusters_requested=clusters_requested, clusters_reached=len(clusters_reached),
        workloads_observed=len(workloads), workloads_mapped=len(mapped), workloads_unresolved=len(workloads) - len(mapped),
        sources_available=len([r for r in reports if r.completed_scopes or r.observations]), sources_missing=len([r for r in reports if not r.completed_scopes and not r.observations]),
    )


def observed_gaps(rows: list[dict[str, Any]], catalog: Catalog) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for r in rows:
        rt = r["resource_type"]
        if rt.startswith("k8s/") and rt.split("/")[1] in ("Deployment", "StatefulSet", "DaemonSet") and not r["match_service_id"]:
            gaps.append({"service_id": None, "kind": "unresolved_workload", "detail": f"{rt} {r['identity'].get('namespace')}/{r['identity'].get('name')} on {r['provider_id']} matches no catalog service", "severity": "high", "basis": "observation", "resource_key": r["resource_key"]})
        if r["match_confidence"] == "inferred":
            gaps.append({"service_id": r["match_service_id"], "kind": "ambiguous_match", "detail": f"{rt} {r['resource_key']} matched {r['match_service_id']}/{r['match_binding_id']} by {r['match_basis']}; confirm before relying on it", "severity": "medium", "basis": "observation", "resource_key": r["resource_key"]})
        also = r["attributes"].get("also_matches") or []
        if r["match_service_id"] and also:
            others = ", ".join(f"{a['service_id']}/{a['binding_id']}" for a in also)
            for target in [r["match_service_id"], *[a["service_id"] for a in also]]:
                gaps.append({"service_id": target, "kind": "ambiguous_match", "detail": f"{rt} {r['identity'].get('namespace')}/{r['identity'].get('name')} is claimed by {r['match_service_id']}/{r['match_binding_id']} and also by {others}; decide which service owns it", "severity": "high", "basis": "observation", "resource_key": r["resource_key"]})
        if rt.endswith("ec2_instance") and not r["match_service_id"] and not r["attributes"].get("tags"):
            gaps.append({"service_id": None, "kind": "unexplained_resource", "detail": f"untagged {rt} {r['identity'].get('instance_id')} in {r['identity'].get('region')}", "severity": "medium", "basis": "observation", "resource_key": r["resource_key"]})
        if rt.endswith("eks_cluster"):
            logging = r["attributes"].get("logging") or {}
            if logging and not logging.get("audit"):
                gaps.append({"service_id": r["match_service_id"], "kind": "unsupported_audit_coverage", "detail": f"EKS cluster {r['identity'].get('name')} has audit logging disabled", "severity": "high", "basis": "observation", "resource_key": r["resource_key"]})
        if rt.startswith("k8s/") and r["attributes"].get("ownership", {}).get("mechanism") in ("argocd", "flux", "helm"):
            sid = r["match_service_id"]
            if sid:
                doc = catalog.service(sid)
                mechs = {s.deployment_mechanism for s in doc.spec.source_repositories} if doc else set()
                if doc and mechs and r["attributes"]["ownership"]["mechanism"] not in {str(m).lower() for m in mechs if m}:
                    gaps.append({"service_id": sid, "kind": "deployment_mechanism_mismatch", "detail": f"observed {r['attributes']['ownership']['mechanism']} ownership but catalog records {sorted(m for m in mechs if m)}", "severity": "high", "basis": "observation", "resource_key": r["resource_key"]})
    # catalog bindings with no observation in a completed scope
    observed_keys = {(r["match_service_id"], r["match_binding_id"]) for r in rows if r["match_service_id"]}
    for sid, doc in catalog.services.items():
        for b in doc.spec.bindings:
            if (sid, b.id) not in observed_keys and b.source_state != "documentary":
                gaps.append({"service_id": sid, "kind": "binding_not_observed", "detail": f"binding {b.id} ({b.source_state}) was not observed in this scan", "severity": "medium", "basis": "observation"})
    return gaps


def service_runtime_view(service_id: str, observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Observed runtime summary for one service from (disclosure-filtered) observations."""
    mine = [o for o in observations if o.get("match_service_id") == service_id or any(a.get("service_id") == service_id for a in (o.get("attributes", {}).get("also_matches") or []))]
    workloads = []
    for o in mine:
        if o["resource_type"].startswith("k8s/") and o["resource_type"].split("/")[1] in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            a = o["attributes"]
            shared = o.get("match_service_id") != service_id
            workloads.append({"binding_id": (next((a["binding_id"] for a in a_list if a.get("service_id") == service_id), None) if (a_list := (o.get("attributes", {}).get("also_matches") or [])) and shared else o["match_binding_id"]), "shared_with": ([o.get("match_service_id")] if shared else [a["service_id"] for a in (o.get("attributes", {}).get("also_matches") or [])]), "provider_id": o["provider_id"], "cluster_identity": o["identity"].get("cluster_identity"), "namespace": o["identity"].get("namespace"), "kind": o["identity"].get("kind"), "name": o["identity"].get("name"), "uid": o["identity"].get("uid"), "desired_images": a.get("desired_images"), "running": a.get("running"), "ownership": a.get("ownership"), "rollout": a.get("rollout"), "match_basis": o.get("match_basis"), "match_confidence": o.get("match_confidence"), "last_seen_at": o.get("last_seen_at"), "missing_since": o.get("missing_since")})
    others = [{"resource_type": o["resource_type"], "resource_key": o["resource_key"], "match_basis": o.get("match_basis"), "confidence": o.get("match_confidence"), "last_seen_at": o.get("last_seen_at")} for o in mine if o["resource_type"].startswith("k8s/") is False or o["resource_type"].split("/")[1] not in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")]
    return {"workloads": workloads, "other_resources": others, "observation_count": len(mine)}
