"""Audit normalization helpers, coverage merging and the initial explainable rule families.

Rules are deterministic functions over normalized events plus catalog context. They never claim that a
named human acted solely because a shared role was involved, and they never conclude "no intrusion".
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from local_ops.catalog import Catalog, IdentityRecord
from local_ops.models import Coverage, Finding, sha256_hex

RULES_VERSION = "1.0"

PRIVILEGE_EVENTS = {
    "CreateAccessKey", "UpdateAssumeRolePolicy", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateUser", "CreateRole", "CreateLoginProfile",
    "UpdateLoginProfile", "DeactivateMFADevice", "DeleteVirtualMFADevice", "AddUserToGroup", "CreatePolicyVersion", "SetDefaultPolicyVersion", "UpdateRole", "CreateServiceSpecificCredential",
}
LOGGING_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount", "DeleteFlowLogs", "DeleteLogGroup", "PutRetentionPolicy", "DeleteLogStream", "UpdateClusterConfig"}
ROOT_MARKERS = {"Root"}
_IDENTITYCENTER_ACTOR_RE = re.compile(r"^identitycenter:([^:]+):(.+)$")
SENSITIVE_K8S = {("get", "secrets"), ("list", "secrets"), ("create", "pods/exec"), ("create", "clusterrolebindings"), ("create", "rolebindings"), ("patch", "clusterrolebindings"), ("update", "clusterrolebindings"), ("create", "clusterroles")}
GITHUB_SUSPICIOUS = {"repo.remove_branch_protection", "protected_branch.destroy", "org.remove_member", "org.add_member", "repo.add_member", "workflows.created_workflow", "org.disable_two_factor_requirement", "personal_access_token.access_granted", "oauth_application.create", "integration_installation.create", "repo.transfer", "org.update_member", "repo.create_actions_secret", "org.update_actions_secret"}


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _narrows_coverage(e: dict[str, Any]) -> bool:
    """True when a logging/detection update visibly reduces coverage (or is indeterminate)."""
    params = (e.get("fields") or {}).get("request_parameters") or {}
    if not isinstance(params, dict):
        return True
    narrowing_flags = {"isMultiRegionTrail": False, "includeGlobalServiceEvents": False, "enableLogFileValidation": False, "enable": False, "isLogging": False}
    for k, bad in narrowing_flags.items():
        if k in params and params[k] == bad:
            return True
    if "retentionInDays" in params:
        return True  # retention reductions are indeterminate without the previous value; keep as a finding
    if "eventSelectors" in params or "advancedEventSelectors" in params:
        return True
    if "logging" in params:
        enabled = [c for c in (params.get("logging") or {}).get("clusterLogging", []) if c.get("enabled")]
        disabled = [c for c in (params.get("logging") or {}).get("clusterLogging", []) if not c.get("enabled")]
        return bool(disabled) or not enabled
    widening = any(k in params and params[k] is True for k in ("isMultiRegionTrail", "includeGlobalServiceEvents", "enableLogFileValidation"))
    return not widening


def _finding(rule_id: str, severity: str, confidence: str, title: str, facts: list[str], events: list[dict[str, Any]], **kw: Any) -> Finding:
    keys = [e["event_key"] for e in events]
    fid = "fnd_" + sha256_hex(rule_id + "|" + "|".join(sorted(keys)) + "|" + title)[:16]
    evidence = sorted({e["evidence_ref"] for e in events if e.get("evidence_ref")})
    return Finding(finding_id=fid, rule_id=rule_id, rule_version=RULES_VERSION, severity=severity, confidence=confidence, title=title, observed_facts=facts, evidence_ids=evidence, event_keys=keys, **kw)  # type: ignore[arg-type]


def identity_join(actor: str | None, identities: list[IdentityRecord]) -> tuple[IdentityRecord | None, str]:
    """Join an observed actor string to a catalog identity: exact alias match, or uncertain substring."""
    if not actor:
        return None, "none"
    a = actor.lower()
    for rec in identities:
        if a == rec.id.lower() or a in {x.lower() for x in rec.aliases}:
            return rec, "exact"
    for rec in identities:
        for alias in [rec.id, *rec.aliases]:
            if alias and alias.lower() in a and len(alias) >= 4:
                return rec, "uncertain"
    return None, "none"


def affected_services_for(resource: str | None, catalog: Catalog) -> list[str]:
    if not resource:
        return []
    out = []
    r = resource.lower()
    for sid, doc in catalog.services.items():
        tokens = [sid, doc.spec.name.lower(), *[b.cluster_name or "" for b in doc.spec.bindings], *[b.workload_name or "" for b in doc.spec.bindings]]
        if any(t and t.lower() in r for t in tokens):
            out.append(sid)
    return sorted(set(out))


def run_rules(events: list[dict[str, Any]], catalog: Catalog, *, deployment_records: list[dict[str, Any]] | None = None, security_findings: list[dict[str, Any]] | None = None, expected_patterns: dict[str, Any] | None = None, identity_center_observations: list[dict[str, Any]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    identities = catalog.identities
    expected = expected_patterns or {}
    events = sorted(events, key=lambda e: e.get("occurred_at") or "")

    # `identity_center_observations` is `aws/identitystore_user` observations already released to the
    # caller (same provenance rule as everywhere else in this module: observed data is read, never
    # fetched here). `missing_since` on one of them is set only by `Database.mark_missing`, which only
    # ever runs for a complete, comparable-scope discovery scan (the absence rule the rest of this
    # codebase already enforces) -- so treating a non-null `missing_since` as "no longer in the current
    # Identity Store listing" reuses that invariant instead of re-deriving scope completeness here.
    identity_center_removed: dict[tuple[str, str], dict[str, Any]] = {}
    for o in identity_center_observations or []:
        if o.get("resource_type") != "aws/identitystore_user" or not o.get("missing_since"):
            continue
        ident = o.get("identity") or {}
        store_id, uid = ident.get("identity_store_id"), ident.get("user_id")
        if store_id and uid:
            identity_center_removed[(store_id, uid)] = o

    # Rule 1: activity by departed/revoked identities
    #
    # An Identity Center sign-in event's actor is `identitycenter:<identity_store_id>:<user_id>`
    # (providers/demo.normalize_cloudtrail); `identity_join`'s substring/alias match already catches it
    # like any other actor string once the catalog's `IdentityRecord.aliases` for that person includes the
    # raw Identity Center user id, so no change was needed here for that case.
    for e in events:
        rec, join = identity_join(e.get("actor"), identities)
        if rec is None and e.get("session"):
            rec, join = identity_join(e.get("session"), identities)
        if rec and rec.status in ("departed", "revoked"):
            cutoff = _dt(rec.departed_at or rec.revoked_at)
            at = _dt(e.get("occurred_at"))
            if cutoff is None or (at and at >= cutoff):
                findings.append(_finding("R1.departed_identity_activity", "high" if join == "exact" else "medium", "high" if join == "exact" else "low", f"Activity by {rec.status} identity {rec.id}: {e['action']}", [f"{e.get('occurred_at')} {e.get('actor')} performed {e['action']} on {e.get('resource') or 'n/a'} from {e.get('source_ip') or 'unknown ip'} (outcome {e.get('outcome')})", f"identity {rec.id} recorded as {rec.status} since {rec.departed_at or rec.revoked_at or 'unknown date'}", f"identity join: {join}"], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], affected_services=affected_services_for(e.get("resource"), catalog), benign_explanations=["identity record is stale and the person has returned or the credential was legitimately reassigned", "shared or similarly named identity (join uncertain)" if join != "exact" else "credential rotation lag after departure for an automated process"], next_queries=[f"List access keys and last-used for {rec.id}", f"Query sign-in attempts for {rec.id} in the surrounding 24h", "Confirm offboarding ticket/date for this identity"], possible_remediation=["Preserve evidence (do not restart workloads yet)", "Disable the credential and review sessions issued from it"], identity_join=join))  # type: ignore[arg-type]
        m = _IDENTITYCENTER_ACTOR_RE.match(e.get("actor") or "")
        if m:
            removed_obs = identity_center_removed.get((m.group(1), m.group(2)))
            if removed_obs:
                findings.append(_finding("R1.identitycenter_user_removed", "high", "medium", f"Activity by an Identity Center user id absent from the current Identity Store listing: {e['action']}", [f"{e.get('occurred_at')} {e.get('actor')} performed {e['action']} on {e.get('resource') or 'n/a'} from {e.get('source_ip') or 'unknown ip'} (outcome {e.get('outcome')})", f"user id {m.group(2)} in identity store {m.group(1)} has been missing from a complete Identity Store listing since {removed_obs.get('missing_since')}"], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], affected_services=affected_services_for(e.get("resource"), catalog), benign_explanations=["the activity predates the removal and the listing scan simply ran after it", "the scan window raced a legitimate, in-progress offboarding"], next_queries=[f"Confirm whether Identity Center user id {m.group(2)} was deliberately removed and when", f"List all CloudTrail activity by {e.get('actor')} in the surrounding 24h"], possible_remediation=["Preserve evidence; treat subsequent credential use under this user id as suspect until the removal is confirmed intentional"]))

    # Rule 2: privileged identity/credential/policy/trust/authentication changes, root use
    for e in events:
        if e.get("provider") != "aws":
            continue
        is_priv = e["action"] in PRIVILEGE_EVENTS
        is_root = (e.get("actor_type") in ROOT_MARKERS) or (e.get("actor") or "").endswith(":root")
        if is_priv or is_root:
            params_norm = re.sub(r"[\\\s]", "", str((e.get("fields") or {}).get("request_parameters", "")))
            trust_wide = '"AWS":"*"' in params_norm or '"Principal":"*"' in params_norm
            sev = "critical" if trust_wide else ("high" if is_root or e["action"] in ("UpdateAssumeRolePolicy", "CreateAccessKey", "AttachUserPolicy") else "medium")
            findings.append(_finding("R2.privileged_change", sev, "high", f"{'Root' if is_root else 'Privileged'} change: {e['action']}", [f"{e.get('occurred_at')} {e.get('actor')} ({e.get('actor_type')}) {e['action']} on {e.get('resource') or 'n/a'} from {e.get('source_ip')} ua={e.get('user_agent')}", *(["trust policy allows any AWS principal (*) to assume the role"] if trust_wide else [])], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], affected_services=affected_services_for(e.get("resource"), catalog), benign_explanations=["scheduled credential rotation or IaC apply by a known pipeline", "break-glass use documented in an incident"], next_queries=["Correlate with change tickets / IaC runs in the same window", f"Show all events by {e.get('actor')} in the surrounding 2h"], possible_remediation=["Review and revert the policy/trust change", "Rotate the created credential if unexplained"]))

    # Rule 3: audit/detection configuration disabled or deleted; missing expected coverage
    for e in events:
        if e.get("provider") == "aws" and e["action"] in LOGGING_EVENTS:
            if e["action"] in ("UpdateTrail", "PutEventSelectors", "UpdateDetector", "PutRetentionPolicy", "UpdateClusterConfig") and not _narrows_coverage(e):
                continue  # configuration changed but coverage was not reduced: not a logging-change finding
            findings.append(_finding("R3.logging_change", "critical" if e["action"] in ("StopLogging", "DeleteTrail", "DeleteDetector") else "high", "high", f"Audit/detection configuration changed: {e['action']}", [f"{e.get('occurred_at')} {e.get('actor')} {e['action']} on {e.get('resource') or 'n/a'} from {e.get('source_ip')}"], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], benign_explanations=["trail consolidation/migration by an operator", "cost-driven log retention change"], next_queries=["Check current trail/detector status and who can modify it", "Look for gaps in event delivery after this timestamp"], possible_remediation=["Re-enable logging; preserve the configuration change as evidence"]))

    # Rule 4: unexpected deployment/image changes or divergence from approved deployment path
    for e in events:
        if e.get("provider") == "kubernetes" and (e.get("fields") or {}).get("verb") in ("patch", "update") and e.get("resource_type") in ("deployments", "statefulsets", "daemonsets"):
            req_obj = (e.get("fields") or {}).get("request_object") or {}
            images = [c.get("image") for c in (((req_obj.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers", []) if c.get("image")]
            if images:
                allowed = {repo for doc in catalog.services.values() for op in doc.spec.operations.values() for repo in op.allowed_image_repositories}
                unexpected = [i for i in images if not any(i.startswith(a) for a in allowed)]
                findings.append(_finding("R4.unexpected_image_change", "critical" if unexpected else "medium", "high" if unexpected else "medium", f"Workload image changed via direct API: {e.get('resource')}", [f"{e.get('occurred_at')} {e.get('actor')} {e['action']} {e.get('resource')} from {e.get('source_ip')}", f"images in request: {images}", *( [f"image repositories outside any approved allow list: {unexpected}"] if unexpected else ["image repository is within an approved allow list, but the change did not pass through this server's execution path"])], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], affected_services=affected_services_for(e.get("resource"), catalog), benign_explanations=["manual hotfix by an operator outside the recorded mechanism", "GitOps controller reconciliation (check the actor)"], next_queries=["Compare the running image digest with the approved artifact", "List deployment receipts/approvals in this server for the same window"], possible_remediation=["Roll back to the approved artifact through the reviewed update path after preserving the pod/image as evidence"]))
    for drec in deployment_records or []:
        if drec.get("outside_recorded_mechanism"):
            findings.append(Finding(finding_id="fnd_" + sha256_hex("R4.deploy|" + str(drec))[:16], rule_id="R4.deployment_outside_mechanism", rule_version=RULES_VERSION, severity="high", confidence="medium", title=f"Deployment outside recorded mechanism: {drec.get('service_id')}", observed_facts=[str(drec.get("detail"))], evidence_ids=drec.get("evidence_ids", []), affected_services=[drec["service_id"]] if drec.get("service_id") else [], benign_explanations=["catalog mechanism record is outdated"], next_queries=["Inspect the workload's managed-by markers and recent ReplicaSets"], possible_remediation=["Update the catalog or revert the unmanaged change"]))

    # Rule 5: failed-authentication bursts followed by success; sensitive credential use outside pattern
    by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e["action"] in ("ConsoleLogin", "GetSessionToken", "AssumeRoleWithSAML", "signin", "sign_in") or e.get("category") == "signin":
            by_actor[e.get("actor") or "?"].append(e)
    for actor, evs in by_actor.items():
        evs.sort(key=lambda x: x.get("occurred_at") or "")
        for i, e in enumerate(evs):
            if e.get("outcome") == "success":
                window_start = (_dt(e.get("occurred_at")) or datetime.min.replace(tzinfo=None)) - timedelta(minutes=30)
                fails = [f for f in evs[:i] if f.get("outcome") == "failure" and (_dt(f.get("occurred_at")) or datetime.min) >= window_start]
                if len(fails) >= 3:
                    ips = sorted({str(f.get("source_ip")) for f in fails} | {str(e.get("source_ip"))})
                    findings.append(_finding("R5.failed_auth_burst_then_success", "high", "medium", f"{len(fails)} failed authentications then success for {actor}", [f"{len(fails)} failures between {fails[0].get('occurred_at')} and {fails[-1].get('occurred_at')}, then success at {e.get('occurred_at')}", f"source IPs: {ips}"], [*fails, e], benign_explanations=["user mistyped a password/MFA code several times", "password manager retry"], next_queries=["Check MFA state of the account and whether MFA was used on the success", f"List all API activity by {actor} after {e.get('occurred_at')}"], possible_remediation=["Force password reset and session revocation if unexplained"]))
    for e in events:
        pattern = expected.get(e.get("actor") or "", {})
        if e["action"] in ("CreateAccessKey", "AssumeRole", "GetFederationToken") and pattern:
            ip_ok = not pattern.get("source_ips") or e.get("source_ip") in pattern["source_ips"]
            ua_ok = not pattern.get("user_agents") or any(ua in (e.get("user_agent") or "") for ua in pattern["user_agents"])
            if not (ip_ok and ua_ok):
                findings.append(_finding("R5.credential_use_outside_pattern", "medium", "low", f"Sensitive credential use outside configured pattern: {e.get('actor')} {e['action']}", [f"{e.get('occurred_at')} from {e.get('source_ip')} ua={e.get('user_agent')}", f"expected ips={pattern.get('source_ips')} user_agents={pattern.get('user_agents')}"], [e], benign_explanations=["operator working from a new network; a new IP alone is a lead, not proof"], next_queries=["Confirm with the credential owner", "Correlate with VPN/identity-provider sign-in logs"]))

    # Rule 6: suspicious Kubernetes administrative activity
    for e in events:
        if e.get("provider") != "kubernetes":
            continue
        verb, res, sub = (e.get("fields") or {}).get("verb"), e.get("resource_type"), (e.get("fields") or {}).get("subresource")
        key = (verb, f"{res}/{sub}" if sub else res)
        if key in SENSITIVE_K8S or (res == "secrets" and verb in ("get", "list", "watch")) or sub == "exec":
            groups = (e.get("fields") or {}).get("groups") or []
            findings.append(_finding("R6.k8s_sensitive_admin", "high" if sub == "exec" or "clusterrolebindings" in str(res) else "medium", "high", f"Kubernetes sensitive action: {e['action']} by {e.get('actor')}", [f"{e.get('occurred_at')} {e.get('actor')} groups={groups} {e['action']} {e.get('resource')} from {e.get('source_ip')} (code {e.get('outcome')})"], [e], affected_resources=[e.get("resource")] if e.get("resource") else [], affected_services=affected_services_for(e.get("resource"), catalog), benign_explanations=["operator debugging with exec during an incident", "controller/service account reading secrets as designed"], next_queries=["Who holds this service account token? List its bindings", "Review subsequent API activity from the same source IP"], possible_remediation=["Rotate secrets that were read; remove unexpected bindings after preserving evidence"]))

    # Rule 7: provider security findings mapped to resources/services
    for f in security_findings or []:
        user = (((f.get("Resource") or {}).get("AccessKeyDetails") or {}).get("UserName")) or (((f.get("Resource") or {}).get("InstanceDetails") or {}).get("InstanceId"))
        findings.append(Finding(finding_id="fnd_" + sha256_hex("R7|" + str(f.get("Id")))[:16], rule_id="R7.provider_security_finding", rule_version=RULES_VERSION, severity="high" if float(f.get("Severity", 0)) >= 7 else "medium" if float(f.get("Severity", 0)) >= 4 else "low", confidence="medium", title=f"Provider finding: {f.get('Type')}", observed_facts=[f"{f.get('UpdatedAt')} {f.get('Title')} resource={user} region={f.get('Region')}"], evidence_ids=[f["evidence_ref"]] if f.get("evidence_ref") else [], affected_resources=[str(user)] if user else [], affected_services=affected_services_for(str(user), catalog), benign_explanations=["known travel/location change", "scanner noise for public endpoints"], next_queries=["Open the finding in the provider console for full detail", "Correlate the principal with CloudTrail activity around the finding time"], possible_remediation=["Follow the provider's remediation guidance after confirming"], provider_severity=str(f.get("Severity"))))

    # Rule 8: correlation example: identity activity -> workflow/deployment change -> workload event, with shared identifiers
    aws_priv = [e for e in events if e.get("provider") == "aws" and e["action"] in PRIVILEGE_EVENTS | LOGGING_EVENTS]
    gh = [e for e in events if e.get("provider") == "github" and e["action"] in GITHUB_SUSPICIOUS | {"workflows.completed_workflow_run"}]
    k8s = [e for e in events if e.get("provider") == "kubernetes" and (e.get("fields") or {}).get("verb") in ("patch", "update", "create")]
    for a in aws_priv:
        chain = [a]
        shared: list[str] = []
        for g in gh:
            if g.get("actor") and (g.get("actor") == a.get("actor") or g.get("source_ip") == a.get("source_ip")):
                chain.append(g)
                shared.append("actor" if g.get("actor") == a.get("actor") else "source_ip")
        for k in k8s:
            if k.get("source_ip") and k.get("source_ip") == a.get("source_ip"):
                chain.append(k)
                shared.append("source_ip")
        if len(chain) >= 3:
            findings.append(_finding("R8.cross_source_correlation", "critical", "medium", f"Correlated chain across {len({c['provider'] for c in chain})} sources sharing {sorted(set(shared))}", [f"{c.get('occurred_at')} [{c['provider']}] {c.get('actor')} {c['action']} {c.get('resource') or ''} ip={c.get('source_ip')}" for c in sorted(chain, key=lambda x: x.get('occurred_at') or '')] + ["correlation is by shared identifiers (actor/source IP), not time proximity alone"], chain, affected_resources=sorted({c.get("resource") for c in chain if c.get("resource")}), affected_services=sorted({s for c in chain for s in affected_services_for(c.get("resource"), catalog)}), benign_explanations=["one operator legitimately performing a multi-system change from one workstation"], next_queries=["Pull full session history for the shared source IP across all sources", "Compare the deployed image digest with the approved artifact"], possible_remediation=["Treat as a suspected intrusion: preserve evidence, decide containment before restarting anything"]))

    # dedupe by finding_id
    seen: set[str] = set()
    out: list[Finding] = []
    for fnd in findings:
        if fnd.finding_id not in seen:
            seen.add(fnd.finding_id)
            out.append(fnd)
    return out


def merge_coverage(parts: list[Coverage]) -> Coverage:
    cov = Coverage()
    for p in parts:
        cov.requested_sources += [s for s in p.requested_sources if s not in cov.requested_sources]
        cov.completed_scopes += [s for s in p.completed_scopes if s not in cov.completed_scopes]
        cov.unavailable_scopes += p.unavailable_scopes
        cov.event_categories += [c for c in p.event_categories if c not in cov.event_categories]
        cov.collection_gaps += p.collection_gaps
        cov.accounts_expected += [a for a in p.accounts_expected if a not in cov.accounts_expected]
        cov.accounts_reached += [a for a in p.accounts_reached if a not in cov.accounts_reached]
        cov.regions_requested += [r for r in p.regions_requested if r not in cov.regions_requested]
        cov.regions_completed += [r for r in p.regions_completed if r not in cov.regions_completed]
        cov.clusters_covered += [c for c in p.clusters_covered if c not in cov.clusters_covered]
        cov.permission_failures += p.permission_failures
        cov.disabled_logging += p.disabled_logging
        cov.filters_local += [f for f in p.filters_local if f not in cov.filters_local]
        cov.filters_provider_side += [f for f in p.filters_provider_side if f not in cov.filters_provider_side]
        cov.pagination_complete = cov.pagination_complete and p.pagination_complete
        cov.truncated = cov.truncated or p.truncated
        cov.source_retention_known = cov.source_retention_known or p.source_retention_known
        if p.time_range_requested and not cov.time_range_requested:
            cov.time_range_requested = p.time_range_requested
        for k in ("first_event", "last_event"):
            v = p.time_range_observed.get(k)
            if v and (cov.time_range_observed.get(k) is None or (k == "first_event" and v < cov.time_range_observed[k]) or (k == "last_event" and v > cov.time_range_observed[k])):  # type: ignore[operator]
                cov.time_range_observed[k] = v
    cov.conclusion_scope = ("No suspicious events were identified in the evidence collected over the completed scopes listed; no conclusion about unavailable, partial or truncated scopes, and first/last event times do not prove continuous coverage between them.")
    return cov
