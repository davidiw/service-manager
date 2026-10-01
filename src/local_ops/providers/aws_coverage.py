"""AWS discovery coverage aggregation.

This is deliberately a projection of discovery reports and trusted configuration.  It does
not call AWS, infer resources from spend, or turn an incomplete scope into an empty one.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from local_ops.config import ServerConfig
from local_ops.providers.base import DiscoveryReport, DiscoveryScope

# Cost Explorer's SERVICE strings are product labels, rather than API names.  Keep this
# mapping deliberately conservative: a label not named here is reported as unsupported.
_BILLING_FAMILIES = {
    "amazon elastic compute cloud - compute": "ec2",
    "amazon elastic compute cloud - other": "ec2",
    "amazon ec2": "ec2",
    "amazon elastic container service": "ecs",
    "amazon elastic kubernetes service": "eks",
    "amazon relational database service": "rds",
    "amazon simple storage service": "s3",
    "amazon route 53": "route53",
    "amazon elastic container registry": "ecr",
    "aws lambda": "lambda",
    "aws backup": "backup",
    "aws certificate manager": "acm",
    "amazon cloudwatch": "cloudwatch",
    "amazoncloudwatch": "cloudwatch",
    "amazon cloudwatch logs": "logs",
    "aws key management service": "kms",
    "aws secrets manager": "secretsmanager",
    "amazon dynamodb": "dynamodb",
    "amazon elasticache": "elasticache",
    "amazon elastic file system": "efs",
    "amazon simple queue service": "sqs",
    "amazon simple notification service": "sns",
    "amazon api gateway": "apigateway",
    "amazon cloudfront": "cloudfront",
    "aws waf": "wafv2",
    "aws wafv2": "wafv2",
    "aws step functions": "stepfunctions",
    "amazon opensearch service": "opensearch",
    "amazon elasticsearch service": "opensearch",
    "aws cloudformation": "cloudformation",
    "aws identity and access management": "iam",
    "aws organizations": "organizations",
    "amazon eventbridge": "events",
    "amazon elastic load balancing": "elb",
    "ec2 - other": "ec2",
}

# These represent account charges, credits, or transport, not a resource family whose
# inventory can be enumerated.  Do not use a broad substring rule here.
_NON_RESOURCE_BILLING = {
    "tax",
    "aws support (business)",
    "aws support (developer)",
    "aws support (enterprise)",
    "aws support (enterprise on-ramp)",
    "aws premium support",
    "aws credits",
    "credit",
    "aws data transfer",
    "data transfer",
}

_BILLING_REQUIREMENTS: dict[str, set[str]] = {"amazon cloudwatch": {"cloudwatch", "logs"}, "amazoncloudwatch": {"cloudwatch", "logs"}}

_STRUCTURAL_LIMITS = {
    "sts": ["current caller identity only"],
    "regions": ["enabled regions discovered when selected; credentials scan only configured/requested regions"],
    "eks": ["cluster metadata; node groups, Fargate profiles and add-ons are not separate inventory types"],
    "ec2": ["instances, EBS volumes, VPCs, subnets, security groups and NAT gateways; AMIs, snapshots, interfaces, routes and other EC2 sub-products are not enumerated"],
    "elb": ["ALB/NLB/Gateway load balancers, listeners and target groups; Classic ELB and target health are not enumerated"],
    "rds": ["DB instances and clusters; snapshots and proxy endpoints are not enumerated"],
    "ecr": ["private repositories and image metadata; ECR Public is not enumerated"],
    "backup": ["vaults and recovery-point metadata; restore jobs and backup plans are not enumerated"],
    "acm": ["certificate metadata only; private CA resources are not enumerated"],
    "lambda": ["function metadata and direct role/VPC references; versions, aliases and event-source mappings are not enumerated"],
    "ecs": ["clusters, services and service-referenced task definitions; standalone tasks and unused task definitions are not enumerated"],
    "events": ["event buses, rules and direct targets; EventBridge Scheduler and Pipes are not enumerated"],
    "autoscaling": ["EC2 Auto Scaling groups; Application Auto Scaling targets are not enumerated"],
    "s3": ["bucket identities and locations; no objects, access points, bucket policies or directory buckets"],
    "route53": ["hosted zones and record sets; registered domains and Resolver endpoints are not enumerated"],
    "iam": ["users, roles, access-key metadata and account summary; groups, policies, instance profiles and Identity Center are not enumerated"],
    "organizations": ["accounts visible through opt-in ListAccounts; no automatic cross-account role assumption"],
    "billing": ["30-day account-filtered Cost Explorer SERVICE costs; not resource inventory or proof of zero usage"],
    "secretsmanager": ["secret metadata including rotation and replicas; never values or version payloads"],
    "kms": ["listed keys, aliases, rotation status and tags; no policies, grants or cryptographic operations"],
    "logs": ["log groups and tags; no streams, events, subscription filters or metric filters"],
    "cloudwatch": ["alarm metadata and direct metric/action references; no metric datapoints or dashboards"],
    "dynamodb": ["tables and replica metadata; no items, backups or exports"],
    "wafv2": ["Web ACLs in REGIONAL scope and CLOUDFRONT scope via configured us-east-1; rule groups/IP sets and WAF Classic are not inventoried"],
    "opensearch": ["provisioned OpenSearch domains only; OpenSearch Serverless is unsupported"],
    "elasticache": ["provisioned clusters and replication groups; ElastiCache Serverless is unsupported"],
    "efs": ["file systems and mount targets; access points are not enumerated; no filesystem data"],
    "sqs": ["queue identities, selected attributes and tags; no messages or queue policy documents"],
    "sns": ["topics and their subscriptions; no messages or subscription payloads"],
    "apigateway": ["REST/HTTP/WebSocket APIs and integration references; stages and custom domains are not inventoried"],
    "cloudfront": ["distributions and origins; functions, key groups and cache policies are not inventoried"],
    "stepfunctions": ["state machine identities and tags; no definitions, executions or inputs"],
    "cloudformation": ["stack summaries and resource identities; no templates, parameters or outputs"],
}


def _scope_parts(scope_key: str) -> tuple[str, str, str, str] | None:
    """Return provider/account/region/family for an account-qualified AWS scope."""
    parts = scope_key.split("/")
    if len(parts) < 4:
        return None
    return parts[0], parts[1], parts[2], "/".join(parts[3:])


def _unavailable_for(scope_key: str, unavailable: list[dict[str, Any]]) -> dict[str, Any] | None:
    """An adapter can report a family, region, or provider-level unavailable source."""
    matches = [u for u in unavailable if (source := str(u.get("source", ""))) and (scope_key == source or scope_key.startswith(source + "/") or source.startswith(scope_key + "/"))]
    return max(matches, key=lambda u: len(str(u.get("source", ""))), default=None)


def _partial_status(scope_key: str, report: DiscoveryReport) -> tuple[str, bool, bool]:
    """Reports predating checkpoints remain restart-only instead of promising a resume."""
    checkpoints = getattr(report, "checkpoints", []) or []
    for checkpoint in checkpoints:
        if isinstance(checkpoint, dict) and checkpoint.get("scope_key") == scope_key:
            return "partial_resumable", bool(checkpoint.get("resumed")), True
    for checkpoint in getattr(report, "checkpoint_updates", []) or []:
        if isinstance(checkpoint, dict) and checkpoint.get("scope_key") == scope_key:
            cursor = checkpoint.get("cursor")
            return "partial_resumable", bool(checkpoint.get("resumed")), bool(cursor)
    return "partial_restart", False, False


def _family_names(configured: list[Any], scope: DiscoveryScope, all_families: list[str]) -> tuple[list[str], list[str]]:
    configured_families = {f for p in configured for f in (p.families or all_families)}
    requested = set(scope.families) if scope.families else configured_families
    return sorted(configured_families), sorted(requested & set(all_families))


def build_aws_coverage(reports: list[DiscoveryReport], config: ServerConfig, provider_ids: list[str], scope: DiscoveryScope) -> dict[str, Any]:
    """Build a first-class, evidence-preserving AWS coverage summary.

    ``reports`` can include non-AWS reports; those are ignored.  The caller supplies the
    selected provider ids so a configured AWS account omitted from the request is visible as
    ``not_requested`` rather than silently treated as absent.
    """
    # Import here because aws.py imports the shared provider protocol above.
    from local_ops.providers.aws import ALL_FAMILIES, GLOBAL_FAMILIES

    all_families = list(ALL_FAMILIES)
    aws_configs = [p for p in config.providers if p.kind == "aws"]
    selected_configs = [p for p in aws_configs if p.id in provider_ids]
    aws_reports = [r for r in reports if (provider := config.provider(r.provider_id)) is not None and provider.kind == "aws"]
    configured_families, requested_families = _family_names(selected_configs, scope, all_families)
    regions_configured = sorted({region for p in selected_configs for region in p.regions})
    regions_requested = sorted(set(scope.regions) if scope.regions else set(regions_configured))

    # Organization list observations establish a denominator only when their own listing
    # completed.  A partial Organizations listing is explicitly an unknown denominator.
    known_accounts: dict[str, dict[str, Any]] = {}
    org_complete = False
    for report in aws_reports:
        for observation in report.observations:
            if observation.resource_type != "aws/org_account":
                continue
            account_id = str(observation.identity.get("account_id") or "")
            if account_id:
                known_accounts[account_id] = {"account_id": account_id, "name": observation.identity.get("name"), "organization_source": report.provider_id}
        org_complete = org_complete or any((parts := _scope_parts(key)) and parts[3] == "organizations" for key in report.completed_scopes)

    org_sources = [p for p in selected_configs if p.enabled and p.organizations_enumeration and "organizations" in (scope.families or p.families or all_families)]
    org_by_source: list[dict[str, Any]] = []
    for provider in org_sources:
        org_report = next((r for r in aws_reports if r.provider_id == provider.id), None)
        explicit = (org_report.aws_coverage.get("family_scopes", []) if org_report else [])
        completed = any(isinstance(e, dict) and e.get("family") == "organizations" and e.get("status") == "complete" for e in explicit)
        if not explicit and org_report:
            completed = any((parts := _scope_parts(k)) and parts[3] == "organizations" for k in org_report.completed_scopes)
        org_by_source.append({"provider_id": provider.id, "status": "complete" if completed else "incomplete"})
    org_complete = bool(org_by_source) and all(item["status"] == "complete" for item in org_by_source)

    provider_by_account: dict[str, list[Any]] = defaultdict(list)
    for provider in aws_configs:
        if provider.expected_account_id:
            provider_by_account[provider.expected_account_id].append(provider)
    reached_by_account: dict[str, list[str]] = defaultdict(list)
    for report in aws_reports:
        if report.identity and report.identity.get("account"):
            reached_by_account[str(report.identity["account"])].append(report.provider_id)

    account_ids = set(known_accounts) | set(provider_by_account) | set(reached_by_account)
    account_coverage: list[dict[str, Any]] = []
    for account_id in sorted(account_ids):
        providers = provider_by_account.get(account_id, [])
        enabled = [p for p in providers if p.enabled]
        selected = [p for p in enabled if p.id in provider_ids]
        reached = sorted(reached_by_account.get(account_id, []))
        if scope.accounts and account_id not in scope.accounts:
            status = "not_requested"
        elif providers and not enabled:
            status = "excluded"
        elif reached:
            status = "reached"
        elif selected:
            status = "inaccessible"
        elif enabled:
            status = "not_requested"
        else:
            status = "not_configured"
        account_coverage.append({
            **known_accounts.get(account_id, {"account_id": account_id}),
            "status": status,
            "configured_provider_ids": sorted(p.id for p in enabled),
            "requested_provider_ids": sorted(p.id for p in selected),
            "reached_provider_ids": reached,
            "intentionally_excluded_provider_ids": sorted(p.id for p in providers if not p.enabled),
        })

    # Determine observed per-family status.  Explicit unavailable always wins over a
    # completed scope, because a region/family may have both (for example sub-scopes).
    scopes: dict[str, dict[str, Any]] = {}
    authorization_failures: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []
    interruptions: list[dict[str, Any]] = []
    enabled_regions: set[str] = set()
    per_provider: list[dict[str, Any]] = []
    for report in aws_reports:
        all_unavailable = list(report.unavailable)
        explicit_scopes = report.aws_coverage.get("family_scopes") if report.aws_coverage else None
        per_provider.append({
            "provider_id": report.provider_id,
            "identity": report.identity,
            "regions_configured": report.aws_coverage.get("regions_configured", []),
            "regions_requested": report.aws_coverage.get("regions_requested", []),
            "regions_enabled": report.aws_coverage.get("regions_enabled", []),
            "region_denominator_known": report.aws_coverage.get("region_denominator_known", False),
            "regions_not_configured": report.aws_coverage.get("regions_not_configured", []),
            "configured_enabled_not_scanned": report.aws_coverage.get("regions_not_configured", []),
            "regions_unavailable": [{"region": u.get("region"), "reason": u.get("reason")} for u in all_unavailable if u.get("region") or u.get("reason") == "region_not_enabled"],
        })
        if explicit_scopes:
            for raw in explicit_scopes:
                if not isinstance(raw, dict) or not raw.get("scope_key"):
                    continue
                entry = dict(raw)
                key = str(entry["scope_key"])
                unavailable = _unavailable_for(key, all_unavailable)
                # A child call failure prevents a parent family claim from being complete.
                if unavailable and entry.get("status") == "complete":
                    entry["status"] = "unavailable"
                    entry["reason"] = str(unavailable.get("reason", "provider_error"))
                scopes[key] = entry
                if entry.get("checkpoint_available"):
                    checkpoints.append({"scope_key": key, "provider_id": report.provider_id})
                if entry.get("reason") in {"budget_exhausted", "throttled", "cancelled"}:
                    interruptions.append({"source": key, "reason": entry["reason"]})
            enabled_regions.update(str(r) for r in report.aws_coverage.get("regions_enabled", []) if r)
            for unavailable in all_unavailable:
                if str(unavailable.get("reason")) in {"budget_exhausted", "throttled", "cancelled"}:
                    interruptions.append({k: unavailable[k] for k in ("source", "reason", "detail") if k in unavailable})
                if str(unavailable.get("reason")) in {"permission_denied", "auth_required", "account_mismatch"}:
                    authorization_failures.append({k: unavailable[k] for k in ("source", "reason", "operation", "detail") if k in unavailable})
        for key in sorted(set(report.completed_scopes + report.partial_scopes)):
            if key in scopes:
                # The explicit adapter entry includes resume/comparability state and wins.
                continue
            parsed = _scope_parts(key)
            if not parsed:
                continue
            pid, account, region, family = parsed
            unavailable = _unavailable_for(key, all_unavailable)
            if unavailable:
                reason = str(unavailable.get("reason", "provider_error"))
                status = "not_attempted" if unavailable.get("detail") == "not attempted" else "unavailable"
                resumed, checkpoint_available = False, False
            elif key in report.partial_scopes:
                status, resumed, checkpoint_available = _partial_status(key, report)
                reason = None
            else:
                status, resumed, checkpoint_available, reason = "complete", False, False, None
            fallback_entry: dict[str, Any] = {"scope_key": key, "account": account, "region": region, "family": family, "status": status}
            if reason:
                fallback_entry["reason"] = reason
            if resumed:
                fallback_entry["resumed"] = True
            if checkpoint_available:
                fallback_entry["checkpoint_available"] = True
                checkpoints.append({"scope_key": key, "provider_id": pid})
            scopes[key] = fallback_entry
            if region != "global" and status in {"complete", "partial_restart", "partial_resumable"}:
                enabled_regions.add(region)
        if not explicit_scopes:
            for unavailable in all_unavailable:
                if str(unavailable.get("reason")) in {"budget_exhausted", "throttled", "cancelled"}:
                    interruptions.append({k: unavailable[k] for k in ("source", "reason", "detail") if k in unavailable})
                if str(unavailable.get("reason")) in {"permission_denied", "auth_required", "account_mismatch"}:
                    authorization_failures.append({k: unavailable[k] for k in ("source", "reason", "operation", "detail") if k in unavailable})

    reported_provider_ids = {entry["provider_id"] for entry in per_provider}
    for provider in selected_configs:
        if provider.id not in reported_provider_ids:
            per_provider.append({
                "provider_id": provider.id,
                "identity": None,
                "regions_configured": list(provider.regions),
                "regions_requested": list(scope.regions or provider.regions),
                "regions_enabled": [],
                "region_denominator_known": False,
                "regions_not_configured": [],
                "configured_enabled_not_scanned": list(provider.regions) if provider.enabled else [],
            })

    # Fill planned requested account scopes as not attempted.  This makes a disabled provider,
    # omitted provider, or a budget-stopped tail distinguishable from a clean empty inventory.
    for provider in selected_configs:
        if not provider.enabled or not provider.expected_account_id:
            continue
        requested = [f for f in requested_families if f in (provider.families or all_families)]
        regions = [r for r in regions_requested if r in provider.regions]
        for family in requested:
            target_regions = ["global"] if family in GLOBAL_FAMILIES or family == "sts" else regions
            if family == "regions":
                target_regions = regions[:1]
            for region in target_regions:
                key = f"{provider.id}/{provider.expected_account_id}/{region}/{family}"
                owner_report = next((r for r in aws_reports if r.provider_id == provider.id), None)
                unavailable = _unavailable_for(key, list(owner_report.unavailable) if owner_report else [])
                if unavailable:
                    status = "not_attempted" if unavailable.get("detail") == "not attempted" else "unavailable"
                    entry = {"scope_key": key, "account": provider.expected_account_id, "region": region, "family": family, "status": status, "reason": str(unavailable.get("reason", "provider_error"))}
                else:
                    entry = {"scope_key": key, "account": provider.expected_account_id, "region": region, "family": family, "status": "not_attempted", "reason": "not_reported"}
                scopes.setdefault(key, entry)

    # Cost is coverage evidence only. Zero spend remains a reported billing row but cannot
    # prove the corresponding service or resources are absent; threshold avoids noise.
    billing_coverage: list[dict[str, Any]] = []
    partial_scope_keys = {key for report in aws_reports for key in report.partial_scopes}
    for report in aws_reports:
        for observation in report.observations:
            if observation.resource_type != "aws/billing_service_cost":
                continue
            service = str(observation.identity.get("service") or "")
            try:
                amount = float(observation.attributes.get("amount") or 0)
            except (TypeError, ValueError):
                amount = 0.0
            billing_family: str | None
            if abs(amount) < 0.01:
                status, billing_family = "below_nontrivial_threshold", _BILLING_FAMILIES.get(service.lower())
            elif service.lower() in _NON_RESOURCE_BILLING:
                status, billing_family = "intentionally_non_resource", None
            else:
                billing_family = _BILLING_FAMILIES.get(service.lower())
                if billing_family is None:
                    status = "unsupported"
                else:
                    billed_account = str(observation.identity.get("account") or "")
                    required = _BILLING_REQUIREMENTS.get(service.lower(), {billing_family})
                    candidates = [s for s in scopes.values() if s["family"].split("/")[0] in required and s["account"] == billed_account]
                    # A billing observation can be management-account aggregated; if no exact
                    # account scope exists, family support is still reported without claiming complete.
                    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
                    for candidate in candidates:
                        by_family[str(candidate["family"]).split("/")[0]].append(candidate)
                    account_reports = [r for r in aws_reports if r.identity and str(r.identity.get("account")) == billed_account]
                    region_denominator_known = bool(account_reports) and all(bool(r.aws_coverage.get("region_denominator_known")) and not r.aws_coverage.get("regions_not_configured") for r in account_reports)

                    def family_complete(family: str, entries_by_family: dict[str, list[dict[str, Any]]] = by_family, reports_for_account: list[DiscoveryReport] = account_reports) -> bool:
                        entries = entries_by_family.get(family, [])
                        if not entries or any(str(entry.get("status")) != "complete" or entry.get("absence_proven") is False or bool(entry.get("resumed")) or str(entry.get("scope_key")) in partial_scope_keys for entry in entries):
                            return False
                        if family in GLOBAL_FAMILIES:
                            return any(str(entry.get("region")) == "global" for entry in entries)
                        enabled = {str(region) for report in reports_for_account for region in report.aws_coverage.get("regions_enabled", []) if region}
                        enumerated = {str(entry.get("region")) for entry in entries}
                        return bool(enabled) and enabled <= enumerated

                    complete = all(family_complete(family) for family in required) and region_denominator_known
                    status = "complete_within_enumerated_scope" if complete else "supported_but_not_complete"
            billing_coverage.append({"service": service, "account": observation.identity.get("account"), "amount": amount, "enumerator_family": billing_family, "status": status})

    return {
        "supported_families": sorted(all_families),
        "configured_families": configured_families,
        "requested_families": requested_families,
        "regions_configured": regions_configured,
        "regions_requested": regions_requested,
        "regions_enabled": sorted(enabled_regions),
        "family_scopes": sorted(scopes.values(), key=lambda item: item["scope_key"]),
        "per_provider": per_provider,
        "accounts": {
            "organization_accounts_known": sorted(known_accounts),
            "organization_denominator": "complete" if org_complete else "unknown_or_partial",
            "organization_sources": org_by_source,
            "organization_denominator_note": "Even completed Organizations sources establish only the accounts visible to those configured credentials; they do not prove every AWS organization in the estate was scanned.",
            "coverage": account_coverage,
        },
        "billing_service_coverage": billing_coverage,
        "authorization_failures": authorization_failures,
        "checkpoints": checkpoints,
        "interruptions": interruptions,
        "nontrivial_spend_threshold": 0.01,
        "enumeration_scope": {family: _STRUCTURAL_LIMITS.get(family, ["See adapter family scope; no whole-product exhaustive claim is made."]) for family in all_families},
        "unsupported_subproducts": ["WAF Classic", "OpenSearch Serverless", "ElastiCache Serverless", "EC2 AMIs", "EC2 snapshots"],
        "absence_note": "No resources exist can be concluded only for a completed comparable family scope whose absence_proven is not false. A resumed suffix, partial, unavailable, not-attempted, and unsupported coverage do not imply absence.",
    }
