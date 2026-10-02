from __future__ import annotations

import asyncio
from typing import Any

from pydantic import Field

from local_ops.catalog import Catalog
from local_ops.config import ServerConfig
from local_ops.discovery import denominators, observation_rows, observed_gaps, scope_regions
from local_ops.models import (
    Coverage,
    DataClass,
    Effect,
    ExecutionStatus,
    StrictModel,
    UnavailableScope,
)
from local_ops.operations.base import OperationContext, OperationOutcome, OperationRegistry, OperationSpec
from local_ops.providers.aws_billing import canonical_billing_observations
from local_ops.providers.aws_coverage import build_aws_coverage
from local_ops.providers.base import DiscoveryReport, DiscoveryScope


class DiscoveryScanArgs(StrictModel):
    providers: list[str] = Field(default_factory=list, description="Provider ids to scan; empty = all configured providers")
    scope: DiscoveryScope = Field(default_factory=DiscoveryScope)
    reason: str | None = None


def describe_scan(args: DiscoveryScanArgs, catalog: Catalog, config: ServerConfig) -> dict[str, Any]:
    providers = args.providers or [p.id for p in config.providers if p.enabled]
    return {
        "summary": f"Read-only discovery across {len(providers)} provider(s)",
        "providers": [{"id": p, "kind": (pc.kind if (pc := config.provider(p)) else "unknown"), "credential": (pc.credential if pc else None)} for p in providers],
        "scope": args.scope.model_dump(exclude_defaults=True),
        "effects": ["read-only API calls against the listed providers", "writes observations to local state (private until released)"],
        "provider_charges": "metadata/list API calls only; no paid features enabled",
        "reason": args.reason,
    }


async def run_scan(ctx: OperationContext, args: DiscoveryScanArgs) -> OperationOutcome:
    provider_ids = args.providers or [p.id for p in ctx.config.providers if p.enabled]
    await ctx.db.record_scan(ctx.request_id, provider_ids, args.scope.model_dump())
    reports: list[DiscoveryReport] = []

    async def one(pid: str) -> DiscoveryReport:
        adapter = ctx.providers.get(pid)
        if adapter is None:
            return DiscoveryReport(provider_id=pid, unavailable=[{"source": pid, "reason": "provider_not_configured"}])
        async with ctx.providers.semaphore(pid):
            try:
                return await adapter.discover(ctx, args.scope, ctx.budget)
            except Exception as e:  # noqa: BLE001
                ctx.notes.append(f"{pid}: discovery failed ({type(e).__name__})")
                return DiscoveryReport(provider_id=pid, unavailable=[{"source": pid, "reason": "provider_error", "detail": type(e).__name__}])

    tasks = [asyncio.create_task(one(p)) for p in provider_ids]
    try:
        reports = list(await asyncio.gather(*tasks))
    except asyncio.CancelledError:
        # AWS returns its already-normalized pages on interruption. Preserve those pages before
        # committing continuation state; never advance a cursor past observations lost to cancellation.
        settled = await asyncio.gather(*tasks, return_exceptions=True)
        reports = [r for r in settled if isinstance(r, DiscoveryReport)]

    # Cost Explorer views from multiple configured credentials overlap.  Normalize them
    # before both persistence and coverage so a management-account view cannot be summed
    # with a member-account view.
    observations = canonical_billing_observations(o for report in reports for o in report.observations)
    rows = observation_rows(DiscoveryReport(provider_id="scan", observations=observations), ctx.catalog)
    rows = [ctx.scrub(r) for r in rows]
    # The database upserts by this identity. Match its last-row-wins behavior so
    # result pages and denominators describe unique persisted observations.
    rows = list({(row["provider_id"], row["resource_key"]): row for row in rows}.values())
    ids = await ctx.db.upsert_observations(ctx.request_id, rows)
    for report in reports:
        for update in report.checkpoint_updates:
            saved = await ctx.db.save_discovery_checkpoint(update["key"], update["cursor"], update["expected_version"])
            if not saved:
                report.notes.append("Concurrent discovery advanced the checkpoint; this scan did not overwrite it.")
    missing_marked = 0
    for r in reports:
        for scope_key in r.completed_scopes:
            if scope_key.endswith("/billing"):
                # Billing periods are historical measurements, not live resources.
                continue
            seen = {row["resource_key"] for row in rows if row["provider_id"] == r.provider_id and row.get("scope_key") == scope_key}
            missing_marked += await ctx.db.mark_missing(r.provider_id, scope_key, seen)
    selected_configs = [p for p in ctx.config.providers if p.id in provider_ids]
    den = denominators(reports, args.scope.model_dump(), rows, provider_ids, selected_configs)
    unavailable = [u for r in reports for u in r.unavailable]
    completed = [s for r in reports for s in r.completed_scopes]
    partial = [s for r in reports for s in r.partial_scopes]
    await ctx.db.finish_scan(ctx.request_id, den.model_dump(), completed, unavailable)
    gaps = observed_gaps(rows, ctx.catalog) + ctx.catalog.gaps()
    expiries = [e for r in reports for e in r.expiries]
    items = [{"observation_id": oid, **{k: v for k, v in row.items() if k != "attributes"}, "attributes": row["attributes"]} for oid, row in zip(ids, rows, strict=False)]
    regions_requested = sorted({region for p in selected_configs if p.kind == "aws" for region in p.regions if not args.scope.regions or region in args.scope.regions})
    cov = Coverage(requested_sources=provider_ids, completed_scopes=completed, unavailable_scopes=[UnavailableScope(source=str(u.get("source", "?")), reason=str(u.get("reason", "?")), detail=(str(u.get("detail")) if u.get("detail") is not None else None)) for u in unavailable], collection_gaps=partial, pagination_complete=not any(r.truncated for r in reports), truncated=any(r.truncated for r in reports), regions_requested=regions_requested, regions_completed=sorted({region for s in completed for region in scope_regions(s) if region in regions_requested}), clusters_covered=[r.provider_id for r in reports if r.identity and r.identity.get("kube_system_uid")], conclusion_scope="Absence of a resource is only meaningful within the completed comparable scopes listed; partial or unavailable scopes prove nothing.")
    status = ExecutionStatus.SUCCEEDED if not unavailable and not partial else (ExecutionStatus.PARTIAL if completed or rows or partial else ExecutionStatus.FAILED)
    result = {
        "summary": {"providers_requested": provider_ids, "observations": len(rows), "newly_marked_missing": missing_marked, "denominators": den.model_dump(), "unavailable_sources": unavailable, "identities": {r.provider_id: r.identity for r in reports if r.identity}},
        "items": items,
        "gaps": gaps,
        "expiries": expiries,
        "notes": [n for r in reports for n in r.notes],
    }
    if any(p.kind == "aws" for p in selected_configs):
        result["aws_coverage"] = build_aws_coverage(reports, ctx.config, provider_ids, args.scope)
    return OperationOutcome(status, result, coverage=cov)


def register(registry: OperationRegistry) -> None:
    registry.register(OperationSpec(name="discovery_scan", data_class=DataClass.INVENTORY, effect=Effect.READ, args_model=DiscoveryScanArgs, handler=run_scan, describe=describe_scan, summary="Scoped read-only discovery across configured providers; records observations, matches and gaps.", budget_seconds=900))
