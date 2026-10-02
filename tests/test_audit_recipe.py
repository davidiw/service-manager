"""identity_and_deployment_audit over AWS sources: changes-only CloudTrail by default, a larger per-region
budget when the caller sets no limits, EKS audit per observed audited cluster, and a loud statement when the
requested window was not fully covered."""

from __future__ import annotations

from typing import Any

from local_ops.models import Coverage
from local_ops.operations.base import OperationContext
from local_ops.operations.diagnosis import (
    AUDIT_DEFAULT_MAX_EVENTS_PER_REGION,
    InvestigationRunArgs,
    run_investigation,
)
from local_ops.providers.base import EvidenceResult
from tests.providers.test_aws import ctx  # noqa: F401


class RecordingAws:
    kind = "aws"

    def __init__(self, provider_id: str, gaps: list[str] | None = None):
        self.provider_id = provider_id
        self.queries: list[dict[str, Any]] = []
        self.gaps = gaps or []

    async def query(self, _ctx: OperationContext, query: dict[str, Any], budget: Any) -> EvidenceResult:
        self.queries.append(query)
        cov = Coverage(requested_sources=[self.provider_id], completed_scopes=[] if self.gaps else [f"{self.provider_id}/us-west-2"], collection_gaps=list(self.gaps))
        return EvidenceResult(coverage=cov)


async def _observe_cluster(c: OperationContext, provider: str, name: str, region: str, audit: bool, released_to: list[str] | None = None) -> None:
    import json

    (oid,) = await c.db.upsert_observations("req_scan", [{"provider_id": provider, "resource_key": f"arn:aws:eks:{region}:1:cluster/{name}", "resource_type": "aws/eks_cluster", "identity": {"account": "1", "region": region, "name": name}, "attributes": {"logging": {"audit": audit}}, "scope_key": f"{provider}/1/{region}/eks"}])
    async with c.db.tx() as t:
        await t.execute("UPDATE observations SET released_to=? WHERE id=?", (json.dumps([c.principal.id] if released_to is None else released_to), oid))


async def test_audit_defaults_to_changes_only_and_per_cluster_eks_audit(ctx: OperationContext) -> None:  # noqa: F811
    ad = RecordingAws("aws-x")
    ctx.providers.register(ad)  # type: ignore[arg-type]
    await _observe_cluster(ctx, "aws-x", "audited", "us-east-1", True)
    await _observe_cluster(ctx, "aws-x", "quiet", "us-west-2", False)
    out = await run_investigation(ctx, InvestigationRunArgs(recipe="identity_and_deployment_audit", sources=["aws-x"], lookback_minutes=10080))
    by_type = {q["query_type"]: q for q in ad.queries}
    # no default ReadOnly narrowing: departed-identity reads and STS credential calls are read-only events
    assert by_type["cloudtrail_events"]["filters"] == {}
    assert by_type["cloudtrail_events"]["limits"]["max_events"] == AUDIT_DEFAULT_MAX_EVENTS_PER_REGION
    assert by_type["cloudtrail_events"]["limits"]["max_pages"] == AUDIT_DEFAULT_MAX_EVENTS_PER_REGION // 50
    ka = [q for q in ad.queries if q["query_type"] == "kubernetes_audit"]
    assert [q["scope"] for q in ka] == [{"cluster_name": "audited", "regions": ["us-east-1"]}]
    assert out.result["window_fully_covered"] is True


async def test_explicit_filters_and_limits_are_respected(ctx: OperationContext) -> None:  # noqa: F811
    ad = RecordingAws("aws-y")
    ctx.providers.register(ad)  # type: ignore[arg-type]
    await run_investigation(ctx, InvestigationRunArgs(recipe="identity_and_deployment_audit", sources=["aws-y"], filters={"actors": ["alice"]}, limits={"max_events": 50}))  # type: ignore[arg-type]
    ct = next(q for q in ad.queries if q["query_type"] == "cloudtrail_events")
    assert ct["filters"] == {"actors": ["alice"]} and ct["limits"]["max_events"] == 50


async def test_schedule_style_max_events_scales_page_cap(ctx: OperationContext) -> None:  # noqa: F811
    ad = RecordingAws("aws-s")
    ctx.providers.register(ad)  # type: ignore[arg-type]
    await run_investigation(ctx, InvestigationRunArgs(recipe="identity_and_deployment_audit", sources=["aws-s"], limits={"max_events": 3000}))  # type: ignore[arg-type]
    ct = next(q for q in ad.queries if q["query_type"] == "cloudtrail_events")
    assert ct["limits"]["max_events"] == 3000 and ct["limits"]["max_pages"] == 60


async def test_unreleased_clusters_never_steer_the_audit(ctx: OperationContext) -> None:  # noqa: F811
    ad = RecordingAws("aws-u")
    ctx.providers.register(ad)  # type: ignore[arg-type]
    await _observe_cluster(ctx, "aws-u", "secret-cluster", "us-east-1", True, released_to=[])
    await run_investigation(ctx, InvestigationRunArgs(recipe="identity_and_deployment_audit", sources=["aws-u"]))
    assert not [q for q in ad.queries if q["query_type"] == "kubernetes_audit"]


async def test_uncovered_window_is_stated_and_no_audited_cluster_is_a_gap(ctx: OperationContext) -> None:  # noqa: F811
    ad = RecordingAws("aws-z", gaps=["aws-z/us-west-2: upstream result set capped at 100 pages / 5000 events; covered 2026-10-01T00:00:00Z .. 2026-10-02T00:00:00Z of requested 2026-09-25T00:00:00Z .. 2026-10-02T00:00:00Z"])
    ctx.providers.register(ad)  # type: ignore[arg-type]
    out = await run_investigation(ctx, InvestigationRunArgs(recipe="identity_and_deployment_audit", sources=["aws-z"]))
    assert out.result["window_fully_covered"] is False
    assert any("NOT fully read" in o for o in out.result["observations"])
    assert out.result["negative_result_statement"].endswith("The requested window was not fully covered.")
    assert any(u.reason == "no_audited_cluster_observed" for u in out.coverage.unavailable_scopes) if out.coverage else False
