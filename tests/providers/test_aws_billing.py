from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.operations.discovery import DiscoveryScanArgs, run_scan
from local_ops.providers.aws_billing import billing_key, canonical_billing_observations
from local_ops.providers.aws_coverage import build_aws_coverage
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    ProviderRegistry,
)
from local_ops.release import Sanitizer
from local_ops.storage import Database

ACCOUNT = "123456789012"
SERVICE = "Amazon Example: Compute / Other"
PERIOD_START = "2026-09-01"
PERIOD_END = "2026-10-01"


def _billing(provider_id: str, amount: float, unit: str = "USD") -> Observation:
    return Observation(
        provider_id=provider_id,
        resource_key=f"raw:{provider_id}",
        resource_type="aws/billing_service_cost",
        identity={"account": ACCOUNT, "service": SERVICE},
        attributes={
            "amount": amount,
            "unit": unit,
            "period_start": PERIOD_START,
            "period_end": PERIOD_END,
            "billing_source_account": provider_id,
        },
        scope_key=f"{provider_id}/{ACCOUNT}/global/billing",
        evidence_id=f"evidence-{provider_id}",
    )


def test_canonical_billing_keeps_sources_and_never_sums_disagreement() -> None:
    canonical = canonical_billing_observations([_billing("aws-z", 40), _billing("aws-a", 10, "EUR")])

    assert len(canonical) == 1
    cost = canonical[0]
    assert cost.provider_id == "aws-a"
    assert cost.resource_key == billing_key(ACCOUNT, SERVICE, PERIOD_START, PERIOD_END)
    assert cost.attributes["amount"] == 10
    assert cost.attributes["unit"] == "EUR"
    assert cost.attributes["billing_disagreement"] is True
    assert cost.attributes["billing_disagreement_fields"] == ["amount", "unit"]
    assert [source["evidence_id"] for source in cost.attributes["billing_sources"]] == ["evidence-aws-a", "evidence-aws-z"]
    assert canonical_billing_observations(canonical) == canonical


def test_coverage_uses_the_same_non_additive_canonical_billing_view() -> None:
    reports = [
        DiscoveryReport(provider_id="aws-z", identity={"account": ACCOUNT}, observations=[_billing("aws-z", 40)]),
        DiscoveryReport(provider_id="aws-a", identity={"account": ACCOUNT}, observations=[_billing("aws-a", 10, "EUR")]),
    ]
    config = ServerConfig(providers=[
        ProviderConfig(id="aws-a", kind="aws", regions=["us-east-1"], expected_account_id=ACCOUNT),
        ProviderConfig(id="aws-z", kind="aws", regions=["us-east-1"], expected_account_id=ACCOUNT),
    ])

    rows = build_aws_coverage(reports, config, ["aws-a", "aws-z"], DiscoveryScope())["billing_service_coverage"]

    assert len(rows) == 1
    assert rows[0]["amount"] == 10
    assert rows[0]["disagreement"] is True
    assert rows[0]["disagreement_fields"] == ["amount", "unit"]
    assert len(rows[0]["sources"]) == 2


class _BillingAdapter:
    kind = "aws"

    def __init__(self, provider_id: str, report: DiscoveryReport) -> None:
        self.provider_id = provider_id
        self.config = ProviderConfig(id=provider_id, kind="aws", regions=["us-east-1"], expected_account_id=ACCOUNT)
        self._report = report

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, operations=[], required_credentials=[], credential_configured=True)

    async def check_availability(self, *, live: bool = False) -> Availability:
        return Availability(available=True)

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        return self._report

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        return EvidenceResult()


@pytest.fixture
async def billing_context(tmp_path: Path) -> AsyncIterator[OperationContext]:
    db = Database(tmp_path / "state" / "db.sqlite", tmp_path / "state" / "evidence")
    await db.open()
    catalog = tmp_path / "catalog"
    (catalog / "services").mkdir(parents=True)
    (catalog / "catalog.yaml").write_text("name: billing-test\n", encoding="utf-8")
    yield OperationContext(
        db=db,
        config=ServerConfig(),
        catalog=load_catalog(catalog),
        providers=ProviderRegistry(),
        sanitizer=Sanitizer(),
        principal=Principal(id="test", name="test", grants=frozenset()),
        request={"id": "billing-first", "review_mode": "yolo"},
        budget=Budget(deadline=utcnow() + timedelta(seconds=30), max_bytes=1_000_000),
    )
    await db.close()


async def test_scan_and_storage_keep_one_billing_observation_when_representative_changes(billing_context: OperationContext) -> None:
    first_a = _BillingAdapter("aws-a", DiscoveryReport(provider_id="aws-a", identity={"account": ACCOUNT}, observations=[_billing("aws-a", 9.5)], completed_scopes=[f"aws-a/{ACCOUNT}/global/billing"]))
    first_z = _BillingAdapter("aws-z", DiscoveryReport(provider_id="aws-z", identity={"account": ACCOUNT}, observations=[_billing("aws-z", 9.5)], completed_scopes=[f"aws-z/{ACCOUNT}/global/billing"]))
    billing_context.config = ServerConfig(providers=[first_a.config, first_z.config])
    billing_context.providers.register(first_a)
    billing_context.providers.register(first_z)

    first = await run_scan(billing_context, DiscoveryScanArgs(providers=["aws-a", "aws-z"], scope=DiscoveryScope(families=["billing"])))
    assert len([item for item in first.result["items"] if item["resource_type"] == "aws/billing_service_cost"]) == 1
    assert len(await billing_context.db.observations()) == 1

    second_z = _BillingAdapter("aws-z", DiscoveryReport(provider_id="aws-z", identity={"account": ACCOUNT}, observations=[_billing("aws-z", 9.5)], completed_scopes=[f"aws-z/{ACCOUNT}/global/billing"]))
    billing_context.config = ServerConfig(providers=[second_z.config])
    billing_context.providers = ProviderRegistry()
    billing_context.providers.register(second_z)
    billing_context.request = {"id": "billing-second", "review_mode": "yolo"}

    await run_scan(billing_context, DiscoveryScanArgs(providers=["aws-z"], scope=DiscoveryScope(families=["billing"])))
    rows = await billing_context.db.observations()
    assert len(rows) == 1
    assert rows[0]["provider_id"] == "aws-z"
    assert rows[0]["attributes"]["billing_source_count"] == 1
    assert rows[0]["attributes"]["billing_sources"] == [{
        "provider_id": "aws-z", "resource_key": "raw:aws-z", "scope_key": f"aws-z/{ACCOUNT}/global/billing", "evidence_id": "evidence-aws-z", "billing_source_account": "aws-z", "amount": 9.5, "unit": "USD",
    }]
