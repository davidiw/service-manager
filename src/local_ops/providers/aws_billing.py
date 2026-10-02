"""Canonical, provenance-preserving AWS Cost Explorer observations.

Cost Explorer is visible from more than one configured AWS credential (most commonly a
management account and a member account).  Those views overlap, so cost observations are
not additive.  This module deliberately chooses a deterministic representative and carries
every source alongside it rather than manufacturing a combined total.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

from local_ops.providers.base import Observation

BILLING_RESOURCE_TYPE = "aws/billing_service_cost"


def _text(value: Any) -> str:
    return str(value) if value is not None else ""


def _amount(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _source_from_observation(observation: Observation) -> list[dict[str, Any]]:
    """Recover raw provenance from either an adapter observation or an earlier merge."""
    saved = observation.attributes.get("billing_sources")
    if isinstance(saved, list) and all(isinstance(item, dict) for item in saved):
        return [dict(item) for item in saved]
    return [{
        "provider_id": observation.provider_id,
        "resource_key": observation.resource_key,
        "scope_key": observation.scope_key,
        "evidence_id": observation.evidence_id,
        "billing_source_account": observation.attributes.get("billing_source_account"),
        "amount": _amount(observation.attributes.get("amount")),
        "unit": observation.attributes.get("unit"),
    }]


def _source_order(source: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        _text(source.get("provider_id")),
        _text(source.get("resource_key")),
        _text(source.get("evidence_id")),
        _text(source.get("billing_source_account")),
    )


def billing_key(account: str, service: str, period_start: str, period_end: str) -> str:
    """A reversible canonical key; service labels are encoded rather than slugged."""
    return f"aws:{account}:global:billing:{quote(service, safe='')}:{quote(period_start, safe='')}:{quote(period_end, safe='')}"


def canonical_billing_observations(observations: Iterable[Observation]) -> list[Observation]:
    """Return non-billing observations plus one cost observation per account/service/period.

    The result is intentionally idempotent.  It never sums sources because two credentials
    may report the same account's charge.  A conflicting amount or currency remains visible
    as disagreement metadata and the stable first source supplies the displayed amount.
    """
    passthrough: list[Observation] = []
    grouped: dict[tuple[str, str, str, str], list[Observation]] = defaultdict(list)
    for observation in observations:
        if observation.resource_type != BILLING_RESOURCE_TYPE:
            passthrough.append(observation)
            continue
        grouped[(
            _text(observation.identity.get("account")),
            _text(observation.identity.get("service")),
            _text(observation.attributes.get("period_start")),
            _text(observation.attributes.get("period_end")),
        )].append(observation)

    merged: list[Observation] = []
    for (account, service, period_start, period_end), group in sorted(grouped.items()):
        source_pairs = [(source, observation) for observation in group for source in _source_from_observation(observation)]
        source_pairs.sort(key=lambda pair: _source_order(pair[0]))
        sources = [source for source, _ in source_pairs]
        representative_source, representative_observation = source_pairs[0]
        variants = {(_amount(source.get("amount")), _text(source.get("unit"))) for source in sources}
        disagreement_fields: list[str] = []
        if len({_amount(source.get("amount")) for source in sources}) > 1:
            disagreement_fields.append("amount")
        if len({_text(source.get("unit")) for source in sources}) > 1:
            disagreement_fields.append("unit")
        attributes = dict(representative_observation.attributes)
        attributes.update({
            "amount": _amount(representative_source.get("amount")),
            "unit": representative_source.get("unit"),
            "period_start": period_start,
            "period_end": period_end,
            "billing_sources": sources,
            "billing_source_count": len(sources),
            "billing_disagreement": bool(disagreement_fields),
            "billing_disagreement_fields": disagreement_fields,
            "billing_amount_variants": [
                {"amount": amount, "unit": unit}
                for amount, unit in sorted(variants)
            ],
        })
        merged.append(Observation(
            provider_id=_text(representative_source.get("provider_id")) or representative_observation.provider_id,
            resource_key=billing_key(account, service, period_start, period_end),
            resource_type=BILLING_RESOURCE_TYPE,
            identity={"account": account, "region": "global", "id": billing_key(account, service, period_start, period_end), "service": service},
            attributes=attributes,
            scope_key=_text(representative_source.get("scope_key")) or representative_observation.scope_key,
            evidence_id=_text(representative_source.get("evidence_id")) or representative_observation.evidence_id,
        ))
    return passthrough + merged
