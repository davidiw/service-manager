"""Live-scan result counts use the same identities as durable observations."""
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
from local_ops.providers.base import DiscoveryReport, Observation, ProviderRegistry
from local_ops.release import Sanitizer
from local_ops.storage import Database


@pytest.mark.asyncio
async def test_scan_deduplicates_results_and_non_aws_coverage(tmp_path: Path) -> None:
    db = Database(tmp_path / 'db.sqlite', tmp_path / 'evidence')
    await db.open()
    try:
        catalog_path = tmp_path / 'catalog'
        (catalog_path / 'services').mkdir(parents=True)
        (catalog_path / 'catalog.yaml').write_text('name: test\n')
        provider = ProviderConfig(id='op-user', kind='onepassword')
        obs = Observation(provider_id=provider.id, resource_key='vault/item', resource_type='onepassword/item', identity={'id': 'item'}, scope_key='op-user/vault')
        report = DiscoveryReport(provider_id=provider.id, observations=[obs, obs.model_copy(update={'attributes': {'title': 'latest'}})], completed_scopes=['op-user/vault'])

        class Adapter:
            provider_id = provider.id
            kind = provider.kind

            async def discover(self, *args: Any) -> DiscoveryReport:
                return report

        registry = ProviderRegistry()
        registry.register(Adapter())  # type: ignore[arg-type]
        ctx = OperationContext(db=db, config=ServerConfig(providers=[provider]), catalog=load_catalog(catalog_path), providers=registry, sanitizer=Sanitizer(), principal=Principal(id='p', name='test', grants=frozenset()), request={'id': 'req_test'}, budget=Budget(utcnow() + timedelta(seconds=60), 100000))
        result = (await run_scan(ctx, DiscoveryScanArgs())).result
        assert 'aws_coverage' not in result
        assert result['summary']['observations'] == 1
        assert result['summary']['denominators']['clusters_requested'] == 0
        assert len(result['items']) == 1
        assert result['items'][0]['attributes']['title'] == 'latest'
        stored = await db.observations_for_scan('req_test')
        assert len(stored) == 1
        assert stored[0]['id'] == result['items'][0]['observation_id']
        assert stored[0]['missing_since'] is None
    finally:
        await db.close()
