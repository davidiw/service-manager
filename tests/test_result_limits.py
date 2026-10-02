"""Pagination validation stays a typed error at the MCP boundary."""
import pytest

from tests.conftest import Env


@pytest.mark.asyncio
@pytest.mark.parametrize(('offset', 'limit'), [(0, 501), (0, 0), (-1, 50)])
async def test_result_invalid_page_is_typed(env: Env, offset: int, limit: int) -> None:
    result = await env.call('read', 'request_result', {'request_id': 'req_missing', 'offset': offset, 'limit': limit})
    assert result['__error__']['error'] == 'invalid_argument'
    assert '500' in result['__error__']['message']


@pytest.mark.asyncio
async def test_discovery_page_total_matches_unique_observations(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = env.core.providers.get('demo-fake')
    assert adapter is not None
    original = adapter.discover

    async def duplicate(*args, **kwargs):
        report = await original(*args, **kwargs)
        report.observations.extend(report.observations[:2])
        return report

    monkeypatch.setattr(adapter, 'discover', duplicate)
    submitted = await env.call('read', 'discovery_scan', {'providers': ['demo-fake']})
    rid = submitted['request_id']
    await env.approve(rid)
    await env.wait('read', rid)
    await env.release(rid)
    result = await env.call('read', 'request_result', {'request_id': rid, 'limit': 500})
    assert result['page']['total'] == len({item['observation_id'] for item in result['items']})
    assert result['summary']['observations'] == result['page']['total']
