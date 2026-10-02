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


@pytest.mark.asyncio
@pytest.mark.parametrize(('query_type', 'scope', 'expected'), [
    ('cloudwatch_metrics', {'region': 'us-west-2'}, 'scope.queries'),
    ('cloudwatch_metrics', {'queries': [{'namespace': 'AWS/EC2'}]}, 'namespace and metric_name'),
    ('cloudwatch_metrics', {'queries': [{'namespace': 'n', 'metric_name': 'm'}] * 21}, 'at most 20'),
    ('cloudwatch_logs', {}, 'scope.log_groups'),
    ('container_logs', {'namespace': 'demo'}, 'workload_name'),
    ('kubernetes_events', {}, 'scope.namespace'),
    ('github_workflow_runs', {}, 'scope.repository'),
])
async def test_evidence_query_scope_shape_rejected_at_submit(env: Env, query_type: str, scope: dict, expected: str) -> None:
    # A malformed query fails synchronously with its reason; it never becomes a request awaiting review.
    result = await env.call('read', 'evidence_query', {'source_id': 'demo-fake', 'query_type': query_type, 'scope': scope})
    assert result['__error__']['error'] == 'invalid_argument'
    assert expected in result['__error__']['message']
    assert 'request_id' not in result
