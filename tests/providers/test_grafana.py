"""Grafana / Prometheus / Loki adapter tests. No network: httpx.MockTransport serves canned responses."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.grafana import GrafanaAdapter, LokiAdapter, PrometheusAdapter
from local_ops.release import Sanitizer
from local_ops.storage import MIGRATIONS_DIR, Database

SECRET = "grafana-service-account-token-abcdef0123456789"


_open_dbs: list[Database] = []


async def _migrate_without_tx(self: Database) -> None:
    """Workaround for a pre-existing storage bug: Database.migrate() wraps `executescript` in an explicit
    BEGIN IMMEDIATE, but sqlite's executescript implicitly COMMITs first, so the trailing COMMIT fails
    ("cannot commit - no transaction is active") on every fresh database. Apply the migrations plainly."""
    await self.conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    cur = await self.conn.execute("SELECT MAX(version) FROM schema_version")
    row = await cur.fetchone()
    current = (row[0] or 0) if row else 0
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = int(f.name.split("_", 1)[0])
        if version > current:
            await self.conn.executescript(f.read_text(encoding="utf-8"))
            await self.conn.execute("INSERT INTO schema_version(version) VALUES (?)", (version,))


@pytest.fixture(autouse=True)
async def _close_dbs(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Always close databases (aiosqlite's worker thread is non-daemon and would hang pytest)."""
    monkeypatch.setattr(Database, "migrate", _migrate_without_tx)
    yield
    while _open_dbs:
        await _open_dbs.pop().close()


async def make_ctx(tmp_path: Path, config: ServerConfig) -> OperationContext:
    db = Database(tmp_path / "s.db", tmp_path / "ev")
    await db.open()
    _open_dbs.append(db)
    cat_dir = tmp_path / "catalog"
    (cat_dir / "services").mkdir(parents=True)
    (cat_dir / "catalog.yaml").write_text("name: t\n")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    return OperationContext(db=db, config=config, catalog=load_catalog(cat_dir), providers=ProviderRegistry(), sanitizer=Sanitizer(), principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)


def server_config(monkeypatch: pytest.MonkeyPatch, kind: str, url: str) -> tuple[ServerConfig, ProviderConfig]:
    monkeypatch.setenv("OBS_TOKEN", SECRET)
    cfg = ServerConfig(credentials=[CredentialRef(id="obs", kind="env", env_var="OBS_TOKEN")], providers=[ProviderConfig(id=f"{kind}-1", kind=kind, url=url, credential="obs")])  # type: ignore[arg-type]
    return cfg, cfg.providers[0]


def evidence_text(ctx: OperationContext) -> str:
    out = []
    for eid in ctx.evidence_ids:
        rel = f"{eid[:6]}/{eid}.bin"
        out.append((ctx.db.evidence_dir / rel).read_text())
    return "\n".join(out)


class Recorder:
    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        handler = self.routes.get(path)
        if handler is None:
            return httpx.Response(404, json={"message": "not found"})
        if callable(handler):
            return handler(request)
        return httpx.Response(200, json=handler)


def loki_payload(n: int, base_ns: int = 1_760_000_000_000_000_000) -> dict[str, Any]:
    return {"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"app": "demo"}, "values": [[str(base_ns + i * 1_000_000_000), f"line {i} password=hunter2hunter2"] for i in range(n)]}]}}


def prom_payload() -> dict[str, Any]:
    return {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {"__name__": "up", "job": "demo"}, "values": [[1_760_000_000, "1"], [1_760_000_060, "0"]]}]}}


GRAFANA_DATASOURCES = [
    {"id": 1, "uid": "loki-uid", "name": "Loki", "type": "loki", "url": "http://loki:3100", "access": "proxy", "isDefault": False, "basicAuth": True, "basicAuthUser": "svc", "basicAuthPassword": "SUPERSECRETPASSWORD", "secureJsonData": {"httpHeaderValue1": "TOPSECRETHEADER"}, "secureJsonFields": {"httpHeaderValue1": True}, "jsonData": {"httpHeaderName1": "X-Scope-OrgID"}},
    {"id": 2, "uid": "prom-uid", "name": "Prometheus", "type": "prometheus", "url": "http://prom:9090", "access": "proxy", "isDefault": True, "basicAuth": False},
]


@pytest.mark.asyncio
async def test_grafana_discover_projects_datasources_without_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid/")
    rec = Recorder({
        "/api/datasources": GRAFANA_DATASOURCES,
        "/api/search": [{"id": 10, "uid": "dash-1", "title": "Demo", "url": "/d/dash-1/demo", "folderTitle": "Ops", "tags": ["demo"]}],
        "/api/v1/provisioning/alert-rules": [{"uid": "rule-1", "title": "High errors", "ruleGroup": "g", "folderUID": "f", "data": [{"refId": "A", "datasourceUid": "prom-uid"}], "labels": {"severity": "page"}, "annotations": {"summary": "errors"}}],
    })
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    types = {o.resource_type for o in report.observations}
    assert types == {"grafana/datasource", "grafana/dashboard", "grafana/alert_rule"}
    dumped = json.dumps([o.model_dump() for o in report.observations])
    for forbidden in ("SUPERSECRETPASSWORD", "TOPSECRETHEADER", "secureJsonData", "basicAuthPassword"):
        assert forbidden not in dumped
        assert forbidden not in evidence_text(ctx)
    loki_obs = next(o for o in report.observations if o.resource_key.endswith("datasource:loki-uid"))
    assert loki_obs.attributes["basic_auth_enabled"] is True and loki_obs.attributes["url"] == "http://loki:3100"
    rule = next(o for o in report.observations if o.resource_type == "grafana/alert_rule")
    assert rule.relationships == [{"kind": "depends_on", "target": "grafana:grafana-1:datasource:prom-uid"}]
    assert set(report.completed_scopes) == {"grafana-1/datasources", "grafana-1/dashboards", "grafana-1/alert_rules"}
    assert all(r.method == "GET" for r in rec.requests)
    assert rec.requests[0].headers["authorization"] == f"Bearer {SECRET}"
    assert "installs nothing" in " ".join(adapter.describe().limitations)


@pytest.mark.asyncio
async def test_grafana_alert_rules_404_is_note_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid")
    rec = Recorder({"/api/datasources": GRAFANA_DATASOURCES, "/api/search": []})
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.unavailable == []
    assert any("alert rule provisioning API not available" in n for n in report.notes)


@pytest.mark.asyncio
async def test_grafana_loki_proxy_truncation_and_stable_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid")
    seen: dict[str, Any] = {}

    def loki(request: httpx.Request) -> httpx.Response:
        seen.update(parse_qs(request.url.query.decode()))
        return httpx.Response(200, json=loki_payload(int(seen["limit"][0])))

    rec = Recorder({"/api/datasources/proxy/uid/loki-uid/loki/api/v1/query_range": loki})
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    q = {"query_type": "loki_logs", "scope": {"datasource_uid": "loki-uid"}, "filters": {"query": '{app="demo"}'}, "time_range": {"start": "2026-09-30T10:00:00Z", "end": "2026-09-30T11:00:00Z"}, "limits": {"max_events": 3}}
    res = await adapter.query(ctx, q, ctx.budget)
    assert seen["limit"] == ["3"] and seen["direction"] == ["backward"]
    assert len(seen["start"][0]) == 19 and seen["start"][0].endswith("000000000")  # nanoseconds
    assert len(res.items) == 3 and res.items[0]["line"].startswith("line 2")  # newest first
    assert res.coverage.truncated is True
    assert res.coverage.filters_provider_side == ["query", "time_range", "limit"]
    link = res.query_description["stable_link"]
    assert link.startswith("https://grafana.example.invalid/explore?")
    panes = json.loads(parse_qs(urlparse(link).query)["panes"][0])
    assert panes["grafana"]["datasource"] == "loki-uid" and panes["grafana"]["queries"][0]["expr"] == '{app="demo"}'
    assert res.raw_evidence_ids and "hunter2hunter2" not in evidence_text(ctx)  # sanitizer scrubbed the stored lines
    assert evidence_text(ctx).count('"line ') == 3  # evidence bounded to max_events entries


@pytest.mark.asyncio
async def test_grafana_loki_not_truncated_below_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid")
    rec = Recorder({"/api/datasources/proxy/uid/loki-uid/loki/api/v1/query_range": loki_payload(2)})
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "loki_logs", "scope": {"datasource_uid": "loki-uid"}, "filters": {"query": '{app="demo"}'}, "limits": {"max_events": 100}}, ctx.budget)
    assert len(res.items) == 2 and res.coverage.truncated is False
    assert res.coverage.completed_scopes == ["grafana-1"]


@pytest.mark.asyncio
async def test_grafana_prometheus_proxy_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid")
    seen: dict[str, Any] = {}

    def prom(request: httpx.Request) -> httpx.Response:
        seen.update(parse_qs(request.url.query.decode()))
        return httpx.Response(200, json=prom_payload())

    rec = Recorder({"/api/datasources/proxy/uid/prom-uid/api/v1/query_range": prom})
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "prometheus_metrics", "scope": {"datasource_uid": "prom-uid"}, "filters": {"query": "up", "step": "30s"}, "time_range": {"start": "2026-09-30T10:00:00Z", "end": "2026-09-30T11:00:00Z"}}, ctx.budget)
    assert seen["step"] == ["30s"] and seen["query"] == ["up"]
    assert [r["value"] for r in res.items] == ["1", "0"]
    assert res.items[0]["metric"]["job"] == "demo" and res.items[0]["timestamp"].endswith("Z")
    assert res.query_description["stable_link"].startswith("https://grafana.example.invalid/explore?")
    assert res.coverage.truncated is False


@pytest.mark.asyncio
async def test_grafana_requires_datasource_uid_and_rejects_unknown_query(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "grafana", "https://grafana.example.invalid")
    rec = Recorder({})
    adapter = GrafanaAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "loki_logs", "filters": {"query": "{}"}}, ctx.budget)
    assert res.coverage.unavailable_scopes[0].reason == "invalid_argument" and rec.requests == []
    res = await adapter.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert res.coverage.unavailable_scopes[0].reason == "unsupported_query_type"


@pytest.mark.asyncio
async def test_prometheus_direct_targets_and_query_range(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "prometheus", "http://prom.example.invalid:9090")
    rec = Recorder({
        "/api/v1/targets": {"status": "success", "data": {"activeTargets": [{"scrapePool": "demo", "scrapeUrl": "http://10.0.0.1:8080/metrics", "labels": {"job": "demo", "instance": "10.0.0.1:8080"}, "health": "up", "lastScrape": "2026-09-30T10:00:00Z", "lastError": ""}]}},
        "/api/v1/query_range": prom_payload(),
    })
    adapter = PrometheusAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert [o.resource_type for o in report.observations] == ["prometheus/target"]
    assert report.observations[0].identity["job"] == "demo" and report.completed_scopes == ["prometheus-1/targets"]
    res = await adapter.query(ctx, {"query_type": "prometheus_metrics", "filters": {"query": "up"}, "limits": {"max_events": 1}}, ctx.budget)
    assert len(res.items) == 1 and res.coverage.truncated is True
    assert res.query_description["stable_link"].startswith("http://prom.example.invalid:9090/graph?")
    assert all(r.method == "GET" for r in rec.requests)
    assert "installs nothing" in " ".join(adapter.describe().limitations)


@pytest.mark.asyncio
async def test_loki_direct_labels_query_and_basic_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "loki", "http://loki.example.invalid:3100")
    monkeypatch.setenv("OBS_TOKEN", "user:pass-word-123")
    rec = Recorder({"/loki/api/v1/labels": {"status": "success", "data": ["app", "namespace"]}, "/loki/api/v1/query_range": loki_payload(5)})
    adapter = LokiAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert len(report.observations) == 1 and report.observations[0].resource_type == "loki/instance"
    assert report.observations[0].attributes["labels"] == ["app", "namespace"]
    assert rec.requests[0].headers["authorization"].startswith("Basic ")
    res = await adapter.query(ctx, {"query_type": "loki_logs", "filters": {"query": '{app="demo"}'}, "limits": {"max_events": 5}}, ctx.budget)
    assert len(res.items) == 5 and res.coverage.truncated is True
    assert res.query_description["stable_link"].startswith("http://loki.example.invalid:3100/loki/api/v1/query_range?")
    assert "installs nothing" in " ".join(adapter.describe().limitations)


@pytest.mark.asyncio
async def test_provider_errors_become_coverage_gaps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg, pcfg = server_config(monkeypatch, "prometheus", "http://prom.example.invalid:9090")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    rec = Recorder({"/api/v1/query_range": boom, "/api/v1/targets": lambda r: httpx.Response(403, json={})})
    adapter = PrometheusAdapter(pcfg, cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(rec)))
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "prometheus_metrics", "filters": {"query": "up"}}, ctx.budget)
    assert res.items == [] and res.coverage.unavailable_scopes[0].reason == "provider_unavailable"
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == [] and report.unavailable[0]["reason"] == "permission_denied"
