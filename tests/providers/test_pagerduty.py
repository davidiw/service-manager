"""PagerDuty adapter tests. No network: httpx.MockTransport serves canned responses and records every request."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import NormalizedEvent, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.pagerduty import PagerDutyAdapter, drop_integration_keys
from local_ops.release import Sanitizer
from local_ops.storage import MIGRATIONS_DIR, Database

SECRET = "u+pagerduty-api-token-0123456789"
INTEGRATION_KEY = "0123456789abcdef0123456789abcdef"

_open_dbs: list[Database] = []


async def _migrate_without_tx(self: Database) -> None:
    """Workaround for a pre-existing storage bug (see test_grafana.py): executescript inside an explicit
    transaction makes the trailing COMMIT fail on a fresh database."""
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


def evidence_text(ctx: OperationContext) -> str:
    return "\n".join((ctx.db.evidence_dir / f"{eid[:6]}/{eid}.bin").read_text() for eid in ctx.evidence_ids)


class FakePagerDuty:
    """Offset-paginated fake honouring `limit`/`offset` and answering with `more`."""

    def __init__(self, services: int = 3, page_size_cap: int = 2):
        self.requests: list[httpx.Request] = []
        self.page_size_cap = page_size_cap
        self.services = [{"id": f"P{i:03d}", "name": f"svc-{i}", "status": "active", "description": "demo", "html_url": f"https://acme.pagerduty.com/service-directory/P{i:03d}", "escalation_policy": {"id": "PEP1", "type": "escalation_policy_reference", "summary": "Primary"}, "integrations": [{"id": f"PI{i}", "type": "events_api_v2_inbound_integration_reference", "summary": "Events API v2", "integration_key": INTEGRATION_KEY}], "teams": [{"summary": "Platform"}]} for i in range(services)]
        self.policies = [{"id": "PEP1", "name": "Primary", "description": None, "num_loops": 2, "escalation_rules": [{"escalation_delay_in_minutes": 30, "targets": [{"id": "PS1", "type": "schedule_reference", "summary": "Primary on-call"}]}, {"escalation_delay_in_minutes": 30, "targets": [{"id": "PU1", "type": "user_reference", "summary": "Alice Admin"}]}], "services": [{"summary": "svc-0"}], "teams": []}]
        self.schedules = [{"id": "PS1", "name": "Primary on-call", "time_zone": "UTC", "html_url": "https://acme.pagerduty.com/schedules/PS1", "users": [{"summary": "Alice Admin"}, {"summary": "Bob Builder"}], "escalation_policies": [{"summary": "Primary"}]}]
        self.incidents = [{"id": f"Q{i:03d}", "incident_number": 100 + i, "title": f"Incident {i} api_key=verysecretvalue123", "status": "resolved" if i % 2 else "triggered", "urgency": "high", "created_at": f"2026-09-30T1{i}:00:00Z", "last_status_change_at": f"2026-09-30T1{i}:30:00Z", "service": {"id": "P000", "summary": "svc-0"}, "assignments": [{"assignee": {"summary": "Alice Admin"}}] if i % 2 == 0 else [], "html_url": f"https://acme.pagerduty.com/incidents/Q{i:03d}", "escalation_policy": {"summary": "Primary"}, "last_status_change_by": {"summary": "Alice Admin"}, "body": {"details": {"integration_key": INTEGRATION_KEY}}} for i in range(5)]

    def page(self, key: str, rows: list[dict[str, Any]], request: httpx.Request) -> httpx.Response:
        q = parse_qs(request.url.query.decode())
        limit = min(int(q.get("limit", ["25"])[0]), self.page_size_cap)
        offset = int(q.get("offset", ["0"])[0])
        chunk = rows[offset : offset + limit]
        return httpx.Response(200, json={key: chunk, "limit": limit, "offset": offset, "more": offset + len(chunk) < len(rows), "total": None})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["accept"] == "application/vnd.pagerduty+json;version=2"
        assert request.headers["authorization"] == f"Token token={SECRET}"
        path = request.url.path
        if path == "/services":
            return self.page("services", self.services, request)
        if path == "/escalation_policies":
            return self.page("escalation_policies", self.policies, request)
        if path == "/schedules":
            return self.page("schedules", self.schedules, request)
        if path == "/incidents":
            q = parse_qs(request.url.query.decode())
            rows = self.incidents
            if "statuses[]" in q:
                rows = [r for r in rows if r["status"] in q["statuses[]"]]
            if "service_ids[]" in q:
                rows = [r for r in rows if r["service"]["id"] in q["service_ids[]"]]
            return self.page("incidents", rows, request)
        if path == "/abilities":
            return httpx.Response(200, json={"abilities": ["read"]})
        return httpx.Response(404, json={"error": {"message": "not found"}})


def build(monkeypatch: pytest.MonkeyPatch, fake: FakePagerDuty, url: str | None = None) -> tuple[ServerConfig, PagerDutyAdapter]:
    monkeypatch.setenv("PD_TOKEN", SECRET)
    cfg = ServerConfig(credentials=[CredentialRef(id="pd", kind="env", env_var="PD_TOKEN")], providers=[ProviderConfig(id="pd-1", kind="pagerduty", credential="pd", url=url)])
    adapter = PagerDutyAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(fake)))
    return cfg, adapter


@pytest.mark.asyncio
async def test_discover_paginates_via_more_and_drops_integration_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePagerDuty(services=3, page_size_cap=2)
    cfg, adapter = build(monkeypatch, fake)
    assert adapter.base_url == "https://api.pagerduty.com"
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    by_type: dict[str, list[Any]] = {}
    for o in report.observations:
        by_type.setdefault(o.resource_type, []).append(o)
    assert len(by_type["pagerduty/service"]) == 3  # two pages (2 + 1) joined via `more`
    assert len(by_type["pagerduty/escalation_policy"]) == 1 and len(by_type["pagerduty/schedule"]) == 1
    service_requests = [r for r in fake.requests if r.url.path == "/services"]
    assert [parse_qs(r.url.query.decode())["offset"][0] for r in service_requests] == ["0", "2"]
    svc = by_type["pagerduty/service"][0]
    assert svc.attributes["integrations"] == [{"type": "events_api_v2_inbound_integration_reference", "name": "Events API v2"}]
    assert svc.attributes["escalation_policy"] == {"id": "PEP1", "name": "Primary"}
    assert svc.relationships == [{"kind": "depends_on", "target": "pagerduty:pd-1:escalation_policy:PEP1"}]
    ep = by_type["pagerduty/escalation_policy"][0]
    assert ep.attributes["knowledge_holders"] == ["Alice Admin", "Primary on-call"]
    assert ep.relationships == [{"kind": "depends_on", "target": "pagerduty:pd-1:schedule:PS1"}]
    assert by_type["pagerduty/schedule"][0].attributes["users"] == ["Alice Admin", "Bob Builder"]
    dumped = json.dumps([o.model_dump() for o in report.observations])
    assert INTEGRATION_KEY not in dumped and "integration_key" not in dumped
    assert INTEGRATION_KEY not in evidence_text(ctx) and "integration_key" not in evidence_text(ctx)
    assert set(report.completed_scopes) == {"pd-1/services", "pd-1/escalation_policies", "pd-1/schedules"}
    assert all(r.method == "GET" for r in fake.requests)


@pytest.mark.asyncio
async def test_incidents_query_filters_paginates_and_normalizes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePagerDuty(page_size_cap=2)
    cfg, adapter = build(monkeypatch, fake, url="https://api.eu.pagerduty.com/")
    ctx = await make_ctx(tmp_path, cfg)
    q = {"query_type": "pagerduty_incidents", "scope": {"service_ids": ["P000"]}, "filters": {"statuses": ["triggered", "resolved"]}, "time_range": {"start": "2026-09-30T00:00:00Z", "end": "2026-10-01T00:00:00Z"}, "limits": {"max_events": 100}}
    res = await adapter.query(ctx, q, ctx.budget)
    assert len(res.items) == 5 and res.coverage.pagination_complete and not res.coverage.truncated
    inc_requests = [r for r in fake.requests if r.url.path == "/incidents"]
    assert len(inc_requests) == 3  # 2 + 2 + 1 via `more`
    first = parse_qs(inc_requests[0].url.query.decode())
    assert first["since"] == ["2026-09-30T00:00:00Z"] and first["until"] == ["2026-10-01T00:00:00Z"]
    assert first["statuses[]"] == ["triggered", "resolved"] and first["service_ids[]"] == ["P000"]
    assert res.items[0] == {"id": "Q000", "incident_number": 100, "title": res.items[0]["title"], "status": "triggered", "urgency": "high", "created_at": "2026-09-30T10:00:00Z", "service": {"id": "P000", "name": "svc-0"}, "assignments": ["Alice Admin"], "last_status_change_at": "2026-09-30T10:30:00Z", "html_url": "https://acme.pagerduty.com/incidents/Q000", "escalation_policy": "Primary", "last_status_change_by": "Alice Admin"}
    events = [NormalizedEvent.model_validate(e) for e in res.events]
    assert events[0].action == "incident:triggered" and events[0].actor == "Alice Admin" and events[0].category == "incident"
    assert events[1].action == "incident:resolved" and events[1].actor == "pagerduty"
    assert len({e.event_key for e in events}) == 5
    assert res.coverage.filters_provider_side == ["time_range", "statuses", "service_ids", "limit"]
    assert res.coverage.time_range_observed == {"first_event": "2026-09-30T10:30:00Z", "last_event": "2026-09-30T14:30:00Z"}
    assert "verysecretvalue123" not in evidence_text(ctx)  # sanitizer scrubbed the key=value in the title
    assert INTEGRATION_KEY not in evidence_text(ctx) and INTEGRATION_KEY not in json.dumps(res.model_dump())
    assert all(r.method == "GET" for r in fake.requests)


@pytest.mark.asyncio
async def test_incidents_bounded_by_max_events(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePagerDuty(page_size_cap=2)
    cfg, adapter = build(monkeypatch, fake)
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "pagerduty_incidents", "limits": {"max_events": 3}}, ctx.budget)
    assert len(res.items) == 3 and res.coverage.truncated and not res.coverage.pagination_complete
    assert any("bounded to 3" in g for g in res.coverage.collection_gaps)
    limits = [parse_qs(r.url.query.decode())["limit"][0] for r in fake.requests]
    assert limits == ["3", "1"]  # never asks for more than the remaining bound


@pytest.mark.asyncio
async def test_never_calls_write_endpoints_and_describes_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakePagerDuty()
    cfg, adapter = build(monkeypatch, fake)
    ctx = await make_ctx(tmp_path, cfg)
    await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    await adapter.query(ctx, {"query_type": "pagerduty_incidents"}, ctx.budget)
    await adapter.check_availability(live=True)
    assert fake.requests and all(r.method == "GET" for r in fake.requests)
    assert all(r.url.path in ("/services", "/escalation_policies", "/schedules", "/incidents", "/abilities") for r in fake.requests)
    desc = adapter.describe()
    assert "read-only; does not trigger pages" in desc.limitations
    assert all(op.effect == "read" for op in desc.operations)
    res = await adapter.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert res.coverage.unavailable_scopes[0].reason == "unsupported_query_type"


@pytest.mark.asyncio
async def test_permission_failure_becomes_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbid(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "forbidden"}})

    monkeypatch.setenv("PD_TOKEN", SECRET)
    cfg = ServerConfig(credentials=[CredentialRef(id="pd", kind="env", env_var="PD_TOKEN")], providers=[ProviderConfig(id="pd-1", kind="pagerduty", credential="pd")])
    adapter = PagerDutyAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(forbid)))
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == [] and {u["reason"] for u in report.unavailable} == {"permission_denied"}
    res = await adapter.query(ctx, {"query_type": "pagerduty_incidents"}, ctx.budget)
    assert res.events == [] and res.coverage.unavailable_scopes[0].reason == "permission_denied"


def test_drop_integration_keys_is_recursive() -> None:
    payload = {"a": [{"integration_key": "x", "name": "n"}], "routing_key": "y", "nested": {"Integration_Key": "z", "ok": 1}}
    assert drop_integration_keys(payload) == {"a": [{"name": "n"}], "nested": {"ok": 1}}
