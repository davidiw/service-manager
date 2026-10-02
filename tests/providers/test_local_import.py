"""Local import adapter tests: fixture files written to tmp_path, no network."""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import NormalizedEvent, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers import local_import as li
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.local_import import LocalImportAdapter, classify
from local_ops.release import Sanitizer
from local_ops.storage import MIGRATIONS_DIR, Database

GHP = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_open_dbs: list[Database] = []


async def _migrate_without_tx(self: Database) -> None:
    """Workaround for a pre-existing storage bug (see test_grafana.py)."""
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


def write_fixtures(tmp_path: Path) -> Path:
    imports = tmp_path / "imports"
    (imports / "sub").mkdir(parents=True)
    (imports / "billing.csv").write_text("vendor,amount,currency,period,description,service_hint\nHetzner,42.50,EUR,2026-09,Cloud server CX31,api\nNamecheap,12.00,USD,2026-09,Domain renewal example.org,\n")
    (imports / "registrar.json").write_text(json.dumps([{"domain": "Example.org", "registrar": "Namecheap", "expires_at": "2027-03-01T00:00:00Z", "auto_renew": "yes", "nameservers": "ns1.example.net, ns2.example.net"}, {"domain": "legacy.example", "registrar": "Gandi"}]))
    (imports / "identities.json").write_text(json.dumps({"records": [{"id": "carol", "status": "departed", "departed_at": "2026-08-15"}, {"id": "alice", "status": "active"}, "not-an-object"]}))
    (imports / "dns.records.csv").write_text("name,type,value,ttl\napi.example.org,CNAME,lb.example.net,300\n")
    (imports / "services.claims.jsonl").write_text(json.dumps({"id": "api", "name": "Public API", "owner": "platform", "location": "hetzner"}) + "\n")
    (imports / "sub" / "notes.md").write_text("# Runbook: API restarts\n\nRestart via helm. password=hunter2hunter2 must not leak.\n")
    (imports / "notes.extra.md").write_text("no heading here\n")
    (imports / "events.sample.jsonl").write_text("\n".join([
        json.dumps({"event_key": "imp:1", "provider": "vendor-x", "source_id": "vendor-x-export", "occurred_at": "2026-09-30T10:00:00Z", "action": "login", "actor": "carol", "fields": {"token": GHP, "note": f"used {GHP}"}}),
        json.dumps({"event_key": "imp:2", "provider": "vendor-x", "source_id": "vendor-x-export", "action": "logout", "actor": "carol"}),  # missing occurred_at
        "{this is not json",
        json.dumps({"event_key": "imp:3", "provider": "vendor-x", "source_id": "vendor-x-export", "occurred_at": "2026-09-30T11:00:00Z", "action": "delete_user", "actor": "carol", "collected_at": "2026-09-30T12:00:00Z"}),
    ]) + "\n")
    (imports / "mystery.csv").write_text("a,b\n1,2\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "billing.secret.csv").write_text("vendor,amount\nleak,1\n")
    os.symlink(outside / "billing.secret.csv", imports / "billing.linked.csv")
    os.symlink(outside, imports / "sub" / "escape")
    return imports


def build(tmp_path: Path) -> tuple[ServerConfig, LocalImportAdapter]:
    cfg = ServerConfig(providers=[ProviderConfig(id="imp", kind="local_import", path=str(tmp_path / "imports"))])
    return cfg, LocalImportAdapter(cfg.providers[0], cfg, None)


def test_classify() -> None:
    assert classify(Path("billing.csv")) == ("billing", "billing", ".csv")
    assert classify(Path("events.sample.jsonl")) == ("events", "sample", ".jsonl")
    assert classify(Path("dns.prod.zone.json")) == ("dns", "prod.zone", ".json")
    assert classify(Path("mystery.csv"))[0] is None
    assert classify(Path("README"))[0] is None


@pytest.mark.asyncio
async def test_discover_formats_provenance_expiries_and_refusals(tmp_path: Path) -> None:
    write_fixtures(tmp_path)
    cfg, adapter = build(tmp_path)
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    by_type: dict[str, list[Any]] = {}
    for o in report.observations:
        by_type.setdefault(o.resource_type, []).append(o)
    assert {k: len(v) for k, v in by_type.items()} == {"import/billing_line": 2, "import/domain": 2, "import/identity": 2, "import/dns_record": 1, "import/service_claim": 1, "import/note": 2}
    # provenance on every observation
    for o in report.observations:
        assert o.attributes["imported"] is True and o.attributes["fixture"] is False
        assert o.attributes["source_file"] and not Path(o.attributes["source_file"]).is_absolute()
        assert o.attributes["imported_at"].endswith("Z") and o.evidence_id
    billing = by_type["import/billing_line"][0]
    assert billing.attributes["vendor"] == "Hetzner" and billing.attributes["amount"] == "42.50" and billing.attributes["service_hint"] == "api"
    assert billing.attributes["source_file"] == "billing.csv" and billing.relationships == []
    domain = next(o for o in by_type["import/domain"] if o.identity["domain"] == "example.org")
    assert domain.resource_key == "import:imp:domain:example.org"
    assert domain.attributes["auto_renew"] is True and domain.attributes["nameservers"] == ["ns1.example.net", "ns2.example.net"]
    assert report.expiries == [{"resource_key": "import:imp:domain:example.org", "kind": "domain", "expires_at": "2027-03-01T00:00:00Z", "source_file": "registrar.json", "imported": True}]
    carol = next(o for o in by_type["import/identity"] if o.identity["id"] == "carol")
    assert carol.attributes["status"] == "departed" and carol.attributes["departed_at"] == "2026-08-15"
    assert by_type["import/dns_record"][0].attributes["type"] == "CNAME" and by_type["import/dns_record"][0].attributes["source_file"] == "dns.records.csv"
    assert by_type["import/service_claim"][0].resource_key == "import:imp:service_claim:api"
    runbook = next(o for o in by_type["import/note"] if o.attributes["source_file"] == "sub/notes.md")
    assert runbook.identity["title"] == "Runbook: API restarts" and "Restart via helm" in runbook.attributes["body"]
    assert "hunter2hunter2" not in evidence_text(ctx)  # stored note content was scrubbed
    # refusals and skips are notes, never crashes
    notes = "\n".join(report.notes)
    assert "billing.linked.csv: symlink escapes the import directory; refused" in notes
    assert "sub/escape: symlink escapes the import directory; refused" in notes
    assert "mystery.csv: no recognised kind prefix" in notes
    assert "identities.json: record 2 is not an object; skipped" in notes
    assert "events.sample.jsonl: event files are loaded by evidence_query" in notes
    assert not any(o.attributes.get("vendor") == "leak" for o in by_type["import/billing_line"])  # escaped symlink content never read
    # billing.linked.csv (a refused symlink) means the "billing" kind cannot be claimed complete, even
    # though billing.csv itself parsed fine: absence of a billing line beyond what billing.csv held is
    # unknown, not confirmed.
    assert set(report.completed_scopes) == {"imp/registrar", "imp/identities", "imp/dns", "imp/services", "imp/notes"}
    assert report.partial_scopes == ["imp/billing"]


@pytest.mark.asyncio
async def test_oversized_file_skipped_with_note(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_fixtures(tmp_path)
    monkeypatch.setattr(li, "MAX_FILE_BYTES", 50)
    cfg, adapter = build(tmp_path)
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert any("billing.csv:" in n and "exceeds the 50 byte bound; skipped" in n for n in report.notes)
    assert not any(o.resource_type == "import/billing_line" for o in report.observations)
    # the oversized billing.csv means "billing" cannot be claimed complete even though billing.linked.csv
    # (also a billing-kind file) was refused for an unrelated reason: both failures land on the same kind.
    assert "imp/billing" in report.partial_scopes
    assert "imp/billing" not in report.completed_scopes


@pytest.mark.asyncio
async def test_non_list_json_file_marks_kind_partial_not_complete(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    imports.mkdir(parents=True)
    (imports / "dns.single.json").write_text(json.dumps({"name": "api.example.org", "type": "A", "value": "203.0.113.5"}))
    cfg, adapter = build(tmp_path)
    ctx = await make_ctx(tmp_path, cfg)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == []
    assert "imp/dns" in report.partial_scopes
    assert "imp/dns" not in report.completed_scopes
    assert any("expected a JSON list" in n for n in report.notes)


@pytest.mark.asyncio
async def test_events_query_validates_rows_and_scrubs_evidence(tmp_path: Path) -> None:
    write_fixtures(tmp_path)
    cfg, adapter = build(tmp_path)
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "local_import", "filters": {"kind": "events"}, "limits": {"max_events": 100}}, ctx.budget)
    assert [e["event_key"] for e in res.events] == ["imp:1", "imp:3"]
    events = [NormalizedEvent.model_validate(e) for e in res.events]
    assert events[0].collected_at is not None and events[0].fields["source_file"] == "events.sample.jsonl" and events[0].fields["imported"] is True
    assert events[1].collected_at.isoformat().startswith("2026-09-30T12:00:00")  # explicit collected_at preserved
    assert all(e.evidence_ref for e in events)
    notes = "\n".join(res.notes)
    assert "imported events are claims from a reviewed file, not live collection" in notes
    assert "record 1 missing required keys ['occurred_at']; skipped" in notes
    assert "line 3: invalid JSON" in notes
    assert "symlink escapes the import directory; refused" in notes
    assert res.coverage.source_retention_known is False and res.coverage.filters_local == ["kind"]
    assert res.coverage.time_range_observed == {"first_event": "2026-09-30T10:00:00Z", "last_event": "2026-09-30T11:00:00Z"}
    assert all(i["imported"] is True for i in res.items)
    assert GHP not in evidence_text(ctx) and "REDACTED" in evidence_text(ctx)
    assert res.query_description == {"path": str(tmp_path / "imports"), "files": ["events.sample.jsonl"], "kind": "events", "imported": True}


@pytest.mark.asyncio
async def test_events_query_bounded_and_unsupported_kinds(tmp_path: Path) -> None:
    write_fixtures(tmp_path)
    cfg, adapter = build(tmp_path)
    ctx = await make_ctx(tmp_path, cfg)
    res = await adapter.query(ctx, {"query_type": "local_import", "filters": {"kind": "events"}, "limits": {"max_events": 1}}, ctx.budget)
    assert len(res.events) == 1 and res.coverage.truncated is True
    res = await adapter.query(ctx, {"query_type": "local_import", "filters": {"kind": "billing"}}, ctx.budget)
    assert res.events == [] and res.coverage.unavailable_scopes[0].reason == "unsupported_query_type"
    res = await adapter.query(ctx, {"query_type": "cloudtrail_events"}, ctx.budget)
    assert res.coverage.unavailable_scopes[0].reason == "unsupported_query_type"


@pytest.mark.asyncio
async def test_missing_path_is_unavailable_not_crash(tmp_path: Path) -> None:
    cfg, adapter = build(tmp_path)  # tmp_path/imports does not exist
    ctx = await make_ctx(tmp_path, cfg)
    assert (await adapter.check_availability()).available is False
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert report.observations == [] and report.unavailable[0]["reason"] == "path_missing"
    desc = adapter.describe()
    assert any("Never executes imported content" in lim for lim in desc.limitations)
