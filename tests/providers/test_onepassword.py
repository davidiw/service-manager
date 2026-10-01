"""1Password SDK adapter (metadata-only discovery, internal secret resolution) and Events API adapter.
No network: the SDK client is a fake object and the Events API is served by httpx.MockTransport."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import ErrorCode, OpsError, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.onepassword import SCOPED_VIEW_LIMITATION, OnePasswordAdapter
from local_ops.providers.onepassword_events import OnePasswordEventsAdapter
from local_ops.release import Sanitizer
from local_ops.storage import Database

SECRET = "s3cr3t-password-value-ZZ"
SA_TOKEN = "ops_" + "A" * 40


_open_dbs: list[Database] = []


async def make_ctx(tmp_path: Path, config: ServerConfig, sanitizer: Sanitizer) -> OperationContext:
    db = Database(tmp_path / "s.db", tmp_path / "ev")
    await db.open()
    _open_dbs.append(db)
    cat_dir = tmp_path / "catalog"
    (cat_dir / "services").mkdir(parents=True, exist_ok=True)
    (cat_dir / "catalog.yaml").write_text("name: t\n", encoding="utf-8")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    return OperationContext(db=db, config=config, catalog=load_catalog(cat_dir), providers=ProviderRegistry(), sanitizer=sanitizer, principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)


@pytest.fixture(autouse=True)
async def _close_dbs() -> Any:
    """Always close databases, even when an assertion fails (aiosqlite's worker thread is non-daemon)."""
    yield
    while _open_dbs:
        await _open_dbs.pop().close()


async def evidence_texts(ctx: OperationContext) -> list[str]:
    rows = await ctx.db.evidence_for_request(ctx.request_id)
    return [ctx.db.evidence_bytes(r).decode("utf-8") for r in rows]


# ---------------------------------------------------------------- fake SDK client


class FakeVaults:
    def __init__(self, vaults: list[Any]):
        self._vaults = vaults

    async def list(self) -> list[Any]:
        return list(self._vaults)


class FakeItems:
    def __init__(self, items: dict[str, list[Any]], full: dict[str, Any]):
        self._items = items
        self._full = full
        self.get_calls: list[tuple[str, str]] = []

    async def list(self, vault_id: str, *filters: Any) -> list[Any]:
        if vault_id not in self._items:
            raise RuntimeError("vault not accessible")
        return list(self._items[vault_id])

    async def get(self, vault_id: str, item_id: str) -> Any:
        self.get_calls.append((vault_id, item_id))
        return self._full[item_id]


class FakeSecrets:
    def __init__(self, values: dict[str, str]):
        self._values = values
        self.calls: list[str] = []

    async def resolve(self, reference: str) -> str:
        self.calls.append(reference)
        if reference not in self._values:
            raise RuntimeError("no such secret reference")
        return self._values[reference]


class FakeClient:
    def __init__(self) -> None:
        t0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=utcnow().tzinfo)
        self.vaults = FakeVaults([
            SimpleNamespace(id="v1", title="Production", description="prod creds", vault_type=SimpleNamespace(value="userCreated"), active_item_count=2, content_version=7, attribute_version=1, created_at=t0, updated_at=t0),
            SimpleNamespace(id="v2", title="Staging", description="", vault_type=SimpleNamespace(value="userCreated"), active_item_count=0, content_version=1, attribute_version=1, created_at=t0, updated_at=t0),
        ])
        self.items = FakeItems({
            "v1": [
                SimpleNamespace(id="i1", title="db password", category=SimpleNamespace(value="Password"), vault_id="v1", websites=[SimpleNamespace(url="https://db.example.invalid")], tags=["prod", "db"], created_at=t0, updated_at=t0),
                SimpleNamespace(id="i2", title="api key", category=SimpleNamespace(value="ApiCredentials"), vault_id="v1", websites=[], tags=[], created_at=t0, updated_at=t0),
            ],
            "v2": [],
        }, full={"i1": SimpleNamespace(id="i1", fields=[SimpleNamespace(id="password", value=SECRET)])})
        self.secrets = FakeSecrets({"op://v1/i1/password": SECRET})


def op_config(vaults: list[str] | None = None) -> ServerConfig:
    return ServerConfig(
        credentials=[
            CredentialRef(id="op-sa", kind="onepassword_service_account", env_var="OP_TEST_TOKEN"),
            CredentialRef(id="db-pass", kind="onepassword_item", vault_id="v1", item_id="i1", field="password", via="op-sa"),
        ],
        providers=[ProviderConfig(id="op", kind="onepassword", credential="op-sa", vaults=vaults or [])],
    )


@pytest.fixture
def op_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OP_TEST_TOKEN", SA_TOKEN)


# ---------------------------------------------------------------- SDK adapter tests


async def test_discover_is_metadata_only(tmp_path: Path, op_env: None) -> None:
    cfg = op_config(vaults=["v1", "v2", "v-missing"])
    sanitizer = Sanitizer()
    resolver = CredentialResolver(cfg, sanitizer)
    fake = FakeClient()
    seen_auth: list[Any] = []

    async def factory(auth: Any) -> Any:
        seen_auth.append(auth)
        return fake

    adapter = OnePasswordAdapter(cfg.providers[0], cfg, resolver, client_factory=factory)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)

    assert seen_auth == [SA_TOKEN]  # service-account token from the resolver, not from config
    types = sorted(o.resource_type for o in report.observations)
    assert types == ["onepassword/item", "onepassword/item", "onepassword/vault", "onepassword/vault"]
    item = next(o for o in report.observations if o.resource_key == "op:v1:i1")
    assert item.identity == {"vault_id": "v1", "item_id": "i1", "title": "db password"}
    assert item.attributes["fields_available"] is False
    assert item.attributes["custodian_unknown"] is True
    assert "custodian" in item.attributes["custodian_note"]
    assert item.attributes["category"] == "Password" and item.attributes["tags"] == ["prod", "db"]
    assert item.attributes["created_at"] == "2026-01-02T03:04:05Z"
    assert {"kind": "member_of", "target": "op:v1"} in item.relationships
    assert fake.items.get_calls == []  # never fetched full items for inventory
    assert fake.secrets.calls == []
    # No field values anywhere in observations or stored evidence
    dumped = json.dumps([o.model_dump() for o in report.observations])
    assert SECRET not in dumped
    for o in report.observations:
        assert not ({"fields", "value", "password"} & set(o.attributes)) and not ({"fields", "value"} & set(o.identity))
    for text in await evidence_texts(ctx):
        assert SECRET not in text
        assert '"fields_available": false' in text
    assert report.completed_scopes == ["op/v1", "op/v2"]
    assert any(u["reason"] == "vault_not_visible_to_credential" and u["source"] == "op/v-missing" for u in report.unavailable)
    assert report.identity is not None and report.identity["visible_vault_count"] == 2
    assert SCOPED_VIEW_LIMITATION in report.notes


async def test_discover_requested_vault_outside_configured_scope_is_refused(tmp_path: Path, op_env: None) -> None:
    cfg = op_config(vaults=["v1"])
    sanitizer = Sanitizer()
    fake = FakeClient()

    async def factory(auth: Any) -> Any:
        return fake

    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer), client_factory=factory)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter.discover(ctx, DiscoveryScope(vaults=["v1", "v2"]), ctx.budget)
    # v2 is visible to the credential but outside the provider's configured allow-list, so it must be
    # refused rather than silently included because a caller asked for it.
    assert sorted(o.resource_key for o in report.observations if o.resource_type == "onepassword/vault") == ["op:v1"]
    refused = [u for u in report.unavailable if u["reason"] == "vault_outside_configured_scope"]
    assert refused and refused[0]["source"] == "op/v2"


async def test_discover_all_visible_vaults_when_unconfigured(tmp_path: Path, op_env: None) -> None:
    cfg = op_config()
    sanitizer = Sanitizer()
    fake = FakeClient()

    async def factory(auth: Any) -> Any:
        return fake

    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer), client_factory=factory)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
    assert sorted(o.resource_key for o in report.observations if o.resource_type == "onepassword/vault") == ["op:v1", "op:v2"]


def test_describe_states_scoped_view_and_no_fields() -> None:
    cfg = op_config()
    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()))
    d = adapter.describe()
    assert SCOPED_VIEW_LIMITATION in d.limitations
    assert any("personal/private/employee" in lim for lim in d.limitations)
    assert any("not organization-wide" in lim for lim in d.limitations)
    assert any("custodian" in lim for lim in d.limitations)
    assert d.credential_configured is False  # env var not set in this test


async def test_resolve_item_secret_via_resolver_and_sanitizer_scrubs(tmp_path: Path, op_env: None) -> None:
    cfg = op_config()
    sanitizer = Sanitizer()
    resolver = CredentialResolver(cfg, sanitizer)
    fake = FakeClient()

    async def factory(auth: Any) -> Any:
        return fake

    adapter = OnePasswordAdapter(cfg.providers[0], cfg, resolver, client_factory=factory)
    assert resolver._onepassword_resolver == adapter.resolve_item_secret
    cred = await resolver.resolve("db-pass")
    assert cred.secret == SECRET
    assert fake.secrets.calls == ["op://v1/i1/password"]
    assert SECRET not in repr(cred)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    eid = await ctx.store_evidence("op", "test", {"note": f"connection string uses {SECRET} inline"}, summary="x")
    row = await ctx.db.evidence(eid)
    assert row is not None
    text = ctx.db.evidence_bytes(row).decode("utf-8")
    assert SECRET not in text and "[REDACTED:known_secret]" in text


async def test_resolve_item_secret_failure_has_no_secret_detail(op_env: None) -> None:
    cfg = op_config()
    fake = FakeClient()

    async def factory(auth: Any) -> Any:
        return fake

    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), client_factory=factory)
    with pytest.raises(OpsError) as ei:
        await adapter.resolve_item_secret(CredentialRef(id="x", kind="onepassword_item", vault_id="v1", item_id="nope", via="op-sa"))
    assert ei.value.code == ErrorCode.AUTH_REQUIRED
    assert SECRET not in (ei.value.private_detail or "")


async def test_check_availability_paths(op_env: None) -> None:
    cfg = op_config()
    fake = FakeClient()

    async def ok(auth: Any) -> Any:
        return fake

    async def bad(auth: Any) -> Any:
        raise RuntimeError("invalid service account token " + SA_TOKEN)

    async def down(auth: Any) -> Any:
        raise ConnectionError("dns")

    a = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), client_factory=ok)
    av = await a.check_availability(live=True)
    assert av.available and av.checked_live and av.identity == {"auth": "onepassword_service_account", "visible_vault_count": 2, "scope": "granted vaults only (not organization-wide)"}
    av2 = await OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), client_factory=bad).check_availability(live=True)
    assert not av2.available and av2.reason == "auth_required"
    assert SA_TOKEN not in json.dumps(av2.model_dump())
    av3 = await OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), client_factory=down).check_availability(live=True)
    assert not av3.available and av3.reason == "provider_unavailable"
    assert (await a.check_availability()).reason == "configured_not_live_checked"


async def test_unconfigured_credential_reports_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OP_TEST_TOKEN", raising=False)
    cfg = op_config()
    a = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()))
    av = await a.check_availability(live=True)
    assert not av.available and av.reason == "credential_not_configured"


async def test_query_unsupported(tmp_path: Path, op_env: None) -> None:
    cfg = op_config()
    sanitizer = Sanitizer()
    a = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer))
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "onepassword_events"}, ctx.budget)
    assert ei.value.code == ErrorCode.UNSUPPORTED_OPERATION


async def test_desktop_auth_uses_sdk_desktop_auth(tmp_path: Path) -> None:
    cfg = ServerConfig(credentials=[CredentialRef(id="op-desk", kind="onepassword_desktop", profile="my.1password.com")], providers=[ProviderConfig(id="op", kind="onepassword", credential="op-desk")])
    seen: list[Any] = []

    async def factory(auth: Any) -> Any:
        seen.append(auth)
        return FakeClient()

    a = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()), client_factory=factory)
    av = await a.check_availability(live=True)
    assert av.available and av.identity is not None and av.identity["auth"] == "onepassword_desktop"
    assert type(seen[0]).__name__ == "DesktopAuth" and seen[0].account_name == "my.1password.com"


# ---------------------------------------------------------------- Events API adapter tests


def events_config(url: str = "https://events.1password.test") -> ServerConfig:
    return ServerConfig(credentials=[CredentialRef(id="op-events", kind="env", env_var="OP_EVENTS_TOKEN")], providers=[ProviderConfig(id="op-ev", kind="onepassword_events", credential="op-events", url=url)])


class EventsServer:
    """Fake Events API: introspection + cursor pagination for each kind."""

    def __init__(self, features: list[str], pages: dict[str, list[dict[str, Any]]]):
        self.features = features
        self.pages = pages
        self.requests: list[tuple[str, dict[str, Any] | None]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer evt-token-123456789"
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.url.path, body))
        if request.url.path == "/api/auth/introspect":
            return httpx.Response(200, json={"uuid": "tok-1", "issued_at": "2026-09-01T00:00:00Z", "features": self.features})
        kind = request.url.path.rsplit("/", 1)[-1]
        if kind not in self.features:
            return httpx.Response(403, json={"Error": {"Message": "feature not enabled"}})
        pages = self.pages[kind]
        if body and "cursor" in body:
            idx = int(body["cursor"].split("-")[-1])
        else:
            assert "limit" in body and "start_time" in body
            idx = 0
        page = pages[idx]
        return httpx.Response(200, json={"cursor": f"{kind}-cursor-{idx + 1}", "has_more": idx + 1 < len(pages), "items": page})


def events_adapter(server: EventsServer, cfg: ServerConfig, sanitizer: Sanitizer | None = None) -> OnePasswordEventsAdapter:
    http = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    return OnePasswordEventsAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer or Sanitizer()), http=http)


@pytest.fixture
def events_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OP_EVENTS_TOKEN", "evt-token-123456789")


SIGNIN_1 = {"uuid": "s1", "session_uuid": "sess-1", "timestamp": "2026-09-30T10:00:00Z", "category": "success", "type": "credentials_ok", "target_user": {"uuid": "u1", "name": "Alice", "email": "alice@example.invalid"}, "client": {"app_name": "1Password for Mac", "app_version": "81200000", "platform_name": "macOS", "ip_address": "203.0.113.9"}}
SIGNIN_2 = {"uuid": "s2", "session_uuid": "sess-2", "timestamp": "2026-09-30T10:05:00Z", "category": "credentials_failed", "type": "password_secret_bad", "target_user": {"uuid": "u2", "name": "Bob", "email": "bob@example.invalid"}, "client": {"app_name": "1Password Browser Extension", "app_version": "20250", "ip_address": "198.51.100.3"}}
AUDIT_1 = {"uuid": "a1", "timestamp": "2026-09-30T11:00:00Z", "actor_uuid": "u1", "actor_details": {"uuid": "u1", "name": "Alice", "email": "alice@example.invalid"}, "action": "grant", "object_type": "uva", "object_uuid": "vault-xyz", "aux_uuid": "u3", "session": {"uuid": "sess-1", "ip": "203.0.113.9"}}
USAGE_1 = {"uuid": "iu1", "timestamp": "2026-09-30T12:00:00Z", "used_version": 3, "vault_uuid": "vault-xyz", "item_uuid": "item-abc", "user": {"uuid": "u1", "name": "Alice", "email": "alice@example.invalid"}, "client": {"app_name": "1Password CLI", "app_version": "2.30", "ip_address": "203.0.113.9"}, "action": "reveal"}


async def test_events_introspection_records_features(events_env: None) -> None:
    cfg = events_config()
    server = EventsServer(["auditevents", "signinattempts"], {})
    a = events_adapter(server, cfg)
    av = await a.check_availability(live=True)
    assert av.available and av.checked_live
    assert av.identity == {"token_uuid": "tok-1", "issued_at": "2026-09-01T00:00:00Z", "features": ["auditevents", "signinattempts"]}
    assert server.requests == [("/api/auth/introspect", None)]


async def test_events_feature_gating_and_cursor_pagination(tmp_path: Path, events_env: None) -> None:
    cfg = events_config()
    sanitizer = Sanitizer()
    server = EventsServer(["auditevents", "signinattempts"], {"signinattempts": [[SIGNIN_1], [SIGNIN_2]], "auditevents": [[AUDIT_1]]})
    a = events_adapter(server, cfg, sanitizer)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "onepassword_events", "filters": {"kinds": ["signinattempts", "itemusages", "auditevents"]}, "time_range": {"start": "2026-09-30T00:00:00Z", "end": "2026-10-01T00:00:00Z"}, "limits": {"max_events": 100, "max_pages": 10}}, ctx.budget)

    # token lacks itemusages -> unavailable scope, not an error and not a silent empty result
    gaps = {u.source: u.reason for u in res.coverage.unavailable_scopes}
    assert gaps == {"op-ev/itemusages": "token_lacks_feature"}
    assert not any(p.endswith("/itemusages") for p, _ in server.requests)
    # two pages for signinattempts followed via has_more/cursor, one page for auditevents
    signin_reqs = [b for p, b in server.requests if p == "/api/v1/signinattempts"]
    assert signin_reqs[0] == {"limit": 100, "start_time": "2026-09-30T00:00:00Z", "end_time": "2026-10-01T00:00:00Z"}
    assert signin_reqs[1] == {"cursor": "signinattempts-cursor-1"}
    assert sorted(res.coverage.completed_scopes) == ["op-ev/auditevents", "op-ev/signinattempts"]
    assert res.coverage.pagination_complete and not res.coverage.truncated
    assert res.coverage.source_retention_known is False
    assert res.coverage.time_range_observed == {"first_event": "2026-09-30T10:00:00Z", "last_event": "2026-09-30T11:00:00Z"}
    assert json.loads(res.cursor or "{}") == {"signinattempts": "signinattempts-cursor-2", "auditevents": "auditevents-cursor-1"}
    assert len(res.raw_evidence_ids) == 3  # one raw page per request

    by_key = {e["event_key"]: e for e in res.events}
    s1 = by_key["op-events:signinattempts:s1"]
    assert s1["provider"] == "onepassword" and s1["category"] == "identity"
    assert s1["actor"] == "alice@example.invalid" and s1["action"] == "signinattempts:success" and s1["outcome"] == "success"
    assert s1["source_ip"] == "203.0.113.9" and s1["user_agent"] == "1Password for Mac 81200000"
    assert "ids_unresolved" not in s1["fields"]
    s2 = by_key["op-events:signinattempts:s2"]
    assert s2["outcome"] == "failure" and s2["action"] == "signinattempts:credentials_failed"
    a1 = by_key["op-events:auditevents:a1"]
    assert a1["actor"] == "alice@example.invalid" and a1["action"] == "auditevents:grant"
    assert a1["resource"] == "vault-xyz" and a1["resource_type"] == "uva"
    assert a1["fields"]["ids_unresolved"] is True and a1["fields"]["object_uuid"] == "vault-xyz"
    assert a1["source_ip"] == "203.0.113.9" and a1["session"] == "sess-1"
    for e in res.events:
        assert e["event_key"].startswith("op-events:") and e["collected_at"]


async def test_events_resume_from_cursor_and_item_usage_ids(tmp_path: Path, events_env: None) -> None:
    cfg = events_config()
    sanitizer = Sanitizer()
    server = EventsServer(["itemusages"], {"itemusages": [[], [USAGE_1]]})
    a = events_adapter(server, cfg, sanitizer)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "onepassword_events", "filters": {"kinds": ["itemusages"]}, "cursor": json.dumps({"itemusages": "itemusages-cursor-1"})}, ctx.budget)
    assert server.requests[1] == ("/api/v1/itemusages", {"cursor": "itemusages-cursor-1"})
    assert len(res.events) == 1
    ev = res.events[0]
    assert ev["resource"] == "item-abc" and ev["resource_type"] == "item"
    assert ev["fields"]["vault_uuid"] == "vault-xyz" and ev["fields"]["ids_unresolved"] is True
    assert ev["action"] == "itemusages:reveal" and ev["user_agent"] == "1Password CLI 2.30"
    assert json.loads(res.cursor or "{}") == {"itemusages": "itemusages-cursor-2"}
    texts = await evidence_texts(ctx)
    assert any('"ids_unresolved": true' in t and "item-abc" in t for t in texts)


async def test_events_max_pages_and_max_events_bound(tmp_path: Path, events_env: None) -> None:
    cfg = events_config()
    sanitizer = Sanitizer()
    server = EventsServer(["signinattempts"], {"signinattempts": [[SIGNIN_1], [SIGNIN_2], [SIGNIN_1]]})
    a = events_adapter(server, cfg, sanitizer)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "onepassword_events", "filters": {"kinds": ["signinattempts"]}, "limits": {"max_pages": 2, "max_events": 50}}, ctx.budget)
    assert len(res.events) == 2 and not res.coverage.pagination_complete
    assert any("max_pages" in g for g in res.coverage.collection_gaps)
    assert json.loads(res.cursor or "{}") == {"signinattempts": "signinattempts-cursor-2"}
    res2 = await events_adapter(server, cfg, sanitizer).query(ctx, {"query_type": "onepassword_events", "filters": {"kinds": ["signinattempts"]}, "limits": {"max_pages": 10, "max_events": 1}}, ctx.budget)
    assert len(res2.events) == 1 and res2.coverage.truncated and not res2.coverage.pagination_complete


async def test_events_bad_kind_and_bad_token(tmp_path: Path, events_env: None) -> None:
    cfg = events_config()
    sanitizer = Sanitizer()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = events_adapter(EventsServer(["auditevents"], {}), cfg, sanitizer)
    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "onepassword_events", "filters": {"kinds": ["vaultnames"]}}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT

    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"Error": {"Message": "unauthorized"}})

    b = OnePasswordEventsAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer), http=httpx.AsyncClient(transport=httpx.MockTransport(rejected)))
    av = await b.check_availability(live=True)
    assert not av.available and av.reason == "auth_required"
    res = await b.query(ctx, {"query_type": "onepassword_events"}, ctx.budget)
    assert res.events == [] and res.coverage.unavailable_scopes[0].reason == "auth_required"
