"""1Password Events Reporting adapter (audit events, sign-in attempts, item usages) over httpx.

Events Reporting uses a distinct bearer token whose capabilities (`features`) are introspected before
collection. The API does not expose vault or item *names*: it returns UUIDs, which the caller may join
to metadata collected by the `onepassword` adapter. Unresolved ids remain visible in each event's fields.

Cursor handling: this adapter persists nothing itself. It returns the last cursor per kind so the caller
can checkpoint *after* the page has been stored.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, ErrorCode, OpsError, UnavailableScope, iso, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    SupportedOperation,
)

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

DEFAULT_BASE_URL = "https://events.1password.com"
EVENT_KINDS = ("auditevents", "signinattempts", "itemusages")
MAX_PAGE_LIMIT = 1000
MAX_RATE_LIMIT_WAIT_SECONDS = 30.0
NAMES_NOT_EXPOSED_NOTE = "The Events API exposes vault/item/user UUIDs only (no names); join ids to onepassword metadata where available and treat unresolved ids as unresolved."


def normalize_onepassword_event(e: dict[str, Any], kind: str, source_id: str, evidence_id: str | None) -> dict[str, Any]:
    """Normalize one Events API record of `kind` into the NormalizedEvent dict shape."""
    user = e.get("user") or e.get("target_user") or e.get("actor_details") or {}
    actor = user.get("email") or user.get("uuid") or e.get("actor_uuid")
    client = e.get("client") or {}
    session = e.get("session") or {}
    detail = e.get("action") or e.get("category") or e.get("type") or e.get("object_type")
    item_uuid = e.get("item_uuid") or (e.get("object_uuid") if e.get("object_type") == "item" else None)
    vault_uuid = e.get("vault_uuid") or (e.get("object_uuid") if e.get("object_type") == "vault" else None)
    object_uuid = e.get("object_uuid")
    resource = item_uuid or vault_uuid or object_uuid
    resource_type = "item" if item_uuid else ("vault" if vault_uuid else (e.get("object_type") if object_uuid else None))
    ua = None
    if client.get("app_name") or client.get("app_version"):
        ua = " ".join(str(x) for x in (client.get("app_name"), client.get("app_version")) if x)
    outcome = None
    if kind == "signinattempts":
        outcome = "success" if e.get("category") == "success" else "failure"
    elif kind == "auditevents":
        outcome = "success"
    fields = {k: v for k, v in e.items() if k not in ("uuid", "timestamp", "user", "target_user", "actor_details", "client", "action", "category", "type")}
    fields["event_kind"] = kind
    fields["user_name"] = user.get("name")
    fields["user_uuid"] = user.get("uuid")
    fields["platform"] = {k: client.get(k) for k in ("platform_name", "platform_version", "os_name", "os_version") if client.get(k)} or None
    fields["session_uuid"] = e.get("session_uuid") or session.get("uuid")
    if item_uuid or vault_uuid or object_uuid:
        fields["ids_unresolved"] = True
        fields["ids_unresolved_note"] = NAMES_NOT_EXPOSED_NOTE
    return {
        "event_key": f"op-events:{kind}:{e.get('uuid')}", "provider": "onepassword", "source_id": source_id, "account": None, "region": None,
        "event_id": e.get("uuid"), "occurred_at": e.get("timestamp"), "collected_at": iso(utcnow()), "actor": actor, "actor_type": "onepassword_user" if actor else None, "session": fields["session_uuid"],
        "action": f"{kind}:{detail}", "resource": resource, "resource_type": resource_type, "source_ip": client.get("ip_address") or session.get("ip"), "user_agent": ua,
        "outcome": outcome, "category": "identity", "evidence_ref": evidence_id, "fields": fields,
    }


class _RateLimited(Exception):
    pass


class OnePasswordEventsAdapter:
    kind = "onepassword_events"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, http: httpx.AsyncClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._http = http
        self._owned_http = http is None
        self._features: list[str] | None = None
        self._token_meta: dict[str, Any] | None = None
        self.base_url = (config.url or DEFAULT_BASE_URL).rstrip("/")

    # ---------------------------------------------------------------- plumbing
    async def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.server.limits.http_timeout_seconds)
        return self._http

    async def close(self) -> None:
        if self._http is not None and self._owned_http:
            await self._http.aclose()

    async def _headers(self) -> dict[str, str]:
        if self.resolver is None or not self.config.credential:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"onepassword_events provider {self.provider_id} has no credential configured")
        cred = await self.resolver.resolve(self.config.credential)
        if not cred.secret:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"Events API token for {self.provider_id} is empty")
        return {"Authorization": f"Bearer {cred.secret}", "Content-Type": "application/json", "Accept": "application/json"}

    async def _request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> httpx.Response:
        """One request with a single bounded rate-limit wait. Raises _RateLimited when the wait would exceed the bound."""
        client = await self.http()
        headers = await self._headers()
        url = f"{self.base_url}{path}"
        for attempt in (0, 1):
            r = await client.request(method, url, headers=headers, json=json_body)
            if r.status_code != 429:
                return r
            wait = _retry_after_seconds(r)
            if attempt == 1 or wait is None or wait > MAX_RATE_LIMIT_WAIT_SECONDS:
                raise _RateLimited(f"rate limited; retry-after {wait}s exceeds bound {MAX_RATE_LIMIT_WAIT_SECONDS}s")
            await asyncio.sleep(wait)
        raise _RateLimited("rate limited")

    async def introspect(self) -> dict[str, Any]:
        """GET /api/auth/introspect -> {uuid, issued_at, features}. Cached for the adapter lifetime."""
        if self._token_meta is not None:
            return self._token_meta
        r = await self._request("GET", "/api/auth/introspect")
        if r.status_code == 401:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"Events API token for {self.provider_id} was rejected")
        if r.status_code != 200:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"Events API introspection returned {r.status_code}", private_detail=r.text[:300])
        body = r.json()
        features = [str(f) for f in (body.get("features") or [])]
        self._features = features
        self._token_meta = {"token_uuid": body.get("uuid"), "issued_at": body.get("issued_at"), "features": features}
        return self._token_meta

    # ---------------------------------------------------------------- description / availability
    def describe(self) -> AdapterDescription:
        return AdapterDescription(
            provider_id=self.provider_id, kind=self.kind, description=self.config.description,
            operations=[SupportedOperation(name="onepassword_events", effect=Effect.READ, description="Audit events, sign-in attempts and item usages from 1Password Events Reporting.", provider_side_filters=["kinds", "time_range", "cursor"], limitations=[NAMES_NOT_EXPOSED_NOTE, "Each event kind is a separate token feature; kinds the token lacks are reported as unavailable scopes."])],
            required_credentials=[c for c in [self.config.credential] if c],
            credential_configured=bool(self.resolver and self.resolver.configured(self.config.credential)),
            scope_constraints={"base_url": self.base_url, "kinds": list(EVENT_KINDS)},
            limitations=[NAMES_NOT_EXPOSED_NOTE, "Events Reporting token capabilities differ from the service-account token; introspection decides which kinds are collectable.", "Source retention is not reported by the API; history before the first collected event is unknown."],
        )

    async def check_availability(self, *, live: bool = False) -> Availability:
        if not (self.resolver and self.resolver.configured(self.config.credential)):
            return Availability(available=False, reason="credential_not_configured", detail=f"Events API token for {self.provider_id} is not resolvable")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        try:
            meta = await self.introspect()
        except OpsError as e:
            return Availability(available=False, reason=e.code.value, detail=e.message, checked_live=True)
        except _RateLimited as e:
            return Availability(available=False, reason="rate_limited", detail=str(e), checked_live=True)
        except httpx.HTTPError as e:
            return Availability(available=False, reason="provider_unavailable", detail=type(e).__name__, checked_live=True)
        return Availability(available=True, checked_live=True, identity=dict(meta))

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        return DiscoveryReport(provider_id=self.provider_id, notes=["onepassword_events is an evidence source, not an inventory; use the onepassword provider for vault/item metadata"])

    # ---------------------------------------------------------------- evidence queries
    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        if query.get("query_type") != "onepassword_events":
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"onepassword_events adapter does not support query_type {query.get('query_type')!r}")
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        max_events = max(1, int(limits.get("max_events", 500)))
        max_pages = max(1, min(int(limits.get("max_pages", 20)), budget.max_pages))
        tr = query.get("time_range") or {}
        kinds = list(filters.get("kinds") or EVENT_KINDS)
        bad = [k for k in kinds if k not in EVENT_KINDS]
        if bad:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"unknown 1Password event kinds {bad}; supported: {list(EVENT_KINDS)}")
        saved_cursors = _parse_cursor(query.get("cursor"), kinds)
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["identity"], time_range_requested={"start": tr.get("start"), "end": tr.get("end")}, source_retention_known=False, source_retention_note="1Password Events Reporting does not report retention; history before the first collected event is unknown.", filters_provider_side=["kinds", "time_range", "cursor"], pagination_complete=True)
        try:
            meta = await self.introspect()
        except OpsError as e:
            cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason=e.code.value, detail=e.message))
            cov.conclusion_scope = "Events API token could not be introspected; nothing collected."
            return EvidenceResult(coverage=cov, query_description={"kinds": kinds})
        except (_RateLimited, httpx.HTTPError) as e:
            cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="provider_unavailable", detail=type(e).__name__))
            return EvidenceResult(coverage=cov, query_description={"kinds": kinds})
        features = set(meta.get("features") or [])
        start = tr.get("start") or iso(utcnow() - timedelta(hours=24))
        end = tr.get("end")
        events: list[dict[str, Any]] = []
        eids: list[str] = []
        out_cursors: dict[str, str] = dict(saved_cursors)
        total = 0
        for kind in kinds:
            if kind not in features:
                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{kind}", reason="token_lacks_feature", detail=f"Events API token features: {sorted(features)}"))
                continue
            cursor = saved_cursors.get(kind)
            pages = 0
            complete = False
            while pages < max_pages:
                budget.check()
                ctx.check_cancel()
                remaining = max_events - total
                if remaining <= 0:
                    cov.truncated = True
                    break
                body: dict[str, Any] = {"cursor": cursor} if cursor else {"limit": min(remaining, MAX_PAGE_LIMIT), "start_time": start, **({"end_time": end} if end else {})}
                try:
                    r = await self._request("POST", f"/api/v1/{kind}", json_body=body)
                except _RateLimited as e:
                    cov.collection_gaps.append(f"{self.provider_id}/{kind}: rate limited beyond bounded wait ({e})")
                    break
                except httpx.HTTPError as e:
                    cov.collection_gaps.append(f"{self.provider_id}/{kind}: {type(e).__name__}")
                    break
                if r.status_code in (401, 403):
                    cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{kind}", reason="auth_required" if r.status_code == 401 else "token_lacks_feature", detail=f"HTTP {r.status_code}"))
                    break
                if r.status_code != 200:
                    cov.collection_gaps.append(f"{self.provider_id}/{kind}: HTTP {r.status_code}")
                    break
                page = r.json()
                items = list(page.get("items") or [])[:remaining]
                pages += 1
                eid = await ctx.store_evidence(self.provider_id, f"onepassword_{kind}", {"kind": kind, "request": {k: v for k, v in body.items() if k != "cursor"} | ({"cursor_used": True} if cursor else {}), "items": items, "has_more": page.get("has_more"), "ids_unresolved": True}, summary=f"{len(items)} {kind} (page {pages})")
                eids.append(eid)
                events.extend(normalize_onepassword_event(e, kind, self.provider_id, eid) for e in items)
                total += len(items)
                new_cursor = page.get("cursor")
                if new_cursor:
                    cursor = str(new_cursor)
                    out_cursors[kind] = cursor
                if not page.get("has_more"):
                    complete = True
                    break
            if complete:
                cov.completed_scopes.append(f"{self.provider_id}/{kind}")
            else:
                cov.pagination_complete = False
                if pages >= max_pages:
                    cov.collection_gaps.append(f"{self.provider_id}/{kind}: stopped at max_pages={max_pages} with has_more; resume from cursor")
        times = sorted(str(e["occurred_at"]) for e in events if e.get("occurred_at"))
        if times:
            cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        if cov.truncated:
            cov.pagination_complete = False
        cov.conclusion_scope = "Only the listed completed kinds within the observed window are covered; unavailable kinds and uncollected pages imply nothing."
        return EvidenceResult(items=events, events=events, coverage=cov, cursor=json.dumps(out_cursors, sort_keys=True) if out_cursors else None, raw_evidence_ids=eids, notes=[NAMES_NOT_EXPOSED_NOTE], query_description={"kinds": kinds, "start_time": start, "end_time": end, "resumed_from_cursor": sorted(saved_cursors)})


def _parse_cursor(raw: Any, kinds: list[str]) -> dict[str, str]:
    """Cursors are a JSON object mapping kind -> cursor. A bare string is accepted for a single-kind query."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if v}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items() if v}
        if len(kinds) == 1:
            return {kinds[0]: raw}
    raise OpsError(ErrorCode.INVALID_ARGUMENT, "onepassword_events cursor must be a JSON object mapping kind -> cursor")


def _retry_after_seconds(r: httpx.Response) -> float | None:
    ra = r.headers.get("retry-after")
    if ra:
        try:
            return max(0.0, float(ra))
        except ValueError:
            return None
    return None
