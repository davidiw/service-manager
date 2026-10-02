"""PagerDuty read adapter.

Lists services, escalation policies and on-call schedules (knowledge-holder leads) and reads bounded
recent incidents. Strictly read-only: every request is a GET; it never creates, acknowledges,
resolves or snoozes incidents and therefore never triggers a page. Integration keys are dropped
before any payload is stored or returned.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, UnavailableScope, iso, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    SupportedOperation,
)

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

DEFAULT_URL = "https://api.pagerduty.com"
PAGE_SIZE = 100
LIST_BOUND = 500
READ_ONLY = "read-only; does not trigger pages"
SECRET_KEYS = {"integration_key", "integration_keys", "routing_key", "vendor_key"}


def drop_integration_keys(value: Any) -> Any:
    """Recursively remove integration/routing keys. The sanitizer also scrubs secret-named fields;
    this is a belt-and-braces guarantee specific to PagerDuty payload shapes."""
    if isinstance(value, dict):
        return {k: drop_integration_keys(v) for k, v in value.items() if str(k).lower() not in SECRET_KEYS}
    if isinstance(value, list):
        return [drop_integration_keys(v) for v in value]
    return value


def _name(ref: dict[str, Any] | None) -> str | None:
    if not isinstance(ref, dict):
        return None
    return ref.get("name") or ref.get("summary")


class PagerDutyAdapter:
    kind = "pagerduty"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, http: httpx.AsyncClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._http = http
        self._owned_http = http is None
        self.base_url = (config.url or DEFAULT_URL).rstrip("/")

    async def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.server.limits.http_timeout_seconds)
        return self._http

    async def close(self) -> None:
        if self._http is not None and self._owned_http:
            await self._http.aclose()

    def credential_configured(self) -> bool:
        return bool(self.resolver and self.config.credential and self.resolver.configured(self.config.credential))

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=[
            SupportedOperation(name="discover", effect=Effect.READ, description="List services (with integration type/name only), escalation policies with their user/schedule targets, and on-call schedules.", limitations=[f"each listing bounded to {LIST_BOUND} entries", "integration keys are never read or stored"]),
            SupportedOperation(name="pagerduty_incidents", effect=Effect.READ, description="Bounded recent incidents (since/until, statuses, service_ids) normalized as incident events.", provider_side_filters=["time_range", "statuses", "service_ids", "limit"], limitations=["PagerDuty caps incident history listing; very old incidents may be unavailable"]),
        ], required_credentials=[c for c in [self.config.credential] if c], credential_configured=self.credential_configured(), scope_constraints={"url": self.base_url}, limitations=[READ_ONLY, "Only GET requests are issued; incident creation/acknowledge/resolve endpoints are never called."])

    async def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.pagerduty+json;version=2"}
        if self.credential_configured() and self.resolver is not None and self.config.credential:
            cred = await self.resolver.resolve(self.config.credential)
            if cred.secret:
                headers["Authorization"] = f"Token token={cred.secret}"
        return headers

    async def _get(self, path: str, params: list[tuple[str, Any]] | dict[str, Any] | None = None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """The only HTTP primitive in this adapter. GET only, by construction."""
        try:
            r = await (await self.http()).get(f"{self.base_url}{path}", params=params, headers=await self._headers())
        except httpx.HTTPError as e:
            return None, {"source": self.provider_id, "reason": "provider_unavailable", "detail": f"{type(e).__name__} on {path}"}
        if r.status_code in (401, 403):
            return None, {"source": self.provider_id, "reason": "permission_denied", "detail": f"HTTP {r.status_code} on {path}"}
        if r.status_code == 429:
            return None, {"source": self.provider_id, "reason": "rate_limited", "detail": f"HTTP 429 on {path}"}
        if r.status_code != 200:
            return None, {"source": self.provider_id, "reason": "provider_error", "detail": f"HTTP {r.status_code} on {path}"}
        try:
            body = r.json()
        except ValueError:
            return None, {"source": self.provider_id, "reason": "provider_error", "detail": f"non-JSON response on {path}"}
        if not isinstance(body, dict):
            return None, {"source": self.provider_id, "reason": "provider_error", "detail": f"unexpected response shape on {path}"}
        return drop_integration_keys(body), None

    async def _paginate(self, budget: Budget, path: str, key: str, bound: int, extra: list[tuple[str, Any]] | None = None) -> tuple[list[dict[str, Any]], bool, dict[str, Any] | None]:
        """Offset pagination via `more`. Returns (items, complete, gap)."""
        items: list[dict[str, Any]] = []
        offset = 0
        pages = 0
        while True:
            budget.check()
            limit = min(PAGE_SIZE, bound - len(items))
            if limit <= 0:
                return items, False, None
            params: list[tuple[str, Any]] = [("limit", limit), ("offset", offset), *(extra or [])]
            body, gap = await self._get(path, params)
            if gap:
                return items, False, gap
            assert body is not None
            page = [x for x in (body.get(key) or []) if isinstance(x, dict)]
            items.extend(page)
            pages += 1
            if not body.get("more") or not page:
                return items, True, None
            if len(items) >= bound or pages >= budget.max_pages:
                return items, False, None
            offset = int(body.get("offset", offset)) + len(page)

    async def check_availability(self, *, live: bool = False) -> Availability:
        if self.config.credential and not self.credential_configured():
            return Availability(available=False, reason="credential_missing", detail=f"credential {self.config.credential!r} is not resolvable")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        body, gap = await self._get("/abilities")
        if gap:
            return Availability(available=False, reason=gap["reason"], detail=gap.get("detail"), checked_live=True)
        return Availability(available=True, checked_live=True, identity={"url": self.base_url, "abilities": len((body or {}).get("abilities") or [])})

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"url": self.base_url})
        # services
        scope_key = f"{self.provider_id}/services"
        services, complete, gap = await self._paginate(budget, "/services", "services", LIST_BOUND, [("include[]", "integrations")])
        if gap:
            report.unavailable.append({**gap, "source": scope_key})
        projected_services = []
        for s in services:
            ep = s.get("escalation_policy") or {}
            projected_services.append({"id": s.get("id"), "name": s.get("name"), "status": s.get("status"), "description": s.get("description"), "html_url": s.get("html_url"), "escalation_policy": {"id": ep.get("id"), "name": _name(ep)}, "integrations": [{"type": i.get("type"), "name": _name(i)} for i in (s.get("integrations") or []) if isinstance(i, dict)], "teams": [_name(t) for t in (s.get("teams") or []) if isinstance(t, dict)], "created_at": s.get("created_at"), "last_incident_timestamp": s.get("last_incident_timestamp")})
        if services or not gap:
            eid = await ctx.store_evidence(self.provider_id, "pagerduty_services", {"services": projected_services, "complete": complete}, summary=f"{len(projected_services)} PagerDuty services")
            for s in projected_services:
                rels = [{"kind": "depends_on", "target": f"pagerduty:{self.provider_id}:escalation_policy:{s['escalation_policy']['id']}"}] if s["escalation_policy"].get("id") else []
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"pagerduty:{self.provider_id}:service:{s['id']}", resource_type="pagerduty/service", identity={"id": s["id"], "name": s["name"], "pagerduty_url": self.base_url}, attributes={k: v for k, v in s.items() if k not in ("id", "name")}, scope_key=scope_key, evidence_id=eid, relationships=rels))
            self._mark(report, scope_key, complete, "services")
        # escalation policies
        scope_key = f"{self.provider_id}/escalation_policies"
        policies, complete, gap = await self._paginate(budget, "/escalation_policies", "escalation_policies", LIST_BOUND)
        if gap:
            report.unavailable.append({**gap, "source": scope_key})
        projected_policies = []
        for p in policies:
            rules: list[dict[str, Any]] = []
            for r in p.get("escalation_rules") or []:
                if not isinstance(r, dict):
                    continue
                targets: list[dict[str, Any]] = [{"id": t.get("id"), "type": t.get("type"), "name": _name(t)} for t in (r.get("targets") or []) if isinstance(t, dict)]
                rules.append({"delay_minutes": r.get("escalation_delay_in_minutes"), "targets": targets})
            holders = sorted({str(t["name"]) for r in rules for t in r["targets"] if t.get("name")})
            projected_policies.append({"id": p.get("id"), "name": p.get("name"), "description": p.get("description"), "html_url": p.get("html_url"), "num_loops": p.get("num_loops"), "rules": rules, "knowledge_holders": holders, "services": [_name(s) for s in (p.get("services") or []) if isinstance(s, dict)], "teams": [_name(t) for t in (p.get("teams") or []) if isinstance(t, dict)]})
        if policies or not gap:
            eid = await ctx.store_evidence(self.provider_id, "pagerduty_escalation_policies", {"escalation_policies": projected_policies, "complete": complete}, summary=f"{len(projected_policies)} PagerDuty escalation policies")
            for p in projected_policies:
                rels = [{"kind": "depends_on", "target": f"pagerduty:{self.provider_id}:schedule:{t['id']}"} for r in p["rules"] for t in r["targets"] if t.get("type") in ("schedule_reference", "schedule") and t.get("id")]
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"pagerduty:{self.provider_id}:escalation_policy:{p['id']}", resource_type="pagerduty/escalation_policy", identity={"id": p["id"], "name": p["name"], "pagerduty_url": self.base_url}, attributes={k: v for k, v in p.items() if k not in ("id", "name")}, scope_key=scope_key, evidence_id=eid, relationships=rels))
            self._mark(report, scope_key, complete, "escalation policies")
        # schedules
        scope_key = f"{self.provider_id}/schedules"
        schedules, complete, gap = await self._paginate(budget, "/schedules", "schedules", LIST_BOUND)
        if gap:
            report.unavailable.append({**gap, "source": scope_key})
        projected_schedules = [{"id": s.get("id"), "name": s.get("name"), "description": s.get("description"), "time_zone": s.get("time_zone"), "html_url": s.get("html_url"), "users": [_name(u) for u in (s.get("users") or []) if isinstance(u, dict)], "escalation_policies": [_name(e) for e in (s.get("escalation_policies") or []) if isinstance(e, dict)], "teams": [_name(t) for t in (s.get("teams") or []) if isinstance(t, dict)]} for s in schedules]
        if schedules or not gap:
            eid = await ctx.store_evidence(self.provider_id, "pagerduty_schedules", {"schedules": projected_schedules, "complete": complete}, summary=f"{len(projected_schedules)} PagerDuty schedules")
            for s in projected_schedules:
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"pagerduty:{self.provider_id}:schedule:{s['id']}", resource_type="pagerduty/schedule", identity={"id": s["id"], "name": s["name"], "pagerduty_url": self.base_url}, attributes={k: v for k, v in s.items() if k not in ("id", "name")}, scope_key=scope_key, evidence_id=eid))
            self._mark(report, scope_key, complete, "schedules")
        return report

    @staticmethod
    def _mark(report: DiscoveryReport, scope_key: str, complete: bool, what: str) -> None:
        if complete:
            report.completed_scopes.append(scope_key)
        else:
            report.partial_scopes.append(scope_key)
            report.truncated = True
            report.notes.append(f"{what} listing stopped at the {LIST_BOUND} bound or page budget; more may exist")

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        if query.get("query_type") != "pagerduty_incidents":
            return EvidenceResult(coverage=Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=self.provider_id, reason="unsupported_query_type", detail=f"{query.get('query_type')!r}; supported: pagerduty_incidents")], conclusion_scope="Unsupported query; no evidence collected."))
        tr = query.get("time_range") or {}
        filters = query.get("filters") or {}
        scope = query.get("scope") or {}
        limits = query.get("limits") or {}
        max_events = max(1, min(int(limits.get("max_events", 500) or 500), budget.max_events))
        statuses = filters.get("statuses") or []
        if isinstance(statuses, str):
            statuses = [statuses]
        service_ids = scope.get("service_ids") or ([scope["service_id"]] if scope.get("service_id") else [])
        extra: list[tuple[str, Any]] = [("time_zone", "UTC"), ("sort_by", "created_at:desc")]
        if tr.get("start"):
            extra.append(("since", str(tr["start"])))
        if tr.get("end"):
            extra.append(("until", str(tr["end"])))
        extra.extend(("statuses[]", str(s)) for s in statuses)
        extra.extend(("service_ids[]", str(s)) for s in service_ids)
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["incident"], time_range_requested={"start": tr.get("start"), "end": tr.get("end")}, filters_provider_side=["time_range", *(["statuses"] if statuses else []), *(["service_ids"] if service_ids else []), "limit"], source_retention_known=False, source_retention_note="PagerDuty incident history availability depends on plan; not verified.")
        incidents, complete, gap = await self._paginate(budget, "/incidents", "incidents", max_events, extra)
        description = {"endpoint": "/incidents", "since": tr.get("start"), "until": tr.get("end"), "statuses": statuses, "service_ids": service_ids, "max_events": max_events, "stable_link": f"{self.base_url.replace('api.', '', 1)}/incidents" if "api." in self.base_url else None}
        if gap and not incidents:
            cov.unavailable_scopes.append(UnavailableScope(**gap))
            cov.conclusion_scope = "PagerDuty incident listing failed; no conclusion about incidents."
            return EvidenceResult(coverage=cov, query_description=description)
        if gap:
            cov.unavailable_scopes.append(UnavailableScope(**gap))
            cov.collection_gaps.append("incident pagination stopped early due to a provider error")
        items = []
        for inc in incidents:
            svc = inc.get("service") or {}
            assignees = [_name(a.get("assignee")) for a in (inc.get("assignments") or []) if isinstance(a, dict)]
            items.append({"id": inc.get("id"), "incident_number": inc.get("incident_number"), "title": inc.get("title"), "status": inc.get("status"), "urgency": inc.get("urgency"), "created_at": inc.get("created_at"), "service": {"id": svc.get("id"), "name": _name(svc)}, "assignments": [a for a in assignees if a], "last_status_change_at": inc.get("last_status_change_at"), "html_url": inc.get("html_url"), "escalation_policy": _name(inc.get("escalation_policy")), "last_status_change_by": _name(inc.get("last_status_change_by"))})
        eid = await ctx.store_evidence(self.provider_id, "pagerduty_incidents", {"incidents": items, "complete": complete}, summary=f"{len(items)} PagerDuty incidents")
        events = [self._normalize(i, eid) for i in items]
        cov.pagination_complete = complete
        cov.truncated = not complete
        cov.completed_scopes = [self.provider_id] if complete else []
        if not complete:
            cov.collection_gaps.append(f"incident listing bounded to {max_events}; older incidents in the window were not fetched")
        if events:
            times = sorted(e["occurred_at"] for e in events if e.get("occurred_at"))
            if times:
                cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        return EvidenceResult(items=items, events=events, coverage=cov, raw_evidence_ids=[eid], query_description=description)

    def _normalize(self, inc: dict[str, Any], evidence_id: str) -> dict[str, Any]:
        status = str(inc.get("status") or "unknown")
        occurred = inc.get("last_status_change_at") or inc.get("created_at")
        actor = (inc.get("assignments") or [None])[0] or "pagerduty"
        return {
            "event_key": f"pagerduty:{self.provider_id}:incident:{inc.get('id')}:{status}:{occurred}", "provider": "pagerduty", "source_id": self.provider_id, "account": None, "region": None,
            "event_id": inc.get("id"), "occurred_at": occurred, "collected_at": iso(utcnow()), "actor": actor, "actor_type": "pagerduty_user" if actor != "pagerduty" else "system", "session": None,
            "action": f"incident:{status}", "resource": inc["service"].get("name") or inc["service"].get("id"), "resource_type": "pagerduty_service", "source_ip": None, "user_agent": None,
            "outcome": status, "category": "incident", "evidence_ref": evidence_id,
            "fields": {"incident_number": inc.get("incident_number"), "title": inc.get("title"), "urgency": inc.get("urgency"), "created_at": inc.get("created_at"), "service_id": inc["service"].get("id"), "assignments": inc.get("assignments"), "html_url": inc.get("html_url"), "escalation_policy": inc.get("escalation_policy"), "last_status_change_by": inc.get("last_status_change_by")},
        }
