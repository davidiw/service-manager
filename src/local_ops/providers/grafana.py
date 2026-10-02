"""Grafana, Prometheus and Loki read adapters.

All three use existing HTTP endpoints and install nothing. Grafana proxies Loki/Prometheus queries
through its data-source proxy so one Grafana credential covers every data source the viewer can
see; the direct Prometheus/Loki adapters hit the native query_range endpoints. Every query is
bounded, every result carries coverage, and a `stable_link` lets a human reopen the same query.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

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

LOKI_HARD_LIMIT = 5000
DISCOVERY_BOUND = 200
TARGET_BOUND = 500
LABEL_BOUND = 500
NO_INSTALL = "uses existing endpoints; installs nothing"

# Grafana data-source fields that are safe to observe. Everything else (basicAuthPassword,
# secureJsonData, secureJsonFields, jsonData with embedded credentials) is dropped before it
# reaches an observation or stored evidence.
DATASOURCE_FIELDS = ("id", "uid", "name", "type", "url", "access", "isDefault", "readOnly", "basicAuth", "orgId", "database")


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=utcnow().tzinfo)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


def _time_window(query: dict[str, Any]) -> tuple[datetime, datetime]:
    tr = query.get("time_range") or {}
    end = _parse_time(tr.get("end")) or utcnow()
    start = _parse_time(tr.get("start")) or end - timedelta(hours=1)
    if start > end:
        start, end = end, start
    return start, end


def _ns(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1_000_000_000))


def _ms(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1000))


def _max_events(query: dict[str, Any], budget: Budget) -> int:
    limits = query.get("limits") or {}
    try:
        requested = int(limits.get("max_events", 500))
    except (TypeError, ValueError):
        requested = 500
    return max(1, min(requested, budget.max_events))


def _loki_entry_ts(raw: str) -> str | None:
    try:
        return iso(datetime.fromtimestamp(int(raw) / 1_000_000_000, tz=utcnow().tzinfo))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _prom_ts(raw: Any) -> str | None:
    try:
        return iso(datetime.fromtimestamp(float(raw), tz=utcnow().tzinfo))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def normalize_loki(data: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    """Flatten Loki streams into rows (newest first). Returns rows, a bounded copy of the raw
    response suitable for evidence, and the total entry count the server returned."""
    result = (data.get("data") or {}).get("result") or []
    rows: list[dict[str, Any]] = []
    total = 0
    for stream in result:
        labels = stream.get("stream") or stream.get("metric") or {}
        for entry in stream.get("values") or []:
            total += 1
            if not isinstance(entry, list | tuple) or len(entry) < 2:
                continue
            rows.append({"timestamp": _loki_entry_ts(str(entry[0])), "timestamp_ns": str(entry[0]), "line": str(entry[1]), "labels": dict(labels)})
    rows.sort(key=lambda r: r["timestamp_ns"], reverse=True)
    rows = rows[:limit]
    bounded_streams: list[dict[str, Any]] = []
    remaining = limit
    for stream in result:
        values = list(stream.get("values") or [])[:remaining]
        remaining -= len(values)
        bounded_streams.append({"stream": stream.get("stream") or stream.get("metric") or {}, "values": values})
        if remaining <= 0:
            break
    bounded = {"status": data.get("status"), "data": {"resultType": (data.get("data") or {}).get("resultType"), "result": bounded_streams}, "entries_total": total}
    return rows, bounded, total


def normalize_prometheus(data: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    """Flatten a matrix/vector/scalar response into rows. Returns rows, bounded raw copy, total samples."""
    payload = data.get("data") or {}
    result_type = payload.get("resultType")
    result = payload.get("result") or []
    rows: list[dict[str, Any]] = []
    total = 0
    if result_type == "scalar" or result_type == "string":
        total = 1
        if isinstance(result, list | tuple) and len(result) >= 2:
            rows.append({"metric": {}, "timestamp": _prom_ts(result[0]), "value": result[1]})
        bounded = {"status": data.get("status"), "data": {"resultType": result_type, "result": result}, "samples_total": total}
        return rows[:limit], bounded, total
    for series in result:
        metric = series.get("metric") or {}
        samples = series.get("values") if "values" in series else ([series.get("value")] if series.get("value") else [])
        for sample in samples or []:
            total += 1
            if not isinstance(sample, list | tuple) or len(sample) < 2:
                continue
            rows.append({"metric": dict(metric), "timestamp": _prom_ts(sample[0]), "value": sample[1]})
    rows = rows[:limit]
    bounded_series: list[dict[str, Any]] = []
    remaining = limit
    for series in result:
        samples = list(series.get("values") or ([series.get("value")] if series.get("value") else []))[:remaining]
        remaining -= len(samples)
        bounded_series.append({"metric": series.get("metric") or {}, "values": samples})
        if remaining <= 0:
            break
    bounded = {"status": data.get("status"), "data": {"resultType": result_type, "result": bounded_series}, "samples_total": total}
    return rows, bounded, total


class _HttpReadAdapter:
    """Shared plumbing: lazy httpx client, bearer/basic auth from the configured credential,
    bounded GETs that never raise on provider errors (they produce coverage gaps instead)."""

    kind: str = "http"
    availability_path: str = "/"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, http: httpx.AsyncClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._http = http
        self._owned_http = http is None
        self.base_url = (config.url or "").rstrip("/")

    async def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.server.limits.http_timeout_seconds)
        return self._http

    async def close(self) -> None:
        if self._http is not None and self._owned_http:
            await self._http.aclose()

    def credential_configured(self) -> bool:
        return bool(self.resolver and self.config.credential and self.resolver.configured(self.config.credential))

    async def _auth_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.credential_configured() and self.resolver is not None and self.config.credential:
            cred = await self.resolver.resolve(self.config.credential)
            if cred.secret and ":" in cred.secret:
                headers["Authorization"] = "Basic " + base64.b64encode(cred.secret.encode()).decode()
            elif cred.secret:
                headers["Authorization"] = f"Bearer {cred.secret}"
        return headers

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> tuple[dict[str, Any] | list[Any] | None, dict[str, Any] | None]:
        """GET `path` (absolute or relative to base_url). Returns (json, gap). Exactly one is set."""
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        try:
            r = await (await self.http()).get(url, params=params, headers=await self._auth_headers())
        except httpx.HTTPError as e:
            return None, {"source": self.provider_id, "reason": "provider_unavailable", "detail": f"{type(e).__name__} on {path}"}
        if r.status_code in (401, 403):
            return None, {"source": self.provider_id, "reason": "permission_denied", "detail": f"HTTP {r.status_code} on {path}"}
        if r.status_code == 404:
            return None, {"source": self.provider_id, "reason": "not_found", "detail": f"HTTP 404 on {path}"}
        if r.status_code != 200:
            return None, {"source": self.provider_id, "reason": "provider_error", "detail": f"HTTP {r.status_code} on {path}"}
        try:
            body = r.json()
        except ValueError:
            return None, {"source": self.provider_id, "reason": "provider_error", "detail": f"non-JSON response on {path}"}
        if isinstance(body, dict) and body.get("status") == "error":
            return None, {"source": self.provider_id, "reason": "query_error", "detail": f"{body.get('errorType') or 'error'}: {str(body.get('error'))[:200]}"}
        return body, None

    def _base_description(self, operations: list[SupportedOperation], limitations: list[str]) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=operations, required_credentials=[c for c in [self.config.credential] if c], credential_configured=self.credential_configured() or not self.config.credential, scope_constraints={"url": self.base_url}, limitations=[NO_INSTALL, "Read-only: discovery and bounded queries only; nothing is written to the provider.", *limitations])

    async def check_availability(self, *, live: bool = False) -> Availability:
        if not self.base_url:
            return Availability(available=False, reason="not_configured", detail="url is required")
        if self.config.credential and not self.credential_configured():
            return Availability(available=False, reason="credential_missing", detail=f"credential {self.config.credential!r} is not resolvable")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        try:
            r = await (await self.http()).get(f"{self.base_url}{self.availability_path}", headers=await self._auth_headers())
        except httpx.HTTPError as e:
            return Availability(available=False, reason="provider_unavailable", detail=type(e).__name__, checked_live=True)
        if r.status_code >= 400:
            return Availability(available=False, reason="provider_error", detail=f"HTTP {r.status_code} on {self.availability_path}", checked_live=True)
        return Availability(available=True, checked_live=True, identity={"url": self.base_url, "kind": self.kind})

    def _coverage(self, query: dict[str, Any], category: str) -> Coverage:
        start, end = _time_window(query)
        return Coverage(requested_sources=[self.provider_id], event_categories=[category], time_range_requested={"start": iso(start), "end": iso(end)}, filters_provider_side=["query", "time_range", "limit"], source_retention_known=False, source_retention_note="Retention is configured on the backend; it was not verified by this query.")

    async def _loki_range(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, path: str, stable_link: str, extra_description: dict[str, Any]) -> EvidenceResult:
        filters = query.get("filters") or {}
        expr = filters.get("query") or filters.get("expr") or (query.get("scope") or {}).get("query")
        cov = self._coverage(query, "logs")
        if not expr:
            cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="invalid_argument", detail="filters.query (LogQL) is required"))
            cov.conclusion_scope = "No query was run."
            return EvidenceResult(coverage=cov, query_description={"stable_link": stable_link, **extra_description})
        start, end = _time_window(query)
        max_events = _max_events(query, budget)
        limit = min(max_events, LOKI_HARD_LIMIT)
        params = {"query": str(expr), "start": _ns(start), "end": _ns(end), "limit": limit, "direction": "backward"}
        budget.check()
        body, gap = await self._get(path, params)
        description = {"query": str(expr), "start": iso(start), "end": iso(end), "limit": limit, "direction": "backward", "stable_link": stable_link, **extra_description}
        if gap or not isinstance(body, dict):
            cov.unavailable_scopes.append(UnavailableScope(**(gap or {"source": self.provider_id, "reason": "provider_error", "detail": "unexpected response shape"})))
            cov.conclusion_scope = "Loki query failed; no conclusion about log contents."
            return EvidenceResult(coverage=cov, query_description=description)
        rows, bounded, total = normalize_loki(body, max_events)
        eid = await ctx.store_evidence(self.provider_id, "loki_query_range", {"endpoint": path, "params": params, "response": bounded}, summary=f"{len(rows)} Loki entries for {str(expr)[:80]}")
        cov.truncated = total >= limit
        cov.completed_scopes = [self.provider_id]
        if rows:
            cov.time_range_observed = {"first_event": rows[-1]["timestamp"], "last_event": rows[0]["timestamp"]}
        notes = [f"Loki returned the requested limit ({limit}); older entries in the window were not fetched."] if cov.truncated else []
        return EvidenceResult(items=rows, coverage=cov, raw_evidence_ids=[eid], notes=notes, query_description=description)

    async def _prom_range(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, path: str, stable_link: str, extra_description: dict[str, Any]) -> EvidenceResult:
        filters = query.get("filters") or {}
        expr = filters.get("query") or filters.get("expr") or (query.get("scope") or {}).get("query")
        cov = self._coverage(query, "metrics")
        if not expr:
            cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="invalid_argument", detail="filters.query (PromQL) is required"))
            cov.conclusion_scope = "No query was run."
            return EvidenceResult(coverage=cov, query_description={"stable_link": stable_link, **extra_description})
        start, end = _time_window(query)
        step = str(filters.get("step") or "60s")
        max_events = _max_events(query, budget)
        params = {"query": str(expr), "start": start.timestamp(), "end": end.timestamp(), "step": step}
        budget.check()
        body, gap = await self._get(path, params)
        description = {"query": str(expr), "start": iso(start), "end": iso(end), "step": step, "stable_link": stable_link, **extra_description}
        if gap or not isinstance(body, dict):
            cov.unavailable_scopes.append(UnavailableScope(**(gap or {"source": self.provider_id, "reason": "provider_error", "detail": "unexpected response shape"})))
            cov.conclusion_scope = "Prometheus query failed; no conclusion about metric values."
            return EvidenceResult(coverage=cov, query_description=description)
        rows, bounded, total = normalize_prometheus(body, max_events)
        eid = await ctx.store_evidence(self.provider_id, "prometheus_query_range", {"endpoint": path, "params": params, "response": bounded}, summary=f"{len(rows)} samples for {str(expr)[:80]}")
        cov.truncated = total > max_events
        cov.completed_scopes = [self.provider_id]
        if rows:
            cov.time_range_observed = {"first_event": rows[0]["timestamp"], "last_event": rows[-1]["timestamp"]}
        notes = [f"{total} samples returned; only the first {max_events} are included (raise limits.max_events or widen step)."] if cov.truncated else []
        return EvidenceResult(items=rows, coverage=cov, raw_evidence_ids=[eid], notes=notes, query_description=description)

    def _unsupported(self, query: dict[str, Any], supported: list[str]) -> EvidenceResult:
        cov = Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=self.provider_id, reason="unsupported_query_type", detail=f"{query.get('query_type')!r}; supported: {', '.join(supported)}")], conclusion_scope="Unsupported query; no evidence collected.")
        return EvidenceResult(coverage=cov)


class GrafanaAdapter(_HttpReadAdapter):
    kind = "grafana"
    availability_path = "/api/health"

    def describe(self) -> AdapterDescription:
        return self._base_description([
            SupportedOperation(name="discover", effect=Effect.READ, description="List data sources, dashboards and provisioned alert rules visible to the configured credential.", limitations=[f"dashboards and alert rules are bounded to {DISCOVERY_BOUND} entries", "data-source secrets (basic auth passwords, secureJsonData) are never read"]),
            SupportedOperation(name="loki_logs", effect=Effect.READ, description="LogQL query_range proxied through Grafana to a Loki data source (scope.datasource_uid).", provider_side_filters=["query", "time_range", "limit"], limitations=[f"limit is min(max_events, {LOKI_HARD_LIMIT}); direction=backward"]),
            SupportedOperation(name="prometheus_metrics", effect=Effect.READ, description="PromQL query_range proxied through Grafana to a Prometheus data source (scope.datasource_uid).", provider_side_filters=["query", "time_range", "step"]),
        ], ["Only data sources the credential's Grafana user/service account can see are discovered."])

    def explore_link(self, datasource_uid: str, expr: str, start: datetime, end: datetime) -> str:
        pane = {"grafana": {"datasource": datasource_uid, "queries": [{"refId": "A", "expr": expr, "datasource": {"uid": datasource_uid}}], "range": {"from": _ms(start), "to": _ms(end)}}}
        return f"{self.base_url}/explore?" + urlencode({"schemaVersion": 1, "panes": json.dumps(pane, separators=(",", ":")), "orgId": 1})

    @staticmethod
    def _datasource_uid(query: dict[str, Any]) -> str | None:
        scope = query.get("scope") or {}
        filters = query.get("filters") or {}
        uid = scope.get("datasource_uid") or filters.get("datasource_uid") or scope.get("datasource") or filters.get("datasource")
        return str(uid) if uid else None

    @staticmethod
    def project_datasource(ds: dict[str, Any]) -> dict[str, Any]:
        return {k: ds.get(k) for k in DATASOURCE_FIELDS if k in ds}

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"url": self.base_url})
        budget.check()
        body, gap = await self._get("/api/datasources")
        ds_scope = f"{self.provider_id}/datasources"
        if gap or not isinstance(body, list):
            report.unavailable.append(gap or {"source": ds_scope, "reason": "provider_error", "detail": "unexpected /api/datasources response"})
        else:
            projected = [self.project_datasource(d) for d in body if isinstance(d, dict)]
            eid = await ctx.store_evidence(self.provider_id, "grafana_datasources", {"datasources": projected}, summary=f"{len(projected)} Grafana data sources (projected; no secrets read)")
            for d in projected:
                uid = str(d.get("uid") or d.get("id") or d.get("name"))
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"grafana:{self.provider_id}:datasource:{uid}", resource_type="grafana/datasource", identity={"uid": d.get("uid"), "id": d.get("id"), "name": d.get("name"), "grafana_url": self.base_url}, attributes={"type": d.get("type"), "url": d.get("url"), "access": d.get("access"), "is_default": bool(d.get("isDefault")), "read_only": bool(d.get("readOnly")), "basic_auth_enabled": bool(d.get("basicAuth")), "database": d.get("database")}, scope_key=ds_scope, evidence_id=eid))
            report.completed_scopes.append(ds_scope)
        budget.check()
        body, gap = await self._get("/api/search", {"type": "dash-db", "limit": DISCOVERY_BOUND})
        dash_scope = f"{self.provider_id}/dashboards"
        if gap or not isinstance(body, list):
            report.unavailable.append(gap or {"source": dash_scope, "reason": "provider_error", "detail": "unexpected /api/search response"})
        else:
            dashboards = [d for d in body if isinstance(d, dict)][:DISCOVERY_BOUND]
            eid = await ctx.store_evidence(self.provider_id, "grafana_dashboards", {"dashboards": dashboards}, summary=f"{len(dashboards)} Grafana dashboards")
            for d in dashboards:
                uid = str(d.get("uid") or d.get("id"))
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"grafana:{self.provider_id}:dashboard:{uid}", resource_type="grafana/dashboard", identity={"uid": d.get("uid"), "id": d.get("id"), "title": d.get("title"), "grafana_url": self.base_url}, attributes={"url": f"{self.base_url}{d.get('url')}" if d.get("url") else None, "folder": d.get("folderTitle"), "folder_uid": d.get("folderUid"), "tags": d.get("tags") or []}, scope_key=dash_scope, evidence_id=eid))
            if len(body) >= DISCOVERY_BOUND:
                report.partial_scopes.append(dash_scope)
                report.truncated = True
                report.notes.append(f"dashboard listing hit the {DISCOVERY_BOUND} bound; more dashboards may exist")
            else:
                report.completed_scopes.append(dash_scope)
        budget.check()
        body, gap = await self._get("/api/v1/provisioning/alert-rules")
        rule_scope = f"{self.provider_id}/alert_rules"
        if gap and gap.get("reason") == "not_found":
            report.notes.append("alert rule provisioning API not available on this Grafana (404); alert rules not enumerated")
        elif gap or not isinstance(body, list):
            report.unavailable.append(gap or {"source": rule_scope, "reason": "provider_error", "detail": "unexpected alert-rules response"})
        else:
            rules = [r for r in body if isinstance(r, dict)][:DISCOVERY_BOUND]
            projected_rules = []
            for r in rules:
                ds_uids = sorted({str(q.get("datasourceUid")) for q in (r.get("data") or []) if isinstance(q, dict) and q.get("datasourceUid")})
                projected_rules.append({"uid": r.get("uid"), "title": r.get("title"), "rule_group": r.get("ruleGroup"), "folder_uid": r.get("folderUID"), "datasource_uids": ds_uids, "labels": r.get("labels") or {}, "annotations": r.get("annotations") or {}, "for": r.get("for"), "no_data_state": r.get("noDataState"), "exec_err_state": r.get("execErrState"), "is_paused": r.get("isPaused")})
            eid = await ctx.store_evidence(self.provider_id, "grafana_alert_rules", {"alert_rules": projected_rules}, summary=f"{len(projected_rules)} Grafana alert rules")
            for r in projected_rules:
                uid = str(r["uid"] or r["title"])
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"grafana:{self.provider_id}:alert_rule:{uid}", resource_type="grafana/alert_rule", identity={"uid": r["uid"], "title": r["title"], "grafana_url": self.base_url}, attributes={k: v for k, v in r.items() if k not in ("uid", "title")}, scope_key=rule_scope, evidence_id=eid, relationships=[{"kind": "depends_on", "target": f"grafana:{self.provider_id}:datasource:{u}"} for u in r["datasource_uids"]]))
            if len(body) > DISCOVERY_BOUND:
                report.partial_scopes.append(rule_scope)
                report.truncated = True
                report.notes.append(f"alert rule listing bounded to {DISCOVERY_BOUND}; {len(body) - DISCOVERY_BOUND} more exist")
            else:
                report.completed_scopes.append(rule_scope)
        return report

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        qtype = query.get("query_type")
        if qtype not in ("loki_logs", "prometheus_metrics"):
            return self._unsupported(query, ["loki_logs", "prometheus_metrics"])
        uid = self._datasource_uid(query)
        if not uid:
            cov = Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=self.provider_id, reason="invalid_argument", detail="scope.datasource_uid is required (see grafana/datasource observations)")], conclusion_scope="No query was run.")
            return EvidenceResult(coverage=cov)
        filters = query.get("filters") or {}
        expr = str(filters.get("query") or filters.get("expr") or "")
        start, end = _time_window(query)
        link = self.explore_link(uid, expr, start, end)
        extra = {"datasource_uid": uid, "via": "grafana_datasource_proxy"}
        if qtype == "loki_logs":
            return await self._loki_range(ctx, query, budget, f"/api/datasources/proxy/uid/{quote(uid, safe='')}/loki/api/v1/query_range", link, extra)
        return await self._prom_range(ctx, query, budget, f"/api/datasources/proxy/uid/{quote(uid, safe='')}/api/v1/query_range", link, extra)


class PrometheusAdapter(_HttpReadAdapter):
    kind = "prometheus"
    availability_path = "/-/ready"

    def describe(self) -> AdapterDescription:
        return self._base_description([
            SupportedOperation(name="discover", effect=Effect.READ, description="List active scrape targets.", limitations=[f"targets bounded to {TARGET_BOUND}"]),
            SupportedOperation(name="prometheus_metrics", effect=Effect.READ, description="PromQL query_range against the native API.", provider_side_filters=["query", "time_range", "step"]),
        ], [])

    def graph_link(self, expr: str, start: datetime, end: datetime) -> str:
        return f"{self.base_url}/graph?" + urlencode({"g0.expr": expr, "g0.tab": 0, "g0.end_input": end.strftime("%Y-%m-%d %H:%M:%S"), "g0.range_input": f"{max(1, int((end - start).total_seconds() // 60))}m"})

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"url": self.base_url})
        scope_key = f"{self.provider_id}/targets"
        budget.check()
        body, gap = await self._get("/api/v1/targets", {"state": "active"})
        if gap or not isinstance(body, dict):
            report.unavailable.append(gap or {"source": scope_key, "reason": "provider_error", "detail": "unexpected /api/v1/targets response"})
            return report
        active = [t for t in ((body.get("data") or {}).get("activeTargets") or []) if isinstance(t, dict)]
        targets = [{"scrape_pool": t.get("scrapePool"), "scrape_url": t.get("scrapeUrl"), "labels": t.get("labels") or {}, "health": t.get("health"), "last_scrape": t.get("lastScrape"), "last_error": t.get("lastError")} for t in active[:TARGET_BOUND]]
        eid = await ctx.store_evidence(self.provider_id, "prometheus_targets", {"targets": targets, "total_active": len(active)}, summary=f"{len(targets)} active Prometheus targets")
        for t in targets:
            labels: dict[str, Any] = t["labels"] or {}
            key = f"prometheus:{self.provider_id}:target:{t['scrape_pool']}:{labels.get('instance') or t['scrape_url']}"
            report.observations.append(Observation(provider_id=self.provider_id, resource_key=key, resource_type="prometheus/target", identity={"job": labels.get("job"), "instance": labels.get("instance"), "scrape_pool": t["scrape_pool"], "prometheus_url": self.base_url}, attributes={"scrape_url": t["scrape_url"], "labels": labels, "health": t["health"], "last_scrape": t["last_scrape"], "last_error": t["last_error"]}, scope_key=scope_key, evidence_id=eid))
        if len(active) > TARGET_BOUND:
            report.partial_scopes.append(scope_key)
            report.truncated = True
            report.notes.append(f"target listing bounded to {TARGET_BOUND}; {len(active) - TARGET_BOUND} more active targets exist")
        else:
            report.completed_scopes.append(scope_key)
        return report

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        if query.get("query_type") != "prometheus_metrics":
            return self._unsupported(query, ["prometheus_metrics"])
        filters = query.get("filters") or {}
        expr = str(filters.get("query") or filters.get("expr") or "")
        start, end = _time_window(query)
        return await self._prom_range(ctx, query, budget, "/api/v1/query_range", self.graph_link(expr, start, end), {"via": "prometheus_api"})


class LokiAdapter(_HttpReadAdapter):
    kind = "loki"
    availability_path = "/ready"

    def describe(self) -> AdapterDescription:
        return self._base_description([
            SupportedOperation(name="discover", effect=Effect.READ, description="Record the Loki instance and its label names.", limitations=[f"label names bounded to {LABEL_BOUND}"]),
            SupportedOperation(name="loki_logs", effect=Effect.READ, description="LogQL query_range against the native API.", provider_side_filters=["query", "time_range", "limit"], limitations=[f"limit is min(max_events, {LOKI_HARD_LIMIT}); direction=backward"]),
        ], ["Loki has no UI of its own; stable_link is the API query URL (open it in Grafana Explore for a rendered view)."])

    def api_link(self, expr: str, start: datetime, end: datetime, limit: int) -> str:
        return f"{self.base_url}/loki/api/v1/query_range?" + urlencode({"query": expr, "start": _ns(start), "end": _ns(end), "limit": limit, "direction": "backward"})

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"url": self.base_url})
        scope_key = f"{self.provider_id}/labels"
        budget.check()
        body, gap = await self._get("/loki/api/v1/labels")
        if gap or not isinstance(body, dict):
            report.unavailable.append(gap or {"source": scope_key, "reason": "provider_error", "detail": "unexpected /loki/api/v1/labels response"})
            return report
        labels = [str(x) for x in (body.get("data") or [])]
        bounded = labels[:LABEL_BOUND]
        eid = await ctx.store_evidence(self.provider_id, "loki_labels", {"labels": bounded, "total": len(labels)}, summary=f"{len(labels)} Loki label names")
        report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"loki:{self.provider_id}:instance", resource_type="loki/instance", identity={"url": self.base_url}, attributes={"labels": bounded, "label_count": len(labels), "labels_truncated": len(labels) > LABEL_BOUND}, scope_key=scope_key, evidence_id=eid))
        report.completed_scopes.append(scope_key)
        if len(labels) > LABEL_BOUND:
            report.notes.append(f"label names bounded to {LABEL_BOUND} of {len(labels)}")
        return report

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        if query.get("query_type") != "loki_logs":
            return self._unsupported(query, ["loki_logs"])
        filters = query.get("filters") or {}
        expr = str(filters.get("query") or filters.get("expr") or "")
        start, end = _time_window(query)
        limit = min(_max_events(query, budget), LOKI_HARD_LIMIT)
        return await self._loki_range(ctx, query, budget, "/loki/api/v1/query_range", self.api_link(expr, start, end, limit), {"via": "loki_api"})
