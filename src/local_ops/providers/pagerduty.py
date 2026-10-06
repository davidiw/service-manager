"""PagerDuty discovery, evidence, and controlled configuration adapter.

Discovery and evidence use GET requests. Typed configuration writes require the reviewed executor;
incident reassignment can notify the new responder. Incident creation, acknowledgement, resolution,
and snoozing remain unsupported. Integration keys are dropped before payloads are stored or returned.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, ErrorCode, OpsError, UnavailableScope, iso, utcnow
from local_ops.pagerduty_contracts import PagerDutyTarget
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
READ_ONLY = "Discovery and evidence are read-only; reviewed incident reassignment may notify responders."
SECRET_KEYS = {"integration_key", "integration_keys", "routing_key", "vendor_key"}
CONFIGURATION_TYPES = {"schedule", "escalation_policy", "service", "user", "incident"}
CONFIGURATION_PATHS = {"schedule": ("/schedules", "schedules", "schedule"), "escalation_policy": ("/escalation_policies", "escalation_policies", "escalation_policy"), "service": ("/services", "services", "service"), "user": ("/users", "users", "user"), "incident": ("/incidents", "incidents", "incident")}
_PRIVATE_LIST_PATHS = {"schedule_v3": ("/v3/schedules", "schedules")}
EXECUTION_HOSTS = {"api.pagerduty.com", "api.eu.pagerduty.com"}


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


def _configuration_error(detail: str) -> OpsError:
    return OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"PagerDuty configuration response is invalid: {detail}")


def _ref(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise _configuration_error("reference")
    return {k: value[k] for k in ("id", "type", "name", "summary", "html_url") if isinstance(value.get(k), str)}


def _refs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise _configuration_error("reference list")
    return [_ref(v) for v in value]


def _schedule_layer_users(value: Any) -> list[dict[str, Any]]:
    """Normalize PagerDuty v2's layer wrapper to the direct references used in plans."""
    if not isinstance(value, list):
        raise _configuration_error("schedule layer users")
    users: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) - {"user"} or not isinstance(entry.get("user"), dict):
            raise _configuration_error("schedule layer user")
        users.append(_ref(entry["user"]))
    return users


def _project_configuration(resource_type: str, value: Any) -> dict[str, Any]:
    """Return the small, typed configuration representation used by planning and evidence.

    Unknown provider fields are deliberately not copied: PagerDuty responses can contain integration
    data and contact methods, neither of which belongs in an operation plan or evidence artifact.
    """
    if resource_type not in CONFIGURATION_TYPES | {"schedule_v3"} or not isinstance(value, dict):
        raise _configuration_error("resource")
    if resource_type == "schedule_v3" and isinstance(value.get("summary"), str) and not isinstance(value.get("name"), str):
        value = {**value, "name": value["summary"]}
    if resource_type == "incident" and isinstance(value.get("title"), str) and not isinstance(value.get("name"), str):
        value = {**value, "name": value["title"]}
    if not isinstance(value.get("id"), str) or not isinstance(value.get("name"), str):
        raise _configuration_error("id or name")
    out = {k: value[k] for k in ("id", "name", "html_url") if isinstance(value.get(k), str)}
    if resource_type == "schedule_v3":
        if isinstance(value.get("type"), str):
            out["type"] = value["type"]
        return out
    if resource_type == "user":
        if isinstance(value.get("role"), str):
            out["role"] = value["role"]
        return drop_integration_keys(out)
    if resource_type == "incident":
        title = value.get("title")
        if not isinstance(title, str):
            raise _configuration_error("incident title")
        out["name"] = title
        if isinstance(value.get("status"), str):
            out["status"] = value["status"]
        for key in ("service", "escalation_policy"):
            if value.get(key) is not None:
                out[key] = _ref(value[key])
        assignments = value.get("assignments", [])
        if not isinstance(assignments, list):
            raise _configuration_error("incident assignments")
        out["assignments"] = [_ref(item["assignee"]) for item in assignments if isinstance(item, dict) and isinstance(item.get("assignee"), dict)]
        if len(out["assignments"]) != len(assignments):
            raise _configuration_error("incident assignment")
        return out
    if resource_type == "service":
        if isinstance(value.get("status"), str):
            out["status"] = value["status"]
        if value.get("escalation_policy") is not None:
            out["escalation_policy"] = _ref(value["escalation_policy"])
        for key in ("auto_resolve_timeout", "acknowledgement_timeout", "alert_creation", "incident_urgency_rule", "support_hours"):
            if key in value and isinstance(value[key], (str, int, bool, dict, list, type(None))):
                out[key] = drop_integration_keys(value[key])
        return drop_integration_keys(out)
    if resource_type == "escalation_policy":
        if not isinstance(value.get("num_loops"), int) or not isinstance(value.get("escalation_rules"), list):
            raise _configuration_error("escalation policy rules")
        out["num_loops"] = value["num_loops"]
        out["rules"] = []
        for rule in value["escalation_rules"]:
            if not isinstance(rule, dict) or not isinstance(rule.get("escalation_delay_in_minutes"), int):
                raise _configuration_error("escalation rule")
            projected = {"delay_minutes": rule["escalation_delay_in_minutes"], "targets": _refs(rule.get("targets"))}
            strategy = rule.get("escalation_rule_assignment_strategy")
            if strategy is not None:
                if not isinstance(strategy, dict) or not isinstance(strategy.get("type"), str):
                    raise _configuration_error("escalation rule assignment strategy")
                projected["assignment_strategy"] = {"type": strategy["type"]}
            out["rules"].append(projected)
        for key in ("description", "on_call_handoff_notifications"):
            if key in value and isinstance(value[key], (str, bool, list, dict, type(None))):
                out[key] = drop_integration_keys(value[key])
        if "teams" in value:
            out["teams"] = _refs(value["teams"])
        return drop_integration_keys(out)
    # schedule
    if not isinstance(value.get("time_zone"), str):
        raise _configuration_error("schedule time_zone")
    out["time_zone"] = value["time_zone"]
    if "description" in value and isinstance(value["description"], (str, type(None))):
        out["description"] = value["description"]
    layers = value.get("schedule_layers", [])
    if not isinstance(layers, list):
        raise _configuration_error("schedule layers")
    out["schedule_layers"] = []
    for layer in layers:
        if not isinstance(layer, dict):
            raise _configuration_error("schedule layer")
        projected = {k: layer[k] for k in ("id", "name", "start", "end", "rotation_virtual_start", "rotation_turn_length_seconds", "time_zone") if k in layer and isinstance(layer[k], (str, int, type(None)))}
        if "users" in layer:
            projected["users"] = _schedule_layer_users(layer["users"])
        if "restrictions" in layer:
            if not isinstance(layer["restrictions"], list) or not all(isinstance(x, dict) for x in layer["restrictions"]):
                raise _configuration_error("schedule restrictions")
            projected["restrictions"] = [{k: x[k] for k in ("type", "start_time_of_day", "start_day_of_week", "duration_seconds") if isinstance(x.get(k), (str, int))} for x in layer["restrictions"]]
        out["schedule_layers"].append(projected)
    for key in ("overrides_subschedule", "final_schedule"):
        if key in value:
            sub = value[key]
            if not isinstance(sub, dict):
                raise _configuration_error(key)
            entries = sub.get("rendered_schedule_entries", [])
            if not isinstance(entries, list):
                raise _configuration_error(f"{key} rendered entries")
            out[key] = {"rendered_schedule_entries": [{k: e[k] for k in ("start", "end") if isinstance(e.get(k), str)} | ({"user": _ref(e["user"])} if e.get("user") is not None else {}) for e in entries if isinstance(e, dict)]}
            if len(out[key]["rendered_schedule_entries"]) != len(entries):
                raise _configuration_error(f"{key} entry")
    return drop_integration_keys(out)


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
            SupportedOperation(name="pagerduty_configuration", effect=Effect.READ, description="Read one exact projected PagerDuty configuration resource.", provider_side_filters=["resource_type", "resource_id", "schedule time_range"], limitations=["schedule evidence reads the legacy REST resource only"]),
            SupportedOperation(name="pagerduty_users", effect=Effect.READ, description="Complete bounded PagerDuty user-directory projection without email or contact methods.", limitations=[f"fails rather than returning a partial list; bound {LIST_BOUND}"]),
        ], required_credentials=[c for c in [self.config.credential, self.config.execution_credential] if c], credential_configured=self.credential_configured(), scope_constraints={"url": self.base_url}, limitations=[READ_ONLY, "Discovery and incident evidence use GET only; configuration writes are available only through the reviewed executor.", "incident creation/acknowledge/resolve endpoints are never called."])

    async def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.pagerduty+json;version=2"}
        if self.credential_configured() and self.resolver is not None and self.config.credential:
            cred = await self.resolver.resolve(self.config.credential)
            if cred.secret:
                headers["Authorization"] = f"Token token={cred.secret}"
        return headers

    def _validate_execution_endpoint(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "https" or parsed.hostname not in EXECUTION_HOSTS or parsed.username is not None or parsed.password is not None or parsed.port is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "PagerDuty execution requires the configured US or EU PagerDuty API endpoint")

    async def _configuration_headers(self, *, execution: bool) -> dict[str, str]:
        headers = {"Accept": "application/vnd.pagerduty+json;version=2", "Content-Type": "application/json"}
        credential_id = self.config.execution_credential if execution else self.config.credential
        if execution:
            self._validate_execution_endpoint()
            if not credential_id:
                raise OpsError(ErrorCode.AUTH_REQUIRED, "PagerDuty execution credential is not configured")
        if credential_id and self.resolver is not None:
            credential = await self.resolver.resolve(credential_id)
            if credential.secret:
                headers["Authorization"] = f"Token token={credential.secret}"
            elif execution:
                raise OpsError(ErrorCode.AUTH_REQUIRED, "PagerDuty execution credential did not resolve to a token")
        elif execution:
            raise OpsError(ErrorCode.AUTH_REQUIRED, "PagerDuty execution credential is not resolvable")
        return headers

    @staticmethod
    def _configuration_path(resource_type: str, resource_id: str | None = None) -> tuple[str, str, str]:
        if resource_type not in CONFIGURATION_PATHS:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported PagerDuty configuration resource type")
        if resource_id is not None and not re.fullmatch(r"[A-Za-z0-9]{1,128}", resource_id, flags=re.ASCII):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "invalid PagerDuty configuration resource id")
        base, list_key, wrapper = CONFIGURATION_PATHS[resource_type]
        return (f"{base}/{resource_id}" if resource_id else base), list_key, wrapper

    async def _configuration_request(self, method: str, resource_type: str, resource_id: str | None, *, execution: bool, params: dict[str, Any] | None = None, payload: dict[str, Any] | None = None, allow_absent: bool = False, private_headers: dict[str, str] | None = None, dispatch_guard: Callable[[], Awaitable[None]] | None = None) -> dict[str, Any] | None:
        path, _, wrapper = self._configuration_path(resource_type, resource_id)
        try:
            headers = await self._configuration_headers(execution=execution)
            headers.update(private_headers or {})
            client = await self.http()
            if method != "GET" and dispatch_guard is not None:
                await dispatch_guard()
            response = await client.request(method, f"{self.base_url}{path}", params=params, json=payload, headers=headers, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"PagerDuty configuration request failed ({type(exc).__name__})") from None
        if response.status_code == 404 and allow_absent and method == "GET":
            return None
        if response.status_code == 204 and method == "DELETE":
            return None
        if response.status_code < 200 or response.status_code >= 300:
            code = ErrorCode.AUTH_REQUIRED if response.status_code in (401, 403) else ErrorCode.PROVIDER_UNAVAILABLE
            raise OpsError(code, f"PagerDuty configuration request failed (HTTP {response.status_code})", data={"http_status": response.status_code})
        try:
            body = response.json()
        except ValueError:
            raise _configuration_error("non-JSON response") from None
        if not isinstance(body, dict) or not isinstance(body.get(wrapper), dict):
            raise _configuration_error("resource wrapper")
        return _project_configuration(resource_type, body[wrapper])

    async def configuration_get(self, resource_type: str, resource_id: str, budget: Budget, *, execution: bool = False, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Read one typed configuration resource; a 404 alone means it is absent."""
        budget.check()
        if params is not None and not isinstance(params, dict):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty configuration parameters must be a mapping")
        if params:
            allowed_params = {"since", "until", "overflow", "time_zone"} if resource_type == "schedule" else set()
            if set(params) - allowed_params or not all(isinstance(v, (str, bool)) for v in params.values()):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported PagerDuty configuration query parameters")
        return await self._configuration_request("GET", resource_type, resource_id, execution=execution, params=params, allow_absent=True)

    async def configuration_list(self, resource_type: str, budget: Budget, *, execution: bool = False) -> list[dict[str, Any]]:
        """List all pages of one legacy REST resource or fail; partial lists never authorize a plan."""
        if resource_type in _PRIVATE_LIST_PATHS:
            path, list_key = _PRIVATE_LIST_PATHS[resource_type]
        else:
            path, list_key, _ = self._configuration_path(resource_type)
        items: list[dict[str, Any]] = []
        offset = 0
        pages = 0
        seen_ids: set[str] = set()
        while True:
            budget.check()
            if len(items) >= LIST_BOUND or pages >= budget.max_pages:
                raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "PagerDuty configuration list exceeded its safe bound")
            requested_limit = min(PAGE_SIZE, LIST_BOUND - len(items))
            try:
                response = await (await self.http()).get(f"{self.base_url}{path}", params={"limit": requested_limit, "offset": offset}, headers=await self._configuration_headers(execution=execution), follow_redirects=False)
            except httpx.HTTPError as exc:
                raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"PagerDuty configuration list failed ({type(exc).__name__})") from None
            if response.status_code < 200 or response.status_code >= 300:
                code = ErrorCode.AUTH_REQUIRED if response.status_code in (401, 403) else ErrorCode.PROVIDER_UNAVAILABLE
                raise OpsError(code, f"PagerDuty configuration list failed (HTTP {response.status_code})", data={"http_status": response.status_code})
            try:
                body = response.json()
            except ValueError:
                raise _configuration_error("non-JSON list response") from None
            rows = body.get(list_key) if isinstance(body, dict) else None
            more = body.get("more") if isinstance(body, dict) else None
            response_offset = body.get("offset") if isinstance(body, dict) else None
            if not isinstance(rows, list) or len(rows) > requested_limit or not all(isinstance(row, dict) for row in rows) or not isinstance(more, bool) or not isinstance(response_offset, int) or response_offset != offset:
                raise _configuration_error("list wrapper")
            projected = [_project_configuration(resource_type, row) for row in rows]
            ids = [row["id"] for row in projected]
            if len(set(ids)) != len(ids) or seen_ids.intersection(ids):
                raise _configuration_error("duplicate list resource")
            seen_ids.update(ids)
            items.extend(projected)
            pages += 1
            if not more:
                return items
            if not rows:
                raise _configuration_error("empty continued page")
            offset += len(rows)

    async def _incident_actor_from(self, actor_user_id: str, account_domain: str) -> str:
        try:
            PagerDutyTarget(resource_type="service", account_domain=account_domain, id="AAAAAAA", name="account")
        except ValueError:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "invalid PagerDuty account domain") from None
        # This private lookup is deliberately separate from public user projections, which exclude email.
        path, _, _ = self._configuration_path("user", actor_user_id)
        response = await (await self.http()).get(f"{self.base_url}{path}", headers=await self._configuration_headers(execution=True), follow_redirects=False)
        if response.status_code < 200 or response.status_code >= 300:
            raise OpsError(ErrorCode.AUTH_REQUIRED if response.status_code in (401, 403) else ErrorCode.PROVIDER_UNAVAILABLE, f"PagerDuty actor lookup failed (HTTP {response.status_code})", data={"http_status": response.status_code})
        try:
            raw_body = response.json()
        except ValueError:
            raise _configuration_error("actor response") from None
        raw = raw_body.get("user") if isinstance(raw_body, dict) else None
        if not isinstance(raw, dict) or raw.get("id") != actor_user_id or not isinstance(raw.get("email"), str) or not isinstance(raw.get("html_url"), str):
            raise _configuration_error("actor identity")
        if urlsplit(raw["html_url"]).hostname != account_domain or not re.fullmatch(r"[^\s@\r\n]+@[^\s@\r\n]+", raw["email"]):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "PagerDuty actor does not match the approved account")
        return raw["email"]

    async def configuration_write(self, method: str, resource_type: str, resource_id: str | None, payload: dict[str, Any] | None, *, actor_user_id: str | None = None, account_domain: str | None = None, dispatch_guard: Callable[[], Awaitable[None]] | None = None) -> dict[str, Any] | None:
        """Dispatch only the reviewed PagerDuty configuration operations using the execution key."""
        allowed = {("POST", "schedule", None), ("POST", "escalation_policy", None), ("PUT", "escalation_policy", "id"), ("PUT", "service", "id"), ("PUT", "incident", "id"), ("DELETE", "schedule", "id")}
        marker = "id" if resource_id else None
        if (method, resource_type, marker) not in allowed:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "unsupported PagerDuty configuration write")
        if resource_type != "incident" and (actor_user_id is not None or account_domain is not None):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty actor is only valid for incident reassignment")
        if method == "DELETE":
            if payload is not None:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty schedule deletion does not accept a payload")
        elif not isinstance(payload, dict):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty configuration write requires a typed payload")
        if resource_type == "incident":
            if not isinstance(actor_user_id, str) or not isinstance(account_domain, str) or not isinstance(payload, dict) or set(payload) != {"incident"} or not isinstance(payload.get("incident"), dict):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty incident reassignment requires approved actor, account, and typed payload")
            incident = payload["incident"]
            if set(incident) != {"type", "escalation_policy"} or incident.get("type") != "incident_reference" or not isinstance(incident.get("escalation_policy"), dict) or set(incident["escalation_policy"]) != {"id", "type"} or incident["escalation_policy"].get("type") != "escalation_policy_reference" or not re.fullmatch(r"[A-Za-z0-9]{1,128}", str(incident["escalation_policy"].get("id")), flags=re.ASCII):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "invalid typed PagerDuty incident reassignment payload")
            email = await self._incident_actor_from(actor_user_id, account_domain)
            return await self._configuration_request(method, resource_type, resource_id, execution=True, payload=payload, private_headers={"From": email}, dispatch_guard=dispatch_guard)
        return await self._configuration_request(method, resource_type, resource_id, execution=True, payload=payload, dispatch_guard=dispatch_guard)

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
        if query.get("query_type") == "pagerduty_users":
            users = await self.configuration_list("user", budget)
            evidence_id = await ctx.store_evidence(self.provider_id, "pagerduty_users", {"users": users, "complete": True}, summary=f"{len(users)} PagerDuty users")
            coverage = Coverage(requested_sources=[self.provider_id], completed_scopes=[f"{self.provider_id}/users"], pagination_complete=True)
            return EvidenceResult(items=users, coverage=coverage, raw_evidence_ids=[evidence_id], query_description={"endpoint": "/users", "projection": ["id", "name", "html_url", "role"]})
        if query.get("query_type") == "pagerduty_configuration":
            scope = query.get("scope") or {}
            resource_type = scope.get("resource_type")
            resource_id = scope.get("resource_id")
            if resource_type not in CONFIGURATION_TYPES or not isinstance(resource_id, str) or not resource_id:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "pagerduty_configuration requires an exact supported resource_type and resource_id")
            params: dict[str, Any] | None = None
            tr = query.get("time_range")
            if resource_type == "schedule":
                if not isinstance(tr, dict) or not isinstance(tr.get("start"), str) or not isinstance(tr.get("end"), str):
                    raise OpsError(ErrorCode.INVALID_ARGUMENT, "pagerduty_configuration schedule requires a bounded time_range")
                try:
                    start = datetime.fromisoformat(tr["start"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(tr["end"].replace("Z", "+00:00"))
                except ValueError:
                    raise OpsError(ErrorCode.INVALID_ARGUMENT, "pagerduty_configuration schedule time_range is invalid") from None
                if start.tzinfo is None or end.tzinfo is None or end <= start or end - start > timedelta(days=31):
                    raise OpsError(ErrorCode.INVALID_ARGUMENT, "pagerduty_configuration schedule time_range must be aware, positive, and at most 31 days")
                params = {"since": tr["start"], "until": tr["end"], "overflow": True}
            item = await self.configuration_get(resource_type, resource_id, budget, params=params)
            cov = Coverage(requested_sources=[self.provider_id], completed_scopes=[f"{self.provider_id}/{resource_type}/{resource_id}"] if item else [], time_range_requested=tr if isinstance(tr, dict) else None)
            if item is None:
                cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="not_found", detail="PagerDuty configuration resource was not found"))
                cov.conclusion_scope = "The requested PagerDuty configuration resource is absent."
                return EvidenceResult(coverage=cov, query_description={"endpoint": f"/{CONFIGURATION_PATHS[resource_type][0].strip('/')}/{resource_id}"})
            # PagerDuty's legacy schedules endpoint does not enumerate schedule-v3 objects.  This is
            # an exact-resource read, not a claim that every account schedule has been considered.
            note = "Schedule evidence covers this legacy REST schedule resource; it does not enumerate schedule-v3 objects." if resource_type == "schedule" else None
            evidence_id = await ctx.store_evidence(self.provider_id, "pagerduty_configuration", {"resource_type": resource_type, "resource": item}, summary=f"PagerDuty {resource_type} {resource_id}")
            return EvidenceResult(items=[item], coverage=cov, raw_evidence_ids=[evidence_id], notes=[note] if note else [], query_description={"endpoint": f"/{CONFIGURATION_PATHS[resource_type][0].strip('/')}/{resource_id}", "resource_type": resource_type, "resource_id": resource_id, "time_range": tr})
        if query.get("query_type") != "pagerduty_incidents":
            return EvidenceResult(coverage=Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=self.provider_id, reason="unsupported_query_type", detail=f"{query.get('query_type')!r}; supported: pagerduty_incidents, pagerduty_configuration")], conclusion_scope="Unsupported query; no evidence collected."))
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
