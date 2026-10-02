"""GitHub adapter over httpx: repository/workflow/deployment metadata, organization audit log, workflow
runs and bounded reads of explicitly named files (runbooks/source). Reads only; never a checkout.

Audit-log access depends on the token and the organization's plan; a 403/404 is reported as an
unavailable scope rather than as an empty, clean result. Retention differs per event family (Git events
are documented as ~7 days), so the adapter reports the source's observed history instead of assuming 90 days.
"""

from __future__ import annotations

import asyncio
import base64
import re
import time
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
    Observation,
    SupportedOperation,
)
from local_ops.providers.demo import normalize_github_audit

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

DEFAULT_BASE_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
MAX_ORG_REPOS = 200
MAX_WORKFLOWS_PER_REPO = 50
RECENT_RUNS_PER_WORKFLOW = 10
RECENT_DEPLOYMENTS = 10
MAX_FILE_BYTES = 200 * 1024
MAX_RATE_LIMIT_WAIT_SECONDS = 30.0
AUDIT_RETENTION_NOTE = "GitHub audit log retention varies by event/plan; git events are retained ~7 days"
NOT_FOUND_NOTE = "404 is an access/location uncertainty (missing permission, renamed/moved, or private to another identity), not proof the repository does not exist"


class _RateLimited(Exception):
    pass


def normalize_workflow_run(run: dict[str, Any], repo: str, source_id: str, evidence_id: str | None, org: str | None = None) -> dict[str, Any]:
    actor = (run.get("actor") or {}).get("login") or (run.get("triggering_actor") or {}).get("login")
    conclusion = run.get("conclusion") or run.get("status") or "unknown"
    return {
        "event_key": f"github:{repo}:run:{run.get('id')}", "provider": "github", "source_id": source_id, "account": org or repo.split("/")[0], "region": None,
        "event_id": str(run.get("id")), "occurred_at": run.get("created_at"), "collected_at": iso(utcnow()), "actor": actor, "actor_type": "github_user" if actor else None, "session": None,
        "action": f"workflow_run:{conclusion}", "resource": repo, "resource_type": "repository", "source_ip": None, "user_agent": None,
        "outcome": "success" if run.get("conclusion") == "success" else ("failure" if run.get("conclusion") in ("failure", "timed_out", "cancelled", "startup_failure") else None),
        "category": "deployment", "evidence_ref": evidence_id,
        "fields": {"run_id": run.get("id"), "name": run.get("name"), "workflow_id": run.get("workflow_id"), "path": run.get("path"), "head_sha": run.get("head_sha"), "head_branch": run.get("head_branch"), "event": run.get("event"), "status": run.get("status"), "conclusion": run.get("conclusion"), "run_number": run.get("run_number"), "run_attempt": run.get("run_attempt"), "updated_at": run.get("updated_at"), "html_url": run.get("html_url"), "triggering_actor": (run.get("triggering_actor") or {}).get("login")},
    }


_REPO_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def validate_repo_full_name(repo: str) -> str:
    """Reject anything that is not a bare `owner/repo` pair before it is interpolated into a GitHub API
    path. Rejects traversal segments (`.`, `..`) even though they would otherwise match the pattern."""
    if not isinstance(repo, str) or not _REPO_FULL_NAME_RE.match(repo):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"invalid repository reference {repo!r}; expected 'owner/repo'")
    if any(seg in (".", "..") for seg in repo.split("/")):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"invalid repository reference {repo!r}")
    return repo


def safe_repo_path(path: str) -> str:
    """Reject traversal, absolute and otherwise malformed in-repository paths."""
    if not path or not isinstance(path, str):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_file requires an explicit, non-empty path")
    if "\x00" in path or "\\" in path or path.startswith("/") or path.startswith("~") or "://" in path:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_file path must be a relative in-repository path")
    if any(seg in ("..", "") for seg in path.split("/")) or path.endswith("/"):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_file path must not contain '..' or empty segments")
    return path


class GitHubAdapter:
    kind = "github"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, http: httpx.AsyncClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._http = http
        self._owned_http = http is None
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
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": "local-ops-mcp"}
        if self.resolver and self.config.credential and self.resolver.configured(self.config.credential):
            cred = await self.resolver.resolve(self.config.credential)
            if cred.secret:
                headers["Authorization"] = f"Bearer {cred.secret}"
        return headers

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """GET with one bounded rate-limit wait (Retry-After or x-ratelimit-reset, max 30s), then give up."""
        client = await self.http()
        headers = await self._headers()
        full = url if url.startswith("http") else f"{self.base_url}{url}"
        for attempt in (0, 1):
            r = await client.get(full, params=params, headers=headers)
            limited = r.status_code == 429 or (r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0")
            if not limited:
                return r
            wait = _rate_limit_wait(r)
            if attempt == 1 or wait is None or wait > MAX_RATE_LIMIT_WAIT_SECONDS:
                raise _RateLimited(f"rate limited; required wait {wait}s exceeds bound {MAX_RATE_LIMIT_WAIT_SECONDS}s")
            await asyncio.sleep(wait)
        raise _RateLimited("rate limited")

    async def _paginate(self, url: str, params: dict[str, Any], max_pages: int, budget: Budget, ctx: OperationContext) -> tuple[list[Any], list[httpx.Response], bool, str | None]:
        """Follow Link rel=next. Returns (items, responses, complete, next_url)."""
        items: list[Any] = []
        responses: list[httpx.Response] = []
        next_url: str | None = url
        next_params: dict[str, Any] | None = params
        pages = 0
        while next_url and pages < max_pages:
            budget.check()
            ctx.check_cancel()
            r = await self._get(next_url, next_params)
            responses.append(r)
            if r.status_code != 200:
                return items, responses, False, next_url
            body = r.json()
            items.extend(body if isinstance(body, list) else _list_payload(body))
            pages += 1
            next_url = (r.links.get("next") or {}).get("url")
            next_params = None
        return items, responses, next_url is None, next_url

    # ---------------------------------------------------------------- description / availability
    def describe(self) -> AdapterDescription:
        return AdapterDescription(
            provider_id=self.provider_id, kind=self.kind, description=self.config.description,
            operations=[
                SupportedOperation(name="discover", effect=Effect.READ, description="Repository metadata, workflows (with recent runs) and recent deployments for configured repositories or an organization's repositories.", provider_side_filters=["repositories", "org"], limitations=["Metadata only; no checkout, no secrets, no artifact download."]),
                SupportedOperation(name="github_audit", effect=Effect.READ, description="Organization audit log (where token/plan permit).", provider_side_filters=["actor", "action", "created>=", "phrase"], limitations=[AUDIT_RETENTION_NOTE, "Enterprise audit log and streaming are not read."]),
                SupportedOperation(name="github_workflow_runs", effect=Effect.READ, description="Workflow runs for one repository in a time window.", provider_side_filters=["repository", "created", "branch", "event", "status"]),
                SupportedOperation(name="github_file", effect=Effect.READ, description="Bounded read of one explicit in-repository path (runbook/source), max 200KB.", provider_side_filters=["repository", "path", "ref"], limitations=["One explicit path per query; no directory listing or recursive reads."]),
            ],
            required_credentials=[c for c in [self.config.credential, self.config.execution_credential] if c],
            credential_configured=bool(self.resolver and self.resolver.configured(self.config.credential)),
            scope_constraints={"base_url": self.base_url, "org": self.config.org, "repositories": self.config.repositories or (f"org {self.config.org} (max {MAX_ORG_REPOS})" if self.config.org else "none configured"), "audit_log": self.config.audit_log},
            limitations=[AUDIT_RETENTION_NOTE, NOT_FOUND_NOTE, "Rate limits are respected with one bounded wait; further limiting produces a coverage gap."],
        )

    async def check_availability(self, *, live: bool = False) -> Availability:
        if not (self.resolver and self.resolver.configured(self.config.credential)):
            return Availability(available=False, reason="credential_not_configured", detail=f"GitHub token for {self.provider_id} is not resolvable")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        try:
            r = await self._get("/user")
            if r.status_code == 401:
                return Availability(available=False, reason="auth_required", detail="GitHub rejected the token", checked_live=True)
            scopes = [s.strip() for s in r.headers.get("x-oauth-scopes", "").split(",") if s.strip()]
            if r.status_code == 200:
                body = r.json()
                return Availability(available=True, checked_live=True, identity={"login": body.get("login"), "type": body.get("type"), "scopes": scopes, "base_url": self.base_url})
            r2 = await self._get("/rate_limit")  # installation/app tokens cannot call /user
            if r2.status_code == 200:
                core = ((r2.json().get("resources") or {}).get("core") or {})
                return Availability(available=True, checked_live=True, identity={"login": None, "scopes": scopes, "rate_limit": core.get("limit"), "rate_remaining": core.get("remaining"), "base_url": self.base_url})
            return Availability(available=False, reason="provider_unavailable", detail=f"HTTP {r.status_code} from /user, {r2.status_code} from /rate_limit", checked_live=True)
        except OpsError as e:
            return Availability(available=False, reason=e.code.value, detail=e.message, checked_live=True)
        except _RateLimited as e:
            return Availability(available=False, reason="rate_limited", detail=str(e), checked_live=True)
        except httpx.HTTPError as e:
            return Availability(available=False, reason="provider_unavailable", detail=type(e).__name__, checked_live=True)

    # ---------------------------------------------------------------- discovery
    async def _repositories(self, scope: DiscoveryScope, report: DiscoveryReport, budget: Budget, ctx: OperationContext) -> list[str]:
        requested = list(scope.repositories)
        configured = list(self.config.repositories)
        if requested and configured:
            # The provider's configured repository list is the allowed set; a request naming repositories
            # outside it is refused rather than silently honored (same precedent as AWS region scoping).
            repos = [r for r in requested if r in configured]
            for r in requested:
                if r not in configured:
                    report.unavailable.append({"source": f"{self.provider_id}/{r}", "reason": "repository_outside_configured_scope", "detail": f"repository {r} is not in the provider's configured repositories"})
        else:
            repos = requested or configured
        if repos or not self.config.org:
            return repos
        items, responses, complete, _ = await self._paginate(f"/orgs/{self.config.org}/repos", {"per_page": 100, "type": "all", "sort": "pushed"}, 2, budget, ctx)
        last = responses[-1] if responses else None
        if last is not None and last.status_code != 200:
            report.unavailable.append({"source": f"{self.provider_id}/org/{self.config.org}", "reason": "org_not_found_or_no_access" if last.status_code in (403, 404) else "provider_unavailable", "detail": f"HTTP {last.status_code}; {NOT_FOUND_NOTE}"})
            return []
        if not complete or len(items) > MAX_ORG_REPOS:
            report.truncated = True
            report.notes.append(f"organization {self.config.org} has more repositories than the enumeration bound ({MAX_ORG_REPOS}); list them explicitly to cover the rest")
        return [str(i.get("full_name")) for i in items[:MAX_ORG_REPOS] if i.get("full_name")]

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"base_url": self.base_url, "org": self.config.org})
        try:
            repos = await self._repositories(scope, report, budget, ctx)
        except OpsError as e:
            report.unavailable.append({"source": self.provider_id, "reason": e.code.value, "detail": e.message})
            return report
        except _RateLimited as e:
            report.unavailable.append({"source": self.provider_id, "reason": "rate_limited", "detail": str(e)})
            return report
        except httpx.HTTPError as e:
            report.unavailable.append({"source": self.provider_id, "reason": "provider_unavailable", "detail": type(e).__name__})
            return report
        if not repos:
            report.notes.append("no repositories configured or enumerated")
        for repo in repos:
            budget.check()
            ctx.check_cancel()
            scope_key = f"{self.provider_id}/{repo}"
            try:
                await self._discover_repo(ctx, repo, scope_key, report)
            except OpsError as e:
                report.unavailable.append({"source": scope_key, "reason": e.code.value, "detail": e.message})
            except _RateLimited as e:
                report.unavailable.append({"source": scope_key, "reason": "rate_limited", "detail": str(e)})
                report.partial_scopes.append(scope_key)
                report.truncated = True
                break
            except httpx.HTTPError as e:
                report.unavailable.append({"source": scope_key, "reason": "provider_unavailable", "detail": type(e).__name__})
        return report

    async def _discover_repo(self, ctx: OperationContext, repo: str, scope_key: str, report: DiscoveryReport) -> None:
        repo = validate_repo_full_name(repo)
        r = await self._get(f"/repos/{repo}")
        if r.status_code == 404:
            report.unavailable.append({"source": scope_key, "reason": "repository_not_found_or_no_access", "detail": NOT_FOUND_NOTE})
            return
        if r.status_code in (401, 403):
            report.unavailable.append({"source": scope_key, "reason": "auth_required" if r.status_code == 401 else "repository_not_found_or_no_access", "detail": f"HTTP {r.status_code}; {NOT_FOUND_NOTE}"})
            return
        if r.status_code != 200:
            report.unavailable.append({"source": scope_key, "reason": "provider_unavailable", "detail": f"HTTP {r.status_code}"})
            return
        meta = r.json()
        full_name = str(meta.get("full_name") or repo)
        partial = False
        # Workflows and deployments are each fetched as a single bounded page (never paginated further),
        # so they are samples, not a complete listing, even when the repository metadata fetch succeeds.
        # They get their own scope keys that are only completed when the page demonstrably held everything.
        workflows_scope_key = f"{scope_key}/workflows"
        deployments_scope_key = f"{scope_key}/deployments"
        workflows: list[dict[str, Any]] = []
        workflows_complete = False
        wr = await self._get(f"/repos/{full_name}/actions/workflows", {"per_page": MAX_WORKFLOWS_PER_REPO})
        if wr.status_code == 200:
            wr_body = wr.json()
            workflows = list((wr_body.get("workflows") or [])[:MAX_WORKFLOWS_PER_REPO])
            total = wr_body.get("total_count")
            workflows_complete = len(workflows) < MAX_WORKFLOWS_PER_REPO if total is None else int(total) <= len(workflows)
        else:
            partial = True
            report.notes.append(f"{full_name}: workflows unavailable (HTTP {wr.status_code})")
        (report.completed_scopes if workflows_complete else report.partial_scopes).append(workflows_scope_key)
        runs_by_workflow: dict[int, list[dict[str, Any]]] = {}
        for wf in workflows:
            rr = await self._get(f"/repos/{full_name}/actions/workflows/{wf['id']}/runs", {"per_page": RECENT_RUNS_PER_WORKFLOW})
            if rr.status_code == 200:
                runs_by_workflow[int(wf["id"])] = [_run_summary(x) for x in (rr.json().get("workflow_runs") or [])[:RECENT_RUNS_PER_WORKFLOW]]
            else:
                partial = True
        deployments: list[dict[str, Any]] = []
        deployments_complete = False
        dr = await self._get(f"/repos/{full_name}/deployments", {"per_page": RECENT_DEPLOYMENTS})
        if dr.status_code == 200:
            dr_body = dr.json()
            deployments = list(dr_body[:RECENT_DEPLOYMENTS]) if isinstance(dr_body, list) else []
            deployments_complete = len(deployments) < RECENT_DEPLOYMENTS
        else:
            partial = True
            report.notes.append(f"{full_name}: deployments unavailable (HTTP {dr.status_code})")
        (report.completed_scopes if deployments_complete else report.partial_scopes).append(deployments_scope_key)
        repo_attrs = {"default_branch": meta.get("default_branch"), "visibility": meta.get("visibility") or ("private" if meta.get("private") else "public"), "pushed_at": meta.get("pushed_at"), "updated_at": meta.get("updated_at"), "archived": bool(meta.get("archived")), "disabled": bool(meta.get("disabled")), "fork": bool(meta.get("fork")), "html_url": meta.get("html_url"), "description": meta.get("description"), "topics": meta.get("topics") or [], "language": meta.get("language"), "workflow_count": len(workflows), "deployment_count_recent": len(deployments)}
        eid = await ctx.store_evidence(self.provider_id, "github_repository_snapshot", {"repository": {k: meta.get(k) for k in ("id", "node_id", "full_name", "default_branch", "visibility", "private", "pushed_at", "updated_at", "archived", "disabled", "fork", "html_url", "description", "topics", "language")}, "workflows": workflows, "workflow_runs": runs_by_workflow, "deployments": deployments}, summary=f"{full_name}: {len(workflows)} workflows, {len(deployments)} recent deployments")
        repo_key = f"gh:{full_name}"
        report.observations.append(Observation(provider_id=self.provider_id, resource_key=repo_key, resource_type="github/repository", identity={"full_name": full_name, "id": meta.get("id"), "node_id": meta.get("node_id"), "base_url": self.base_url}, attributes=repo_attrs, scope_key=scope_key, evidence_id=eid))
        for wf in workflows:
            report.observations.append(Observation(
                provider_id=self.provider_id, resource_key=f"{repo_key}:workflow:{wf.get('id')}", resource_type="github/workflow",
                identity={"repository": full_name, "id": wf.get("id"), "path": wf.get("path"), "name": wf.get("name")},
                attributes={"state": wf.get("state"), "created_at": wf.get("created_at"), "updated_at": wf.get("updated_at"), "html_url": wf.get("html_url"), "recent_runs": runs_by_workflow.get(int(wf["id"]), []), "recent_runs_bound": RECENT_RUNS_PER_WORKFLOW},
                scope_key=workflows_scope_key, evidence_id=eid, relationships=[{"kind": "owner", "target": repo_key}],
            ))
        for d in deployments:
            report.observations.append(Observation(
                provider_id=self.provider_id, resource_key=f"{repo_key}:deployment:{d.get('id')}", resource_type="github/deployment",
                identity={"repository": full_name, "id": d.get("id"), "environment": d.get("environment")},
                attributes={"sha": d.get("sha"), "ref": d.get("ref"), "task": d.get("task"), "environment": d.get("environment"), "transient_environment": d.get("transient_environment"), "production_environment": d.get("production_environment"), "creator": (d.get("creator") or {}).get("login"), "created_at": d.get("created_at"), "updated_at": d.get("updated_at"), "description": d.get("description")},
                scope_key=deployments_scope_key, evidence_id=eid, relationships=[{"kind": "owner", "target": repo_key}],
            ))
        (report.partial_scopes if partial else report.completed_scopes).append(scope_key)

    # ---------------------------------------------------------------- evidence queries
    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        qtype = query.get("query_type")
        if qtype == "github_audit":
            return await self._query_audit(ctx, query, budget)
        if qtype == "github_workflow_runs":
            return await self._query_runs(ctx, query, budget)
        if qtype == "github_file":
            return await self._query_file(ctx, query, budget)
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"github adapter does not support query_type {qtype!r}")

    async def _query_audit(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        tr = query.get("time_range") or {}
        requested_org = (query.get("scope") or {}).get("org")
        org = requested_org or self.config.org
        if not org:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_audit requires an organization (provider org or scope.org)")
        if self.config.org and requested_org and requested_org != self.config.org:
            cov = Coverage(requested_sources=[self.provider_id], unavailable_scopes=[UnavailableScope(source=f"{self.provider_id}/{requested_org}", reason="org_outside_configured_scope", detail=f"provider {self.provider_id} is configured for org {self.config.org!r}; refusing org {requested_org!r}")], conclusion_scope="Requested org is outside this provider's configured scope; refused.")
            return EvidenceResult(coverage=cov, query_description={"org": requested_org})
        max_events = max(1, int(limits.get("max_events", 500)))
        max_pages = max(1, min(int(limits.get("max_pages", 20)), budget.max_pages))
        phrase_parts: list[str] = []
        if filters.get("phrase"):
            phrase_parts.append(str(filters["phrase"]))
        for actor in _as_list(filters.get("actor") or filters.get("actors")):
            phrase_parts.append(f"actor:{actor}")
        for action in _as_list(filters.get("action") or filters.get("actions")):
            phrase_parts.append(f"action:{action}")
        if tr.get("start"):
            phrase_parts.append(f"created:>={str(tr['start'])[:10]}")
        if tr.get("end"):
            phrase_parts.append(f"created:<={str(tr['end'])[:10]}")
        params: dict[str, Any] = {"per_page": min(100, max_events), "include": filters.get("include", "all"), "order": "desc"}
        if phrase_parts:
            params["phrase"] = " ".join(phrase_parts)
        if query.get("cursor"):
            params["after"] = str(query["cursor"])
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["github_audit"], time_range_requested={"start": tr.get("start"), "end": tr.get("end")}, source_retention_known=False, source_retention_note=AUDIT_RETENTION_NOTE, filters_provider_side=[k for k in ("actor", "action", "created", "phrase") if k in params.get("phrase", "")])
        try:
            raw, responses, complete, next_url = await self._paginate(f"/orgs/{org}/audit-log", params, max_pages, budget, ctx)
        except _RateLimited as e:
            cov.collection_gaps.append(f"{self.provider_id}/{org}/audit-log: rate limited beyond bounded wait ({e})")
            cov.pagination_complete = False
            return EvidenceResult(coverage=cov, query_description={"org": org, "phrase": params.get("phrase")})
        except httpx.HTTPError as e:
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{org}/audit-log", reason="provider_unavailable", detail=type(e).__name__))
            return EvidenceResult(coverage=cov, query_description={"org": org, "phrase": params.get("phrase")})
        last = responses[-1] if responses else None
        if last is not None and last.status_code != 200:
            if last.status_code in (403, 404):
                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{org}/audit-log", reason="audit_log_not_available_for_plan_or_token", detail=f"HTTP {last.status_code}: organization audit log requires an eligible plan and a token with read:audit_log (or equivalent)"))
            elif last.status_code == 401:
                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{org}/audit-log", reason="auth_required", detail="HTTP 401"))
            else:
                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{org}/audit-log", reason="provider_unavailable", detail=f"HTTP {last.status_code}"))
            if not raw:
                cov.conclusion_scope = "GitHub audit log was not readable; absence of events here is not evidence of inactivity."
                return EvidenceResult(coverage=cov, query_description={"org": org, "phrase": params.get("phrase")})
            cov.pagination_complete = False
        truncated = len(raw) > max_events
        raw = raw[:max_events]
        eid = await ctx.store_evidence(self.provider_id, "github_audit", {"org": org, "phrase": params.get("phrase"), "events": raw}, summary=f"{len(raw)} GitHub audit events for {org}")
        events = [normalize_github_audit(e, self.provider_id, eid, org=org) for e in raw]
        times = sorted(str(e["occurred_at"]) for e in events if e.get("occurred_at"))
        if times:
            cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        cov.truncated = truncated
        cov.pagination_complete = cov.pagination_complete and complete and not truncated
        if complete and not truncated:
            cov.completed_scopes.append(f"{self.provider_id}/{org}/audit-log")
        elif not complete:
            cov.collection_gaps.append(f"{self.provider_id}/{org}/audit-log: stopped at max_pages={max_pages}; more pages exist")
        cursor = _after_param(next_url) if next_url else None
        return EvidenceResult(items=events, events=events, coverage=cov, cursor=cursor, raw_evidence_ids=[eid], notes=[AUDIT_RETENTION_NOTE], query_description={"org": org, "phrase": params.get("phrase"), "per_page": params["per_page"]})

    async def _query_runs(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        tr = query.get("time_range") or {}
        sc = query.get("scope") or {}
        repo = sc.get("repository") or sc.get("repo")
        if not repo:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_workflow_runs requires scope.repository (owner/name)")
        repo = validate_repo_full_name(str(repo))
        max_events = max(1, int(limits.get("max_events", 500)))
        max_pages = max(1, min(int(limits.get("max_pages", 20)), budget.max_pages))
        params: dict[str, Any] = {"per_page": min(100, max_events)}
        if tr.get("start") or tr.get("end"):
            params["created"] = f"{tr.get('start') or '*'}..{tr.get('end') or '*'}"
        for k in ("branch", "event", "status", "actor"):
            if filters.get(k):
                params[k] = filters[k]
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["deployment"], time_range_requested={"start": tr.get("start"), "end": tr.get("end")}, source_retention_known=False, source_retention_note="Workflow run history retention depends on the repository's Actions log retention setting (default 90 days).", filters_provider_side=[k for k in ("created", "branch", "event", "status", "actor") if k in params])
        try:
            raw, responses, complete, next_url = await self._paginate(f"/repos/{repo}/actions/runs", params, max_pages, budget, ctx)
        except _RateLimited as e:
            cov.collection_gaps.append(f"{self.provider_id}/{repo}/runs: rate limited beyond bounded wait ({e})")
            cov.pagination_complete = False
            return EvidenceResult(coverage=cov, query_description={"repository": repo, **params})
        except httpx.HTTPError as e:
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{repo}/runs", reason="provider_unavailable", detail=type(e).__name__))
            return EvidenceResult(coverage=cov, query_description={"repository": repo, **params})
        last = responses[-1] if responses else None
        if last is not None and last.status_code != 200:
            reason = "repository_not_found_or_no_access" if last.status_code in (403, 404) else ("auth_required" if last.status_code == 401 else "provider_unavailable")
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{repo}/runs", reason=reason, detail=f"HTTP {last.status_code}; {NOT_FOUND_NOTE}" if last.status_code == 404 else f"HTTP {last.status_code}"))
            if not raw:
                return EvidenceResult(coverage=cov, query_description={"repository": repo, **params})
            cov.pagination_complete = False
        truncated = len(raw) > max_events
        raw = raw[:max_events]
        summaries = [_run_summary(x) for x in raw]
        eid = await ctx.store_evidence(self.provider_id, "github_workflow_runs", {"repository": repo, "params": params, "runs": summaries}, summary=f"{len(summaries)} workflow runs for {repo}")
        events = [normalize_workflow_run(x, repo, self.provider_id, eid, org=self.config.org) for x in raw]
        times = sorted(str(e["occurred_at"]) for e in events if e.get("occurred_at"))
        if times:
            cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        cov.truncated = truncated
        cov.pagination_complete = cov.pagination_complete and complete and not truncated
        if complete and not truncated:
            cov.completed_scopes.append(f"{self.provider_id}/{repo}/runs")
        return EvidenceResult(items=summaries, events=events, coverage=cov, cursor=None, raw_evidence_ids=[eid], query_description={"repository": repo, **params})

    async def _query_file(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        sc = query.get("scope") or {}
        repo = sc.get("repository") or sc.get("repo")
        if not repo:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "github_file requires scope.repository (owner/name)")
        repo = validate_repo_full_name(str(repo))
        path = safe_repo_path(sc.get("path") or (query.get("filters") or {}).get("path") or "")
        ref = sc.get("ref") or (query.get("filters") or {}).get("ref")
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["source"], filters_provider_side=["repository", "path", "ref"], source_retention_known=True, source_retention_note="Repository content at the requested ref.")
        params = {"ref": ref} if ref else None
        budget.check()
        try:
            r = await self._get(f"/repos/{repo}/contents/{path}", params)
        except _RateLimited as e:
            cov.collection_gaps.append(f"{self.provider_id}/{repo}/{path}: rate limited beyond bounded wait ({e})")
            return EvidenceResult(coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        except httpx.HTTPError as e:
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{repo}/{path}", reason="provider_unavailable", detail=type(e).__name__))
            return EvidenceResult(coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        src = f"{self.provider_id}/{repo}/{path}"
        if r.status_code in (403, 404):
            cov.unavailable_scopes.append(UnavailableScope(source=src, reason="file_or_repository_not_found_or_no_access", detail=f"HTTP {r.status_code}; {NOT_FOUND_NOTE}"))
            return EvidenceResult(coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        if r.status_code == 401:
            cov.unavailable_scopes.append(UnavailableScope(source=src, reason="auth_required", detail="HTTP 401"))
            return EvidenceResult(coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        if r.status_code != 200:
            cov.unavailable_scopes.append(UnavailableScope(source=src, reason="provider_unavailable", detail=f"HTTP {r.status_code}"))
            return EvidenceResult(coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        body = r.json()
        if isinstance(body, list) or body.get("type") != "file":
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"github_file reads single files only; {path} is a {'directory' if isinstance(body, list) else body.get('type')}")
        size = int(body.get("size") or 0)
        content_b64 = body.get("content") or ""
        if body.get("encoding") != "base64" or not content_b64:
            cov.unavailable_scopes.append(UnavailableScope(source=src, reason="content_not_inline", detail=f"size {size} bytes; the contents API returns inline content only for files up to 1MB"))
            return EvidenceResult(items=[{"repository": repo, "path": path, "ref": ref, "sha": body.get("sha"), "size": size, "content_available": False}], coverage=cov, query_description={"repository": repo, "path": path, "ref": ref})
        data = base64.b64decode(content_b64)
        truncated = len(data) > MAX_FILE_BYTES
        data = data[:MAX_FILE_BYTES]
        text = data.decode("utf-8", errors="replace")
        cov.truncated = truncated
        if truncated:
            cov.collection_gaps.append(f"{src}: content truncated at {MAX_FILE_BYTES} bytes (file is {size} bytes)")
        eid = await ctx.store_evidence(self.provider_id, "github_file", {"repository": repo, "path": path, "ref": ref, "sha": body.get("sha"), "size": size, "truncated": truncated, "text": text}, summary=f"{repo}:{path}@{ref or 'default'} ({size} bytes{', truncated' if truncated else ''})")
        cov.completed_scopes.append(src)
        return EvidenceResult(items=[{"repository": repo, "path": path, "ref": ref, "sha": body.get("sha"), "size": size, "truncated": truncated, "html_url": body.get("html_url"), "text": text}], coverage=cov, raw_evidence_ids=[eid], query_description={"repository": repo, "path": path, "ref": ref, "max_bytes": MAX_FILE_BYTES})


def _run_summary(run: dict[str, Any]) -> dict[str, Any]:
    return {"id": run.get("id"), "name": run.get("name"), "workflow_id": run.get("workflow_id"), "head_sha": run.get("head_sha"), "head_branch": run.get("head_branch"), "event": run.get("event"), "status": run.get("status"), "conclusion": run.get("conclusion"), "actor": (run.get("actor") or {}).get("login"), "created_at": run.get("created_at"), "updated_at": run.get("updated_at"), "run_number": run.get("run_number"), "html_url": run.get("html_url")}


def _list_payload(body: dict[str, Any]) -> list[Any]:
    for k in ("workflow_runs", "workflows", "items"):
        if isinstance(body.get(k), list):
            return list(body[k])
    return []


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def _after_param(url: str) -> str | None:
    return dict(httpx.URL(url).params).get("after")


def _rate_limit_wait(r: httpx.Response) -> float | None:
    ra = r.headers.get("retry-after")
    if ra:
        try:
            return max(0.0, float(ra))
        except ValueError:
            pass
    reset = r.headers.get("x-ratelimit-reset")
    if reset:
        try:
            return max(0.0, float(reset) - time.time())
        except ValueError:
            return None
    return None
