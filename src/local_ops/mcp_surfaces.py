"""Two thin capability-specific MCP surfaces (read, write) over the shared core (D28).

Authentication happens in BearerKeyMiddleware (app.py) which populates the SDK's `scope["user"]` so the
SDK binds each session to the authenticating credential. Tools re-check authorization in the core on
every call; `tools/list` filtering is never the only control."""

from __future__ import annotations

import json
from typing import Any

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field, ValidationError

from local_ops.auth import Principal
from local_ops.core import Core
from local_ops.models import Capability, ErrorCode, OpsError, Page
from local_ops.operations.diagnosis import (
    EvidenceQueryArgs,
    InvestigationRunArgs,
    ServiceInspectArgs,
    expand_saved_query,
)
from local_ops.operations.discovery import DiscoveryScanArgs
from local_ops.operations.execution import ActionPrepareArgs, ActionSubmitArgs


def _tool_error(e: OpsError) -> ToolError:
    return ToolError(json.dumps(e.public()))


async def _principal(core: Core, capability: Capability) -> Principal:
    token = get_access_token()
    if token is None:
        raise ToolError(json.dumps({"error": ErrorCode.AUTH_REQUIRED.value, "message": "bearer credential required"}))
    p = await core.auth.principal(token.client_id)
    if p is None or p.revoked:
        raise ToolError(json.dumps({"error": ErrorCode.AUTHORIZATION_DENIED.value, "message": "credential revoked or unknown"}))
    if not p.has(capability):
        raise ToolError(json.dumps({"error": ErrorCode.AUTHORIZATION_DENIED.value, "message": f"credential is not granted {capability.value}"}))
    return p


def _common_tools(server: MCPServer, core: Core, capability: Capability) -> None:
    @server.tool(name="capabilities_get", description="Describe this surface: granted capability, effective review mode, operations and their argument schemas, configured providers and catalog revision. Control-only; no provider I/O.")
    async def capabilities_get() -> dict[str, Any]:
        p = await _principal(core, capability)
        return await core.capabilities(p, capability)

    @server.tool(name="request_status", description="Safe lifecycle status of a request you submitted (execution_status and response_status axes). Control-only.")
    async def request_status(request_id: str) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return (await core.requests.status(p, request_id)).model_dump(mode="json")
        except OpsError as e:
            raise _tool_error(e) from None

    @server.tool(name="request_result", description="Retrieve the released result of a request (paginated over `items`). Only released responses are readable; pending or withheld responses return a typed error. Control-only.")
    async def request_result(request_id: str, offset: int = 0, limit: int = 50) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return await core.requests.result(p, request_id, Page(offset=offset, limit=limit))
        except ValidationError:
            raise _tool_error(OpsError(ErrorCode.INVALID_ARGUMENT, "offset must be non-negative; limit must be between 1 and 500 (maximum 500)")) from None
        except OpsError as e:
            raise _tool_error(e) from None

    @server.tool(name="request_cancel", description="Cancel a request. Before dispatch this prevents the operation; after dispatch it stops further stages where possible and records observed state.")
    async def request_cancel(request_id: str) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return (await core.requests.cancel(p, request_id)).model_dump(mode="json")
        except OpsError as e:
            raise _tool_error(e) from None

    @server.tool(name="evidence_get", description="Read a bounded excerpt of an evidence fragment that has been released to you (sanitized at ingestion).")
    async def evidence_get(evidence_id: str, max_bytes: int = Field(default=100_000, ge=1000, le=2_000_000)) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return await core.requests.evidence(p, evidence_id, max_bytes)
        except OpsError as e:
            raise _tool_error(e) from None


KNOWLEDGE_LOOP = (
    " Cross-session knowledge lives in the approved catalog, shared by every assistant: start with catalog_read, "
    "reuse a service's knowledge.queries (saved_query_run) and knowledge.failure_signatures "
    "before exploring, and when you learn something durable (where a service runs, its dependencies, a useful query, "
    "what a failure looks like) propose it with catalog_propose, citing released evidence. Proposals are reviewed by a "
    "human and committed to Git; check catalog_proposals before proposing again."
)


def _proposal_tools(server: MCPServer, core: Core, capability: Capability) -> None:
    @server.tool(name="catalog_propose", description="Propose a change to one service file (or a new service) in the approved catalog: a list of {op: add|replace|remove, path: JSON pointer, value, evidence: [released evidence/observation/finding ids]}. Only descriptive and knowledge fields, plus adding a non-executable binding, are proposable. Requires the current catalog revision from catalog_read. A human reviews it; nothing changes until it is committed. Control-only.")
    async def catalog_propose(service_id: str, base_revision: str, changes: list[dict[str, Any]], reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return await core.proposals.propose(p, capability, service_id=service_id, base_revision=base_revision, changes=changes, reason=reason)
        except OpsError as e:
            raise _tool_error(e) from None

    @server.tool(name="catalog_proposals", description="Your catalog proposals and their status (pending_review, stale, accepted, rejected, applied) with reviewer notes. Control-only.")
    async def catalog_proposals(service_id: str | None = None, status: str | None = None) -> dict[str, Any]:
        p = await _principal(core, capability)
        return await core.proposals.list_for(p, service_id=service_id, status=status)

    @server.tool(name="observations_query", description="Page through observations released to you, for correlating resources into logical services before proposing bindings. Exact filters (provider_id, resource_type, account, region, tag_key[/tag_value]); `text` is a literal substring over key/label that only narrows the listing; unbound_only hides resources an approved binding already names; include_related adds exact provider relationships (resolved where the target was also observed). Control-only; never calls a provider.")
    async def observations_query(provider_id: str | None = None, resource_type: str | None = None, account: str | None = None, region: str | None = None, tag_key: str | None = None, tag_value: str | None = None, text: str | None = None, unbound_only: bool = False, include_related: bool = False, offset: int = Field(default=0, ge=0), limit: int = Field(default=100, ge=1, le=500)) -> dict[str, Any]:
        p = await _principal(core, capability)
        try:
            return await core.observations_query(p, provider_id=provider_id, resource_type=resource_type, account=account, region=region, tag_key=tag_key, tag_value=tag_value, text=text, unbound_only=unbound_only, include_related=include_related, offset=offset, limit=limit)
        except OpsError as e:
            raise _tool_error(e) from None

    @server.tool(name="access_report", description="AWS human-access graph from released Identity Center and IAM observations: the observed onboarding path, coverage warnings, and (with `person`, matched exactly by user name, display name, user id or IAM user name) that person's effective access and an offboarding checklist. Control-only; never asserts access is removed when coverage is incomplete.")
    async def access_report(person: str | None = None) -> dict[str, Any]:
        p = await _principal(core, capability)
        return await core.access_report(p, person=person)


def _submit_tool(core: Core, capability: Capability, operation: str):
    async def submit(p: Principal, args: dict[str, Any], reason: str | None, idempotency_key: str | None = None) -> dict[str, Any]:
        try:
            res = await core.requests.submit(p, operation, args, reason=reason, idempotency_key=idempotency_key)
        except OpsError as e:
            raise _tool_error(e) from None
        return res.model_dump(mode="json")

    return submit


def build_read(core: Core) -> MCPServer:
    s = MCPServer("local-ops-read", instructions="Read-only discovery, diagnosis and investigation. Every data-bearing call returns a request id; poll request_status then request_result. Review is set per data class: inventory (discovery_scan) and content (evidence_query, service_inspect, investigation_run, saved_query_run) may need a human to approve the request and/or release the result. The service map (catalog_read) returns approved configuration plus observations released to you. Findings are evidence-backed and never claim 'no intrusion'." + KNOWLEDGE_LOOP)
    cap = Capability.READ
    _common_tools(s, core, cap)
    _proposal_tools(s, core, cap)

    @s.tool(name="discovery_scan", description="Scoped read-only discovery across configured providers (AWS, Kubernetes, 1Password, GitHub, observability, imports). Records observations, candidate matches and gaps. Data class: inventory. Returns a request id.")
    async def discovery_scan(providers: list[str] = Field(default_factory=list), scope: dict[str, Any] = Field(default_factory=dict), reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        args = DiscoveryScanArgs.model_validate({"providers": providers, "scope": scope, "reason": reason})
        return await _submit_tool(core, cap, "discovery_scan")(p, args.model_dump(mode="json"), reason)

    @s.tool(name="catalog_read", description="Read the service map: approved configuration (what/why/where/who/depends-on/credential refs/health/runbooks/knowledge.queries/failure_signatures/contradictions/unknowns) joined with released observations. Control-only.")
    async def catalog_read(service_id: str | None = None, include_observed: bool = True, include_notes: bool = False) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            return await core.catalog_read(p, service_id=service_id, include_observed=include_observed, include_body=include_notes)
        except OpsError as e:
            raise _tool_error(e) from None

    @s.tool(name="catalog_gaps", description="Reconciliation gaps: unbound deployments, unknown owners, missing alert/log/audit sources, contradictions, unresolved workloads, ambiguous matches, expiry unknowns. Control-only.")
    async def catalog_gaps(service_id: str | None = None, kinds: list[str] = Field(default_factory=list)) -> dict[str, Any]:
        p = await _principal(core, cap)
        return await core.catalog_gaps(p, service_id=service_id, kinds=kinds or None)

    @s.tool(name="catalog_export", description="Export the service map as readable Markdown (index + one file per service) or JSON, respecting disclosure. Optionally writes a proposed export under the server state directory (never to Git).")
    async def catalog_export(format: str = "markdown", service_id: str | None = None, write: bool = False) -> dict[str, Any]:
        p = await _principal(core, cap)
        if format not in ("markdown", "json"):
            raise ToolError(json.dumps({"error": "invalid_argument", "message": "format must be markdown or json"}))
        return await core.catalog_export(p, fmt=format, service_id=service_id, write=write)

    @s.tool(name="saved_query_run", description="Run a service's reviewed saved query (catalog knowledge.queries) as an ordinary evidence_query. You choose only the window and reason; the query itself comes from approved configuration. Data class: content. Returns a request id.")
    async def saved_query_run(service_id: str, query_id: str, lookback_minutes: int | None = Field(default=None, ge=1, le=10080), reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            args = expand_saved_query(core.catalog, service_id, query_id, lookback_minutes=lookback_minutes, reason=reason)
        except OpsError as e:
            raise _tool_error(e) from None
        return await _submit_tool(core, cap, "evidence_query")(p, args.model_dump(mode="json"), args.reason)

    @s.tool(name="service_inspect", description="Resolve a service/binding to its running workload and collect exact identity, artifact, readiness, restarts, events, bounded current/previous logs, recent changes and dependency health. Returns observations, hypotheses, next queries and possible (non-executed) actions. Data class: content.")
    async def service_inspect(service_id: str, binding_id: str | None = None, lookback_minutes: int = 60, log_lines: int = 200, include_previous_logs: bool = True, reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        args = ServiceInspectArgs(service_id=service_id, binding_id=binding_id, lookback_minutes=lookback_minutes, log_lines=log_lines, include_previous_logs=include_previous_logs, reason=reason)
        return await _submit_tool(core, cap, "service_inspect")(p, args.model_dump(mode="json"), reason)

    @s.tool(name="evidence_query", description="Typed bounded evidence query: cloudtrail_events, cloudwatch_logs, cloudwatch_metrics, loki_logs, prometheus_metrics, kubernetes_events, container_logs, github_audit, github_workflow_runs, onepassword_events, kubernetes_audit, guardduty_findings, pagerduty_incidents, local_import. Scope/time_range/filters/limits are validated; the adapter reports which filters are provider-side vs local and the exact coverage. Data class: content.")
    async def evidence_query(source_id: str, query_type: str, scope: dict[str, Any] = Field(default_factory=dict), time_range: dict[str, str] | None = None, filters: dict[str, Any] = Field(default_factory=dict), limits: dict[str, int] = Field(default_factory=dict), reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            args = EvidenceQueryArgs.model_validate({"source_id": source_id, "query_type": query_type, "scope": scope, "time_range": time_range, "filters": filters, "limits": limits, "reason": reason})
        except Exception as e:  # noqa: BLE001
            raise ToolError(json.dumps({"error": "invalid_argument", "message": str(e)[:500]})) from None
        return await _submit_tool(core, cap, "evidence_query")(p, args.model_dump(mode="json"), reason)

    @s.tool(name="investigation_run", description="Run a deterministic investigation recipe (generic_workload, health_checks, identity_and_deployment_audit) over configured sources: collects bounded evidence, runs explainable rules (departed identities, privileged/logging changes, unexpected images, auth bursts, k8s admin actions, provider findings, cross-source correlation) and returns findings + timeline + coverage, including whether the requested window was fully read. Data class: content.")
    async def investigation_run(recipe: str, service_id: str | None = None, binding_id: str | None = None, sources: list[str] = Field(default_factory=list), time_range: dict[str, str] | None = None, lookback_minutes: int = 1440, filters: dict[str, Any] = Field(default_factory=dict), limits: dict[str, int] = Field(default_factory=dict), reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            args = InvestigationRunArgs.model_validate({"recipe": recipe, "service_id": service_id, "binding_id": binding_id, "sources": sources, "time_range": time_range, "lookback_minutes": lookback_minutes, "filters": filters, "limits": limits, "reason": reason})
        except Exception as e:  # noqa: BLE001
            raise ToolError(json.dumps({"error": "invalid_argument", "message": str(e)[:500]})) from None
        return await _submit_tool(core, cap, "investigation_run")(p, args.model_dump(mode="json"), reason)

    @s.tool(name="findings_read", description="Read findings whose contributing evidence has been released to you (optionally for one request). Control-only.")
    async def findings_read(request_id: str | None = None, limit: int = 100) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            return await core.findings_read(p, request_id, limit)
        except OpsError as e:
            raise _tool_error(e) from None

    return s


def build_write(core: Core) -> MCPServer:
    s = MCPServer("local-ops-write", instructions="Two-step controlled execution: action_prepare (read-only exact plan, reviewed and released to you) then action_submit(plan_id, plan_hash, idempotency_key) (mutation, reviewed). Only declared operations on execution-enabled bindings. No shell, no arbitrary manifests.")
    cap = Capability.WRITE
    _common_tools(s, core, cap)

    @s.tool(name="action_prepare", description="Prepare an exact immutable plan for restart | update (to an explicit artifact, tags resolved to digests) | rollback (only where declared) | redeploy of a declared service binding. Read-only. The plan must be released to you before action_submit.")
    async def action_prepare(service_id: str, binding_id: str, action: str, desired_artifact: str | None = None, reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        try:
            args = ActionPrepareArgs.model_validate({"service_id": service_id, "binding_id": binding_id, "action": action, "desired_artifact": desired_artifact, "reason": reason})
        except Exception as e:  # noqa: BLE001
            raise ToolError(json.dumps({"error": "invalid_argument", "message": str(e)[:500]})) from None
        return await _submit_tool(core, cap, "action_prepare")(p, args.model_dump(mode="json"), reason)

    @s.tool(name="action_submit", description="Submit a released plan for execution through the execution review gate. Requires the exact plan_hash and a client-chosen idempotency_key (same key+payload returns the same request; a plan can be consumed once).")
    async def action_submit(plan_id: str, plan_hash: str, idempotency_key: str, reason: str | None = None) -> dict[str, Any]:
        p = await _principal(core, cap)
        args = ActionSubmitArgs(plan_id=plan_id, plan_hash=plan_hash, reason=reason)
        return await _submit_tool(core, cap, "action_submit")(p, args.model_dump(mode="json"), reason, idempotency_key)

    return s


def build_all(core: Core) -> dict[Capability, MCPServer]:
    return {Capability.READ: build_read(core), Capability.WRITE: build_write(core)}
