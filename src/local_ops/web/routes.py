"""Reviewer routes: login, queue, request/response detail, catalog, investigation, history, settings.

Only the reviewer session cookie authenticates here; agent API keys cannot reach these routes. Every
state-changing POST requires the session's CSRF token. Pages render source-controlled strings as text."""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from local_ops.core import Core
from local_ops.models import (
    Capability,
    DataClass,
    ExecutionStatus,
    OpsError,
    ResponseStatus,
    ReviewMode,
    sha256_hex,
)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.autoescape = True
COOKIE = "lop_session"


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str, ensure_ascii=False)


TEMPLATES.env.filters["pretty"] = _pretty


def build_router(get_core: Callable[[], Core]) -> APIRouter:
    r = APIRouter()

    async def session_of(request: Request) -> dict[str, Any] | None:
        core = get_core()
        return await core.auth.session(request.cookies.get(COOKIE))

    def render(request: Request, name: str, session: dict[str, Any] | None, **ctx: Any) -> HTMLResponse:
        core = get_core()
        ctx.setdefault("session", session)
        ctx.setdefault("csrf", session["csrf_token"] if session else "")
        ctx.setdefault("catalog_name", core.catalog.meta.name)
        ctx.setdefault("execution_allowed", core.catalog.meta.execution_allowed)
        ctx.setdefault("now", datetime.now().astimezone().isoformat())
        return TEMPLATES.TemplateResponse(request, name, ctx)

    async def require(request: Request) -> dict[str, Any] | RedirectResponse:
        s = await session_of(request)
        if not s:
            return RedirectResponse("/login?next=" + request.url.path, status_code=303)
        return s

    async def check_csrf(request: Request, session: dict[str, Any], csrf: str) -> Response | None:
        expected = session.get("csrf_token") if session else None
        if not csrf or not expected or not hmac.compare_digest(csrf, expected):
            return JSONResponse({"error": "csrf", "message": "invalid CSRF token"}, status_code=403)
        return None

    async def banner(core: Core) -> dict[str, Any]:
        overrides = await core.db.active_overrides()
        yolo_settings = [s for s in await core.db.review_settings_all() if s["mode"] == ReviewMode.YOLO.value]
        names = {p.id: p.name for p in await core.auth.list_principals()}
        return {"yolo_overrides": [{**o, "principal_name": names.get(o["principal_id"], "all principals") if o["principal_id"] else "all principals"} for o in overrides], "yolo_settings": [{**s, "principal_name": names.get(s["principal_id"], s["principal_id"])} for s in yolo_settings], "mutations_stopped": await core.auth.mutations_stopped(), "pending": (await pending_state(core))[0]}

    async def pending_state(core: Core) -> tuple[dict[str, int], str]:
        """Counts of everything awaiting a reviewer decision, plus a fingerprint of the reviewable state
        (ids and statuses only) that the browser polls to know when a page is out of date."""
        req = await core.db.requests_list(execution_status=[ExecutionStatus.PENDING_REQUEST_REVIEW.value])
        resp = await core.db.requests_list(response_status=[ResponseStatus.PENDING_RESPONSE_REVIEW.value])
        active = await core.db.requests_list(execution_status=[ExecutionStatus.QUEUED.value, ExecutionStatus.RUNNING.value])
        props = [(x["id"], core.proposals.effective_status(x)) for x in await core.db.proposals(status="pending_review", limit=1000)]
        counts = {"pending_requests": len(req), "pending_responses": len(resp), "active": len(active), "pending_proposals": sum(st == "pending_review" for _, st in props), "stale_proposals": sum(st == "stale" for _, st in props)}
        state = [[x["id"], x["execution_status"], x["response_status"], x.get("phase")] for x in (*req, *resp, *active)] + [list(t) for t in props]
        return counts, sha256_hex(json.dumps(sorted(state, key=str), default=str))

    def safe_next(target: str, default: str) -> str:
        return target if target.startswith("/") and not target.startswith("//") else default

    # ------------------------------------------------------------------ auth
    @r.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        return render(request, "login.html", None, error=None, next=request.query_params.get("next", "/"))

    @r.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")) -> Response:
        core = get_core()
        sess = await core.auth.login_reviewer(username, password)
        if not sess:
            return render(request, "login.html", None, error="invalid username or password", next=next)
        target = next if next.startswith("/") and not next.startswith("//") else "/"
        resp = RedirectResponse(target, status_code=303)
        resp.set_cookie(COOKIE, sess["id"], httponly=True, samesite="strict", secure=core.config.server.tls, path="/", max_age=12 * 3600)
        return resp

    @r.post("/logout")
    async def logout(request: Request, csrf: str = Form("")) -> Response:
        s = await session_of(request)
        if s:
            if (bad := await check_csrf(request, s, csrf)) is not None:
                return bad
            await get_core().auth.logout(s["id"])
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE, path="/")
        return resp

    # ------------------------------------------------------------------ queue / home
    @r.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        return RedirectResponse("/review", status_code=303)

    @r.get("/review", response_class=HTMLResponse)
    async def queue(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        q = request.query_params
        pending_req = await core.db.requests_list(execution_status=[ExecutionStatus.PENDING_REQUEST_REVIEW.value], limit=200)
        pending_resp = await core.db.requests_list(response_status=[ResponseStatus.PENDING_RESPONSE_REVIEW.value], limit=200)
        active = await core.db.requests_list(execution_status=[ExecutionStatus.QUEUED.value, ExecutionStatus.RUNNING.value], limit=200)
        names = {p.id: p.name for p in await core.auth.list_principals()}

        def flt(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            out = rows
            if q.get("client"):
                out = [x for x in out if names.get(x["principal_id"]) == q["client"]]
            if q.get("capability"):
                out = [x for x in out if x["capability"] == q["capability"]]
            if q.get("service"):
                out = [x for x in out if q["service"] in json.dumps(x)]
            return out

        async def enrich(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            out = []
            for x in rows:
                rev = await core.db.revision(x["id"])
                x["principal_name"] = names.get(x["principal_id"], x["principal_id"])
                x["args"] = rev["args"] if rev else {}
                x["service_hint"] = (x["args"].get("service_id") or x["args"].get("source_id") or ",".join(x["args"].get("providers", [])) or "") if isinstance(x["args"], dict) else ""
                out.append(x)
            return out

        return render(request, "queue.html", s, pending_requests=await enrich(flt(pending_req)), pending_responses=await enrich(flt(pending_resp)), active=await enrich(flt(active)), clients=sorted(set(names.values())), filters=dict(q), banner=await banner(core))

    @r.get("/api/ui/queue")
    async def queue_api(request: Request) -> Response:
        s = await session_of(request)
        if not s:
            return JSONResponse({"error": "auth_required"}, status_code=401)
        counts, fingerprint = await pending_state(get_core())
        return JSONResponse({**counts, "fingerprint": fingerprint})

    # ------------------------------------------------------------------ request detail
    async def _request_context(core: Core, request_id: str) -> dict[str, Any] | None:
        req = await core.db.request(request_id)
        if not req:
            return None
        rev = await core.db.revision(request_id)
        revisions = await core.db.revisions(request_id)
        principal = await core.auth.principal(req["principal_id"])
        try:
            preview = core.requests.preview(req, rev) if rev else {}
        except OpsError as e:
            preview = {"summary": "preview unavailable", "error": e.public()}
        except Exception as e:  # noqa: BLE001
            preview = {"summary": "preview unavailable", "error": type(e).__name__}
        plan = None
        if req.get("plan_id"):
            plan = await core.db.plan(req["plan_id"])
        elif isinstance(rev["args"] if rev else None, dict) and rev["args"].get("plan_id"):  # type: ignore[index]
            plan = await core.db.plan(rev["args"]["plan_id"])  # type: ignore[index]
        result = await core.db.result(request_id)
        evidence = await core.db.evidence_for_request(request_id)
        receipt = await core.db.receipt_for_request(request_id)
        intents = await core.db.intents(request_id)
        approvals = await core.db.approvals(request_id)
        audit = await core.db.app_audit_list(100, request_id)
        mode = await core.auth.effective_mode(req["principal_id"], core.registry.get(req["operation"]).data_class)
        return {"req": req, "rev": rev, "revisions": revisions, "principal": principal, "preview": preview, "plan": plan, "result": result, "evidence": evidence, "receipt": receipt, "intents": intents, "approvals": approvals, "audit": audit, "mode": {"mode": mode[0].value, "source": mode[1], "expires": mode[2]}, "spec": core.registry.get(req["operation"])}

    @r.get("/review/{request_id}", response_class=HTMLResponse)
    async def request_detail(request: Request, request_id: str) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        ctx = await _request_context(core, request_id)
        if ctx is None:
            return render(request, "error.html", s, message="no such request")
        return render(request, "request.html", s, **ctx, banner=await banner(core))

    @r.post("/review/{request_id}/approve")
    async def approve(request: Request, request_id: str, csrf: str = Form(""), edited_args: str = Form(""), note: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        core = get_core()
        edited = None
        if edited_args.strip():
            try:
                edited = json.loads(edited_args)
            except json.JSONDecodeError:
                return render(request, "error.html", s, message="edited arguments are not valid JSON")
        try:
            await core.requests.approve(request_id, s["username"], edited_args=edited, note=note or None)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.post("/review/{request_id}/reject")
    async def reject(request: Request, request_id: str, csrf: str = Form(""), reason: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().requests.reject(request_id, s["username"], reason or "rejected")
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.post("/review/{request_id}/requeue")
    async def requeue(request: Request, request_id: str, csrf: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().requests.requeue(request_id, s["username"])
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.post("/review/{request_id}/cancel")
    async def cancel(request: Request, request_id: str, csrf: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        await get_core().requests.reviewer_cancel(request_id, s["username"])
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.post("/review/{request_id}/release")
    async def release(request: Request, request_id: str, csrf: str = Form(""), redact_paths: str = Form(""), exclude_evidence: str = Form(""), note: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        paths = [p.strip() for p in redact_paths.replace("\n", ",").split(",") if p.strip()]
        excl = [p.strip() for p in exclude_evidence.replace("\n", ",").split(",") if p.strip()]
        try:
            await get_core().requests.release(request_id, s["username"], redact_paths=paths or None, exclude_evidence_ids=excl or None, note=note or None)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.post("/review/{request_id}/withhold")
    async def withhold(request: Request, request_id: str, csrf: str = Form(""), reason: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().requests.withhold(request_id, s["username"], reason or "withheld by reviewer")
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(f"/review/{request_id}", status_code=303)

    @r.get("/review/{request_id}/evidence/{evidence_id}", response_class=HTMLResponse)
    async def evidence_view(request: Request, request_id: str, evidence_id: str) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        ev = await core.db.evidence(evidence_id)
        if not ev or ev.get("request_id") != request_id:
            return render(request, "error.html", s, message="no such evidence for this request")
        raw = core.db.evidence_bytes(ev)[:200_000].decode("utf-8", errors="replace")
        try:
            body = _pretty(json.loads(raw))
        except json.JSONDecodeError:
            body = raw
        return render(request, "evidence.html", s, ev=ev, body=body, request_id=request_id)

    # ------------------------------------------------------------------ catalog
    @r.get("/catalog", response_class=HTMLResponse)
    async def catalog(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        data = await core.catalog_read(None, include_observed=True)
        gaps = await core.catalog_gaps(None)
        return render(request, "catalog.html", s, data=data, gaps=gaps, banner=await banner(core))

    @r.get("/catalog/{service_id}", response_class=HTMLResponse)
    async def service_page(request: Request, service_id: str) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        try:
            data = await core.catalog_read(None, service_id=service_id, include_observed=True, include_body=True)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        svc = data["services"][0]
        obs = await core.db.observations(service_id=service_id)
        receipts = [x for x in await core.db.receipts(100) if x["body"].get("service_id") == service_id]
        return render(request, "service.html", s, svc=svc, observations=obs, receipts=receipts, catalog=data["catalog"], banner=await banner(core))

    @r.post("/catalog/reload")
    async def catalog_reload(request: Request, csrf: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        core = get_core()
        core.reload_catalog()
        await core.db.app_audit(s["username"], "reviewer", "catalog.reload", detail=core.catalog.revision)
        return RedirectResponse("/catalog", status_code=303)

    # ------------------------------------------------------------------ operational views (D26)
    # Read-only projections of approved catalog knowledge over observations that passed the release gate.
    # No route here calls a provider, changes state, or links evidence that was not released.
    async def _released_evidence(core: Core, ids: set[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for eid in sorted(i for i in ids if i):
            ev = await core.db.evidence(eid)
            if ev and ev.get("released_to"):
                out[eid] = {"id": eid, "request_id": ev.get("request_id"), "kind": ev.get("kind"), "summary": ev.get("summary"), "created_at": ev.get("created_at")}
        return out

    @r.get("/ops", response_class=HTMLResponse)
    async def ops_index(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops import opsview

        core = get_core()
        snap = await core.ops_snapshot(None)
        return render(request, "ops_index.html", s, envs=opsview.environments(snap), unmapped=opsview.unmapped_summary(snap), pending=snap.pending_release, observed=len(snap.index.rows), scans=snap.coverage.scans[:5], banner=await banner(core))

    @r.get("/ops/services/{service_id}", response_class=HTMLResponse)
    async def ops_service(request: Request, service_id: str) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops import opsview

        core = get_core()
        doc = core.catalog.service(service_id)
        if doc is None:
            return render(request, "error.html", s, message=f"service {service_id!r} not in catalog")
        snap = await core.ops_snapshot(None)
        view = opsview.service_view(doc, snap)
        ids = {c.get("evidence_id") for b in view["bindings"] for c in b["resources"]} | {c.get("evidence_id") for c in view["related"]}
        return render(request, "ops_service.html", s, v=view, evidence=await _released_evidence(core, {i for i in ids if i}), execution_allowed_catalog=core.catalog.meta.execution_allowed, banner=await banner(core))

    @r.get("/ops/resource", response_class=HTMLResponse)
    async def ops_resource(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops import opsview

        core = get_core()
        snap = await core.ops_snapshot(None)
        row = snap.index.get(request.query_params.get("provider", ""), request.query_params.get("key", ""))
        if row is None:
            return render(request, "error.html", s, message="no released observation with that provider and key (it may be pending review, withheld, or never observed)")
        view = opsview.resource_view(row, snap)
        ids = {row.get("evidence_id")} | {n["row"]["evidence_id"] for n in view["neighbours"] if n["row"]}
        return render(request, "ops_resource.html", s, v=view, evidence=await _released_evidence(core, {i for i in ids if i}), banner=await banner(core))

    @r.get("/ops/inventory", response_class=HTMLResponse)
    async def ops_inventory(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops import opsview

        core = get_core()
        q = request.query_params
        snap = await core.ops_snapshot(None)
        inv = opsview.inventory(snap, provider_id=q.get("provider") or None, resource_type=q.get("type") or None, account=q.get("account") or None)
        return render(request, "ops_inventory.html", s, inv=inv, filters=dict(q), banner=await banner(core))

    @r.get("/ops/access", response_class=HTMLResponse)
    async def ops_access(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops.access import AccessGraph

        core = get_core()
        person = request.query_params.get("person") or None
        report = await core.access_report(None, person=person)
        snap = await core.ops_snapshot(None)
        graph = AccessGraph.build(snap)
        accounts = [graph.account_access(a) for a in sorted(graph.accounts, key=lambda x: str(graph.accounts[x].get("name") or x))]
        return render(request, "ops_access.html", s, report=report, accounts=accounts, person=person, banner=await banner(core))

    @r.get("/ops/access/guide.md")
    async def ops_access_guide(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        from local_ops.access import guide_markdown

        person = request.query_params.get("person") or None
        report = await get_core().access_report(None, person=person)
        body = guide_markdown(report["onboarding"], report["offboarding"], person)
        return Response(body, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="aws-access-guide.md"'})

    # ------------------------------------------------------------------ investigation
    @r.get("/investigation", response_class=HTMLResponse)
    async def investigation(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        q = request.query_params
        rid = q.get("request_id") or None
        events = await core.db.audit_events(request_id=rid, source_ids=[q["source"]] if q.get("source") else None, start=q.get("start") or None, end=q.get("end") or None, limit=1000)
        if q.get("actor"):
            events = [e for e in events if q["actor"] in (e.get("actor") or "")]
        findings = await core.db.findings(request_id=rid, limit=300)
        cursors = await core.db.cursors()
        sources = sorted({e["source_id"] for e in await core.db.audit_events(limit=5000)})
        coverage = None
        if rid:
            res = await core.db.result(rid)
            coverage = (res or {}).get("candidate", {}).get("coverage") if res else None
        return render(request, "investigation.html", s, events=events, findings=findings, cursors=cursors, sources=sources, filters=dict(q), coverage=coverage, banner=await banner(core))

    @r.post("/evidence/{evidence_id}/hold")
    async def hold(request: Request, evidence_id: str, csrf: str = Form(""), hold: str = Form("1")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        await get_core().db.set_retention_hold(evidence_id, hold == "1")
        return RedirectResponse(request.headers.get("referer", "/investigation") if request.headers.get("referer", "").startswith(get_core().config.server.base_url) else "/investigation", status_code=303)

    # ------------------------------------------------------------------ catalog proposals (D24)
    async def _proposal_view(core: Core, row: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
        return {**row, "effective_status": core.proposals.effective_status(row), "principal_name": names.get(row["principal_id"], row["principal_id"])}

    @r.get("/proposals", response_class=HTMLResponse)
    async def proposals(request: Request) -> Response:
        """Proposals stacked per service, newest first. A newer open proposal for the same service supersedes
        older open ones; by default only stacks with an open (pending or stale) proposal are shown."""
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        show_all = request.query_params.get("show") == "all"
        names = {p.id: p.name for p in await core.auth.list_principals()}
        rows = [await _proposal_view(core, x, names) for x in await core.db.proposals(limit=300)]
        stacks: dict[str, list[dict[str, Any]]] = {}
        for x in rows:
            stacks.setdefault(x["service_id"], []).append(x)
        out = []
        for service_id, items in stacks.items():
            open_items = [x for x in items if x["effective_status"] in ("pending_review", "stale")]
            shown = items if show_all else open_items
            if not shown:
                continue
            head, older = shown[0], shown[1:]
            for x in older:
                x["superseded"] = x["effective_status"] in ("pending_review", "stale") and head["effective_status"] in ("pending_review", "stale")
            out.append({"service_id": service_id, "head": head, "older": older, "superseded_open": sum(1 for x in older if x.get("superseded"))})
        open_count = sum(1 for x in rows if x["effective_status"] in ("pending_review", "stale"))
        return render(request, "proposals.html", s, stacks=out, show_all=show_all, open_count=open_count, total=len(rows), banner=await banner(core))

    @r.get("/proposals/{proposal_id}", response_class=HTMLResponse)
    async def proposal_detail(request: Request, proposal_id: str) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        row = await core.db.proposal(proposal_id)
        if row is None:
            return render(request, "error.html", s, message="no such proposal")
        names = {p.id: p.name for p in await core.auth.list_principals()}
        return render(request, "proposal.html", s, p=await _proposal_view(core, row, names), banner=await banner(core))

    @r.post("/proposals/{proposal_id}/accept")
    async def proposal_accept(request: Request, proposal_id: str, csrf: str = Form(""), note: str = Form(""), next: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().proposals.accept(proposal_id, s["username"], note or None)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(safe_next(next, f"/proposals/{proposal_id}"), status_code=303)

    @r.post("/proposals/{proposal_id}/reject")
    async def proposal_reject(request: Request, proposal_id: str, csrf: str = Form(""), note: str = Form(""), next: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().proposals.reject(proposal_id, s["username"], note or None)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse(safe_next(next, f"/proposals/{proposal_id}"), status_code=303)

    @r.post("/proposals/{proposal_id}/reject-superseded")
    async def proposal_reject_superseded(request: Request, proposal_id: str, csrf: str = Form(""), next: str = Form("")) -> Response:
        """Reject every open proposal for the same service made before this one."""
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        core = get_core()
        row = await core.db.proposal(proposal_id)
        if row is None:
            return render(request, "error.html", s, message="no such proposal")
        for x in await core.db.proposals(service_id=row["service_id"], status="pending_review", limit=1000):
            if x["id"] != proposal_id and x["created_at"] < row["created_at"]:
                await core.proposals.reject(x["id"], s["username"], f"superseded by {proposal_id}")
        return RedirectResponse(safe_next(next, "/proposals"), status_code=303)

    # ------------------------------------------------------------------ history & settings
    @r.get("/history", response_class=HTMLResponse)
    async def history(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        names = {p.id: p.name for p in await core.auth.list_principals()}
        reqs = await core.db.requests_list(limit=300)
        for x in reqs:
            x["principal_name"] = names.get(x["principal_id"], x["principal_id"])
        return render(request, "history.html", s, requests=reqs, receipts=await core.db.receipts(100), audit=await core.db.app_audit_list(300), recovery=core.worker.recovery_report, banner=await banner(core))

    @r.get("/settings", response_class=HTMLResponse)
    async def settings(request: Request) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        core = get_core()
        principals = await core.auth.list_principals()
        effective = []
        for p in principals:
            for dc in DataClass:
                if not p.has(dc.capability):
                    continue  # never offer a review mode for a capability the client does not hold
                m, src, exp = await core.auth.effective_mode(p.id, dc)
                effective.append({"principal": p, "capability": dc.capability.value, "data_class": dc.value, "mode": m.value, "source": src, "expires": exp})
        avail = []
        for a in core.providers.adapters.values():
            avd: dict[str, Any]
            try:
                avd = (await a.check_availability(live=False)).model_dump()
            except Exception as e:  # noqa: BLE001
                avd = {"available": False, "reason": type(e).__name__}
            avail.append({"desc": a.describe().model_dump(), "availability": avd})
        return render(request, "settings.html", s, principals=principals, effective=effective, overrides=await core.db.active_overrides(), providers=avail, schedules=await core.db.schedules(), locks=await core.db.locks(), stopped=await core.auth.mutations_stopped(), modes=[m.value for m in ReviewMode], data_classes=[d.value for d in DataClass], banner=await banner(core), config=core.config, catalog=core.catalog)

    @r.post("/settings/mode")
    async def set_mode(request: Request, csrf: str = Form(""), principal_id: str = Form(...), data_class: str = Form(...), mode: str = Form(...)) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().auth.set_mode(principal_id, DataClass(data_class), ReviewMode(mode), s["username"])
        except (OpsError, ValueError) as e:
            return render(request, "error.html", s, message=str(getattr(e, "message", e)))
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/yolo")
    async def add_yolo(request: Request, csrf: str = Form(""), principal_id: str = Form(""), data_class: str = Form(""), minutes: int = Form(30)) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().auth.add_yolo_override(principal_id or None, DataClass(data_class) if data_class else None, minutes, s["username"])
        except (OpsError, ValueError) as e:
            return render(request, "error.html", s, message=str(getattr(e, "message", e)))
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/yolo/{override_id}/revoke")
    async def revoke_yolo(request: Request, override_id: str, csrf: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        await get_core().auth.revoke_override(override_id, s["username"])
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/stop")
    async def stop_switch(request: Request, csrf: str = Form(""), stopped: str = Form("1")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        await get_core().auth.set_mutations_stopped(stopped == "1", s["username"])
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/keys/{name}/revoke")
    async def revoke_key(request: Request, name: str, csrf: str = Form("")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        try:
            await get_core().auth.revoke_key(name)
        except OpsError as e:
            return render(request, "error.html", s, message=e.message)
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/providers/{provider_id}/check")
    async def provider_check(request: Request, provider_id: str, csrf: str = Form("")) -> Response:
        """Explicit developer action: live connection check (never runs at startup)."""
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        core = get_core()
        a = core.providers.get(provider_id)
        if a is None:
            return render(request, "error.html", s, message="unknown provider")
        try:
            av = await a.check_availability(live=True)
            result = av.model_dump()
        except Exception as e:  # noqa: BLE001
            result = {"available": False, "reason": type(e).__name__}
        await core.db.app_audit(s["username"], "reviewer", "provider.live_check", detail=f"{provider_id}: {result.get('available')} {result.get('reason') or ''}")
        return render(request, "provider_check.html", s, provider_id=provider_id, result=result)

    @r.post("/settings/schedules")
    async def add_schedule(request: Request, csrf: str = Form(""), name: str = Form(...), principal_id: str = Form(...), source_ids: str = Form(...), frequency_minutes: int = Form(60), lookback_minutes: int = Form(120), approval_days: int = Form(7), max_events: int = Form(500), enabled: str = Form("1")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        from datetime import timedelta

        from local_ops.models import utcnow

        core = get_core()
        await core.db.insert_schedule({"name": name, "principal_id": principal_id, "capability": Capability.READ.value, "operation": "investigation_run", "template": {"recipe": "identity_and_deployment_audit", "sources": [x.strip() for x in source_ids.split(",") if x.strip()]}, "frequency_seconds": max(60, frequency_minutes * 60), "lookback_seconds": max(60, lookback_minutes * 60), "budgets": {"max_events": max_events}, "approval_expires_at": utcnow() + timedelta(days=max(1, approval_days)), "disclosure": {"audience": [principal_id]}, "enabled": enabled == "1", "created_by": s["username"]})
        await core.db.app_audit(s["username"], "reviewer", "schedule.create", detail=name)
        return RedirectResponse("/settings", status_code=303)

    @r.post("/settings/schedules/{schedule_id}/toggle")
    async def toggle_schedule(request: Request, schedule_id: str, csrf: str = Form(""), enabled: str = Form("0")) -> Response:
        s = await require(request)
        if isinstance(s, Response):
            return s
        if (bad := await check_csrf(request, s, csrf)) is not None:
            return bad
        await get_core().db.update_schedule(schedule_id, enabled=int(enabled == "1"))
        return RedirectResponse("/settings", status_code=303)

    return r
