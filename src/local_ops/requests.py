"""Request lifecycle: submission, idempotency, approval binding, cancellation, release gate and
authorized result retrieval. MCP and browser routes both call this service; there is no other path."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError

from local_ops.auth import AuthService, Principal
from local_ops.catalog import Catalog
from local_ops.config import ServerConfig
from local_ops.models import (
    Capability,
    DataClass,
    ErrorCode,
    ExecutionStatus,
    OpsError,
    Page,
    RequestStatusResult,
    ResponseStatus,
    ReviewMode,
    SubmissionResult,
    canonical_json,
    iso,
    sha256_hex,
    utcnow,
)
from local_ops.operations.base import OperationRegistry, OperationSpec
from local_ops.release import apply_redaction, derived_disclosable
from local_ops.storage import Database, PlanConflict, new_id


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class RequestService:
    def __init__(self, db: Database, config: ServerConfig, auth: AuthService, registry: OperationRegistry, catalog_ref: dict[str, Catalog]):
        self.db = db
        self.config = config
        self.auth = auth
        self.registry = registry
        self._catalog_ref = catalog_ref  # mutable holder so reloads propagate
        self.wake = asyncio.Event()

    @property
    def catalog(self) -> Catalog:
        return self._catalog_ref["catalog"]

    def review_url(self, request_id: str) -> str:
        return f"{self.config.server.base_url}/review/{request_id}"

    # ------------------------------------------------------------------ submission
    async def submit(self, principal: Principal, operation: str, args: dict[str, Any], *, reason: str | None = None, idempotency_key: str | None = None, audience: list[str] | None = None) -> SubmissionResult:
        spec = self.registry.get(operation)
        principal.require(spec.capability)
        try:
            parsed = spec.args_model.model_validate(args)
        except ValidationError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "invalid arguments", data={"errors": [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}) from e
        canonical = canonical_json(parsed.model_dump(mode="json"))
        args_hash = sha256_hex(canonical)
        if spec.is_mutation and not idempotency_key:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "mutations require an idempotency_key")
        if spec.is_mutation and not self.catalog.meta.execution_allowed:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "this catalog does not allow execution (catalog.execution_allowed is false)")
        idem_hash = sha256_hex(f"{principal.id}:{operation}:{args_hash}") if idempotency_key else None
        if idempotency_key:
            existing = await self.db.request_by_idempotency(principal.id, idempotency_key)
            if existing:
                if existing["idempotency_hash"] != idem_hash:
                    raise OpsError(ErrorCode.CONFLICT, "idempotency_key was already used with a different payload", data={"request_id": existing["id"]})
                return SubmissionResult(
                    request_id=existing["id"], operation=operation, execution_status=ExecutionStatus(existing["execution_status"]),
                    response_status=ResponseStatus(existing["response_status"]), review_url=self.review_url(existing["id"]), existing=True,
                )
        mode, _source, _exp = await self.auth.effective_mode(principal.id, spec.data_class)
        review_request = mode.reviews_request
        review_response = mode.reviews_response
        target_key = None
        if spec.target_keys is not None:
            keys = spec.target_keys(parsed, self.catalog, self.config)
            target_key = ",".join(sorted(keys)) if keys else None
        plan_id = getattr(parsed, "plan_id", None)
        if spec.pre_submit is not None:
            extra = await spec.pre_submit(parsed, principal, self.db, self.catalog)
            if extra.get("target_keys"):
                target_key = ",".join(sorted(extra["target_keys"]))
            plan_id = extra.get("plan_id", plan_id)
        rid = new_id("req")
        row = {
            "id": rid, "principal_id": principal.id, "capability": spec.capability.value, "operation": operation, "reason": reason,
            "execution_status": (ExecutionStatus.PENDING_REQUEST_REVIEW if review_request else ExecutionStatus.QUEUED).value,
            "response_status": ResponseStatus.UNAVAILABLE.value, "phase": None, "idempotency_key": idempotency_key, "idempotency_hash": idem_hash,
            "review_request": review_request, "review_response": review_response, "review_mode": mode.value, "catalog_revision": self.catalog.revision,
            "target_key": target_key, "plan_id": plan_id, "audience": audience or [principal.id],
        }
        # Plan consumption (for action_submit) and the request insert happen in one transaction keyed
        # on the real request id: either a concurrent identical submission (same idempotency_key) is
        # already committed and we replay it untouched, or we consume the plan and insert together, so
        # a plan can never be left consumed by a request that was never created (lost-insert strands it)
        # nor claimed by a placeholder a later request can't reclaim.
        try:
            existing = await self.db.insert_request_with_plan(
                row, canonical, args_hash, idempotency_key=idempotency_key, consume_plan_id=plan_id if spec.is_mutation else None,
            )
        except PlanConflict as e:
            raise OpsError(ErrorCode.CONFLICT, "plan was already submitted; prepare a new plan") from e
        if existing is not None:
            if idem_hash is not None and existing["idempotency_hash"] != idem_hash:
                raise OpsError(ErrorCode.CONFLICT, "idempotency_key was already used with a different payload", data={"request_id": existing["id"]})
            return SubmissionResult(
                request_id=existing["id"], operation=operation, execution_status=ExecutionStatus(existing["execution_status"]),
                response_status=ResponseStatus(existing["response_status"]), review_url=self.review_url(existing["id"]), existing=True,
            )
        await self.db.app_audit(principal.name, "agent", "request.submit", rid, f"{operation} mode={mode.value}")
        self.wake.set()
        return SubmissionResult(
            request_id=rid, operation=operation, execution_status=ExecutionStatus(str(row["execution_status"])),
            response_status=ResponseStatus.UNAVAILABLE, review_url=self.review_url(rid),
        )

    # ------------------------------------------------------------------ status / result (agent)
    async def _authorized_request(self, principal: Principal, request_id: str) -> dict[str, Any]:
        if principal.revoked:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "credential revoked")
        req = await self.db.request(request_id)
        if not req or (req["principal_id"] != principal.id and principal.id not in req["audience"]):
            raise OpsError(ErrorCode.NOT_FOUND, "no such request for this principal")
        spec = self.registry.get(req["operation"])
        principal.require(spec.capability)
        return req

    async def status(self, principal: Principal, request_id: str) -> RequestStatusResult:
        req = await self._authorized_request(principal, request_id)
        public_error = None
        if req.get("public_error") and req["response_status"] == ResponseStatus.RELEASED.value:
            public_error = req["public_error"]
        elif req.get("public_error") and req["public_error"].get("error") in ("authorization_denied", "plan_stale", "review_required", "stopped", "limit_reached", "conflict", "unsupported_operation", "invalid_argument"):
            public_error = {"error": req["public_error"]["error"]}  # typed code only; never provider text
        es = ExecutionStatus(str(req["execution_status"]))
        return RequestStatusResult(
            request_id=req["id"], operation=req["operation"], capability=Capability(req["capability"]), execution_status=es,
            response_status=ResponseStatus(req["response_status"]), review_url=self.review_url(req["id"]),
            submitted_at=_parse_iso(req["created_at"]), updated_at=_parse_iso(req["updated_at"]), revision=req["current_revision"],
            poll_after_ms=500 if es in (ExecutionStatus.RUNNING, ExecutionStatus.QUEUED) else 2000, public_error=public_error,
        )

    async def result(self, principal: Principal, request_id: str, page: Page | None = None) -> dict[str, Any]:
        req = await self._require_released(principal, request_id)
        res = await self.db.result(request_id)
        if not res or res.get("released") is None:
            raise OpsError(ErrorCode.REVIEW_REQUIRED, "released projection missing")
        projection = dict(res["released"])
        page = page or Page()
        items = projection.get("items")
        if isinstance(items, list):
            total = len(items)
            projection["items"] = items[page.offset : page.offset + page.limit]
            projection["page"] = {"offset": page.offset, "limit": page.limit, "total": total, "has_more": page.offset + page.limit < total}
        projection["request_id"] = request_id
        projection["execution_status"] = req["execution_status"]
        projection["released_at"] = res.get("released_at")
        if res.get("redaction"):
            projection["redaction_record"] = {"paths": res["redaction"].get("paths", []), "note": res["redaction"].get("note"), "excluded_evidence_count": len(res["redaction"].get("excluded_evidence_ids", []))}
        return projection

    async def cancel(self, principal: Principal, request_id: str) -> RequestStatusResult:
        req = await self._authorized_request(principal, request_id)
        es = ExecutionStatus(req["execution_status"])
        if es in (ExecutionStatus.PENDING_REQUEST_REVIEW, ExecutionStatus.QUEUED):
            ok = await self.db.transition_request(
                request_id, (ExecutionStatus.PENDING_REQUEST_REVIEW.value, ExecutionStatus.QUEUED.value),
                execution_status=ExecutionStatus.CANCELLED.value, cancel_requested_at=iso(utcnow()), finished_at=iso(utcnow()), phase="cancelled_before_dispatch",
            )
            if ok:
                await self.db.app_audit(principal.name, "agent", "request.cancel", request_id, "before dispatch")
                return await self.status(principal, request_id)
            # lost the race to the worker claiming it for dispatch; re-read and fall through to the
            # running behaviour below instead of reporting "cancelled before dispatch" for a request
            # that is actually running.
            refreshed = await self.db.request(request_id)
            assert refreshed is not None
            es = ExecutionStatus(refreshed["execution_status"])
        if es == ExecutionStatus.RUNNING:
            ok = await self.db.transition_request(request_id, (ExecutionStatus.RUNNING.value,), cancel_requested_at=iso(utcnow()))
            if not ok:
                raise OpsError(ErrorCode.CONFLICT, "request finished before the cancellation could be applied")
            await self.db.app_audit(principal.name, "agent", "request.cancel", request_id, "after dispatch; stages will stop where possible")
            self.wake.set()
            return await self.status(principal, request_id)
        raise OpsError(ErrorCode.CONFLICT, f"request is already {es.value}")

    async def evidence(self, principal: Principal, evidence_id: str, max_bytes: int = 200_000) -> dict[str, Any]:
        if principal.revoked:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "credential revoked")
        ev = await self.db.evidence(evidence_id)
        if not ev or principal.id not in ev["released_to"]:
            raise OpsError(ErrorCode.NOT_FOUND, "no such evidence for this principal")
        if ev.get("request_id"):
            req = await self.db.request(ev["request_id"])
            if req:
                self.registry.get(req["operation"])
                principal.require(Capability(req["capability"]))
        raw = self.db.evidence_bytes(ev)
        truncated = len(raw) > max_bytes
        return {
            "evidence_id": ev["id"], "source": ev["source"], "kind": ev["kind"], "created_at": ev["created_at"], "bytes": ev["bytes"],
            "summary": ev["summary"], "sanitization": ev["sanitization"], "truncated": truncated,
            "content": raw[:max_bytes].decode("utf-8", errors="replace"),
        }

    async def _require_released(self, principal: Principal, request_id: str) -> dict[str, Any]:
        req = await self._authorized_request(principal, request_id)
        if req["response_status"] != ResponseStatus.RELEASED.value:
            raise OpsError(ErrorCode.REVIEW_REQUIRED if req["response_status"] in (ResponseStatus.PENDING_RESPONSE_REVIEW.value, ResponseStatus.UNAVAILABLE.value) else ErrorCode.AUTHORIZATION_DENIED,
                           {"pending_response_review": "response is awaiting reviewer release", "unavailable": "no response is available yet", "withheld": "the response was withheld by the reviewer"}[req["response_status"]],
                           data={"response_status": req["response_status"]})
        return req

    async def findings_for(self, principal: Principal, request_id: str | None, limit: int) -> list[dict[str, Any]]:
        """Findings are derived data: disclosed only when their contributing evidence is released."""
        if request_id:
            await self._require_released(principal, request_id)
        rows = await self.db.findings(request_id=request_id, audience=principal.id, limit=limit)
        out = []
        for r in rows:
            contributing = []
            for eid in r["evidence_ids"]:
                ev = await self.db.evidence(eid)
                contributing.append(ev["released_to"] if ev else [])
            if derived_disclosable(contributing, principal.id):
                out.append(r["body"])
        return out

    # ------------------------------------------------------------------ reviewer actions
    async def approve(self, request_id: str, reviewer: str, *, edited_args: dict[str, Any] | None = None, note: str | None = None) -> dict[str, Any]:
        req = await self.db.request(request_id)
        if not req:
            raise OpsError(ErrorCode.NOT_FOUND, "no such request")
        if req["execution_status"] != ExecutionStatus.PENDING_REQUEST_REVIEW.value:
            raise OpsError(ErrorCode.CONFLICT, f"request is {req['execution_status']}, not pending request review")
        spec = self.registry.get(req["operation"])
        rev = await self.db.revision(request_id)
        assert rev is not None
        if edited_args is not None:
            try:
                parsed = spec.args_model.model_validate(edited_args)
            except ValidationError as e:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "edited arguments are invalid", data={"errors": [x["msg"] for x in e.errors()]}) from e
            if getattr(parsed, "saved_query", None) and sha256_hex(canonical_json(parsed.model_dump(mode="json"))) != rev["args_hash"]:
                parsed = parsed.model_copy(update={"saved_query": None})  # edited: no longer the catalog template
            canonical = canonical_json(parsed.model_dump(mode="json"))
            new_hash = sha256_hex(canonical)
            if new_hash != rev["args_hash"]:
                if spec.is_mutation:
                    raise OpsError(ErrorCode.INVALID_ARGUMENT, "mutation plans cannot be edited; reject and prepare a new plan")
                revision = await self.db.add_revision(request_id, canonical, new_hash, reviewer, note or "edited by reviewer")
                rev = await self.db.revision(request_id, revision)
                assert rev is not None
                if spec.target_keys is not None:
                    keys = spec.target_keys(parsed, self.catalog, self.config)
                    await self.db.update_request(request_id, target_key=",".join(sorted(keys)) if keys else None)
        principal = await self.auth.principal(req["principal_id"])
        if principal is None or principal.revoked or not principal.has(spec.capability):
            await self.db.transition_request(
                request_id, (ExecutionStatus.PENDING_REQUEST_REVIEW.value,),
                execution_status=ExecutionStatus.REJECTED.value, finished_at=iso(utcnow()), public_error={"error": "authorization_denied", "message": "credential revoked or grant removed"},
            )
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "submitting credential is revoked or no longer granted; request rejected")
        plan_hash = rev["args"].get("plan_hash") if isinstance(rev["args"], dict) else None
        # Approval insert and the PENDING_REQUEST_REVIEW -> QUEUED transition are one atomic,
        # conditional operation: if a reject or cancel landed on this request during the awaits above,
        # the CAS fails, no approval row is written, and the request keeps whatever status it already
        # moved to (never a fresh, unopposed approval on a rejected/cancelled request).
        aid = await self.db.approve_transition(request_id, (ExecutionStatus.PENDING_REQUEST_REVIEW.value,), {
            "request_id": request_id, "revision": rev["revision"], "args_hash": rev["args_hash"], "principal_id": req["principal_id"], "capability": req["capability"],
            "implementation_version": spec.version, "catalog_revision": self.catalog.revision, "plan_hash": plan_hash, "approved_by": reviewer,
            "expires_at": utcnow() + timedelta(minutes=self.config.review.approval_ttl_minutes),
        })
        if aid is None:
            cur = await self.db.request(request_id)
            raise OpsError(ErrorCode.CONFLICT, f"request is {cur['execution_status'] if cur else 'gone'}, not pending request review")
        await self.db.app_audit(reviewer, "reviewer", "request.approve", request_id, f"revision {rev['revision']}" + (" (edited)" if edited_args is not None else ""))
        self.wake.set()
        return {"request_id": request_id, "revision": rev["revision"], "execution_status": ExecutionStatus.QUEUED.value}

    async def reject(self, request_id: str, reviewer: str, reason: str) -> None:
        req = await self.db.request(request_id)
        if not req:
            raise OpsError(ErrorCode.NOT_FOUND, "no such request")
        if req["execution_status"] not in (ExecutionStatus.PENDING_REQUEST_REVIEW.value, ExecutionStatus.QUEUED.value):
            raise OpsError(ErrorCode.CONFLICT, f"request is {req['execution_status']}")
        ok = await self.db.transition_with_approval_invalidation(
            request_id, (ExecutionStatus.PENDING_REQUEST_REVIEW.value, ExecutionStatus.QUEUED.value),
            {"execution_status": ExecutionStatus.REJECTED.value, "finished_at": iso(utcnow()), "phase": "rejected", "public_error": {"error": "review_required", "message": "rejected by reviewer"}},
            "rejected by reviewer",
        )
        if not ok:
            cur = await self.db.request(request_id)
            raise OpsError(ErrorCode.CONFLICT, f"request is {cur['execution_status'] if cur else 'gone'}")
        await self.db.app_audit(reviewer, "reviewer", "request.reject", request_id, reason)

    async def requeue(self, request_id: str, reviewer: str) -> None:
        """Send a queued request back to request review (e.g. after a mode tightening)."""
        req = await self.db.request(request_id)
        if not req or req["execution_status"] != ExecutionStatus.QUEUED.value:
            raise OpsError(ErrorCode.CONFLICT, "only queued requests can be requeued for review")
        ok = await self.db.transition_with_approval_invalidation(
            request_id, (ExecutionStatus.QUEUED.value,),
            {"execution_status": ExecutionStatus.PENDING_REQUEST_REVIEW.value, "review_request": 1},
            "requeued by reviewer",
        )
        if not ok:
            raise OpsError(ErrorCode.CONFLICT, "request is no longer queued")
        await self.db.app_audit(reviewer, "reviewer", "request.requeue", request_id)

    async def release(self, request_id: str, reviewer: str, *, redact_paths: list[str] | None = None, exclude_evidence_ids: list[str] | None = None, note: str | None = None) -> dict[str, Any]:
        req = await self.db.request(request_id)
        if not req:
            raise OpsError(ErrorCode.NOT_FOUND, "no such request")
        if req["response_status"] not in (ResponseStatus.PENDING_RESPONSE_REVIEW.value, ResponseStatus.WITHHELD.value):
            raise OpsError(ErrorCode.CONFLICT, f"response is {req['response_status']}")
        res = await self.db.result(request_id)
        if not res or res.get("candidate") is None:
            raise OpsError(ErrorCode.CONFLICT, "no candidate response to release")
        principal = await self.auth.principal(req["principal_id"])
        if principal is None or principal.revoked:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "originating credential is revoked; nothing can be released to it")
        projection = dict(res["candidate"])
        redaction: dict[str, Any] | None = None
        if redact_paths or exclude_evidence_ids:
            projection, applied = apply_redaction(projection, redact_paths or [])
            excluded = set(exclude_evidence_ids or [])
            if excluded:
                projection["evidence"] = [e for e in projection.get("evidence", []) if e.get("evidence_id") not in excluded]
            if applied:
                # underlying fragments stay private: the agent receives only this redacted projection
                projection["evidence"] = []
                projection["evidence_withheld_due_to_redaction"] = True
            redaction = {"paths": applied, "excluded_evidence_ids": sorted(excluded), "note": note, "by": reviewer, "at": iso(utcnow())}
        await self.db.release_result(request_id, projection, reviewer, redaction, req["audience"])
        await self.db.app_audit(reviewer, "reviewer", "response.release" if not redaction else "response.redact_release", request_id, note)
        return projection

    async def withhold(self, request_id: str, reviewer: str, reason: str) -> None:
        req = await self.db.request(request_id)
        if not req:
            raise OpsError(ErrorCode.NOT_FOUND, "no such request")
        if req["response_status"] not in (ResponseStatus.PENDING_RESPONSE_REVIEW.value, ResponseStatus.RELEASED.value):
            raise OpsError(ErrorCode.CONFLICT, f"response is {req['response_status']}")
        await self.db.withhold_result(request_id, reviewer, reason)
        await self.db.app_audit(reviewer, "reviewer", "response.withhold", request_id, reason)

    async def reviewer_cancel(self, request_id: str, reviewer: str) -> None:
        req = await self.db.request(request_id)
        if not req:
            raise OpsError(ErrorCode.NOT_FOUND, "no such request")
        es = ExecutionStatus(req["execution_status"])
        handled = False
        if es in (ExecutionStatus.PENDING_REQUEST_REVIEW, ExecutionStatus.QUEUED):
            handled = await self.db.transition_request(
                request_id, (ExecutionStatus.PENDING_REQUEST_REVIEW.value, ExecutionStatus.QUEUED.value),
                execution_status=ExecutionStatus.CANCELLED.value, cancel_requested_at=iso(utcnow()), finished_at=iso(utcnow()),
            )
            if not handled:
                # lost the race to the worker claiming it for dispatch; fall through to the running case
                req = await self.db.request(request_id)
                assert req is not None
                es = ExecutionStatus(req["execution_status"])
        if not handled and es == ExecutionStatus.RUNNING:
            if await self.db.transition_request(request_id, (ExecutionStatus.RUNNING.value,), cancel_requested_at=iso(utcnow())):
                self.wake.set()
        await self.db.app_audit(reviewer, "reviewer", "request.cancel", request_id)

    # ------------------------------------------------------------------ previews (no provider I/O)
    def preview(self, req: dict[str, Any], rev: dict[str, Any]) -> dict[str, Any]:
        spec: OperationSpec = self.registry.get(req["operation"])
        parsed = spec.args_model.model_validate(rev["args"])
        desc = spec.describe(parsed, self.catalog, self.config)
        desc.setdefault("operation", spec.name)
        desc.setdefault("capability", spec.capability.value)
        desc.setdefault("effect", spec.effect.value)
        desc["implementation_version"] = spec.version
        desc["catalog_revision"] = self.catalog.revision
        desc["args_hash"] = rev["args_hash"]
        return desc

    async def expire_stale(self) -> int:
        """Expire approvals and pending requests past their TTL."""
        n = 0
        now = utcnow()
        for req in await self.db.requests_list(execution_status=[ExecutionStatus.PENDING_REQUEST_REVIEW.value, ExecutionStatus.QUEUED.value], limit=1000):
            created = _parse_iso(req["created_at"])
            ttl = timedelta(hours=24)
            if req["execution_status"] == ExecutionStatus.QUEUED.value and req["review_request"]:
                ap = await self.db.active_approval(req["id"])
                if ap and _parse_iso(ap["expires_at"]) < now:
                    # conditional on still QUEUED: a worker may have claimed it for dispatch (or a
                    # reviewer acted on it) between the batch read above and this write.
                    if await self.db.transition_with_approval_invalidation(
                        req["id"], (ExecutionStatus.QUEUED.value,),
                        {"execution_status": ExecutionStatus.EXPIRED.value, "finished_at": iso(now), "public_error": {"error": "review_required", "message": "approval expired before dispatch"}},
                        "approval expired",
                    ):
                        n += 1
                    continue
            if now - created > ttl:
                if await self.db.transition_request(req["id"], (req["execution_status"],), execution_status=ExecutionStatus.EXPIRED.value, finished_at=iso(now), public_error={"error": "review_required", "message": "request expired"}):
                    n += 1
        return n

    async def mode_for(self, principal_id: str, data_class: DataClass) -> ReviewMode:
        mode, _, _ = await self.auth.effective_mode(principal_id, data_class)
        return mode
