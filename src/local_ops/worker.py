"""Lifespan-owned durable worker: claims persisted requests, runs operations under bounded concurrency,
serializes mutations by their shared deployment boundary, and reconciles interrupted work on startup."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import traceback
from datetime import datetime, timedelta
from typing import Any

from local_ops.auth import AuthService
from local_ops.catalog import Catalog, committed_change, load_catalog
from local_ops.config import ServerConfig
from local_ops.executors.base import dispatched_intents
from local_ops.models import (
    Capability,
    ErrorCode,
    ExecutionStatus,
    OpsError,
    ResponseStatus,
    canonical_json,
    iso,
    utcnow,
)
from local_ops.operations.base import Budget, OperationContext, OperationOutcome, OperationRegistry
from local_ops.providers.base import ProviderRegistry
from local_ops.release import Sanitizer, bound_payload
from local_ops.requests import RequestService
from local_ops.storage import Database

log = logging.getLogger("local_ops.worker")


def _sanitized_traceback(sanitizer: Sanitizer, e: BaseException) -> str:
    """A useful traceback for operators, with the exception's own text scrubbed like any other
    persisted/logged material (D18); stored private_error is bounded elsewhere."""
    tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
    scrubbed, _ = sanitizer.scrub_text(tb)
    return scrubbed


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class Worker:
    def __init__(self, db: Database, config: ServerConfig, auth: AuthService, registry: OperationRegistry, providers: ProviderRegistry, sanitizer: Sanitizer, requests: RequestService, catalog_ref: dict[str, Catalog]):
        self.db = db
        self.config = config
        self.auth = auth
        self.registry = registry
        self.providers = providers
        self.sanitizer = sanitizer
        self.requests = requests
        self._catalog_ref = catalog_ref
        self.token = secrets.token_hex(6)
        self._sem = asyncio.Semaphore(config.limits.provider_concurrency_global)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._stop = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None
        self.recovery_report: list[dict[str, Any]] = []
        self._failed_catalog_head: str | None = None

    @property
    def catalog(self) -> Catalog:
        return self._catalog_ref["catalog"]

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        await self.recover()
        self._loop_task = asyncio.create_task(self._loop(), name="local-ops-worker")

    async def stop(self) -> None:
        self._stop.set()
        self.requests.wake.set()
        if self._loop_task:
            self._loop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._loop_task
        for t in list(self._tasks.values()):
            t.cancel()
        for t in list(self._tasks.values()):
            with contextlib.suppress(BaseException):
                await t

    async def _loop(self) -> None:
        tick = 0
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self.requests.wake.wait(), timeout=1.0)
            except TimeoutError:
                pass
            self.requests.wake.clear()
            tick += 1
            try:
                await self._poll_cancellations()
                await self._claim_and_dispatch()
                if tick % 5 == 0:
                    await self.reload_catalog_if_committed()
                if tick % 30 == 0:
                    await self.requests.expire_stale()
                    await self._run_schedules()
                if tick % 3600 == 0:
                    await self._prune()
            except Exception:  # noqa: BLE001
                log.exception("worker loop iteration failed")

    async def reload_catalog_if_committed(self) -> bool:
        """Reload the approved catalog when its Git HEAD moved. Commits reach the catalog only after review
        (proposals are accepted into patches a human applies and commits), so a new commit is approved
        configuration. A commit that fails to load is logged once and the loaded catalog is kept."""
        head = committed_change(self.catalog)
        if head is None or head == self._failed_catalog_head:
            return False
        try:
            fresh = load_catalog(self.catalog.root)
        except Exception:  # noqa: BLE001
            self._failed_catalog_head = head
            log.exception("catalog commit %s failed to load; keeping revision %s", head[:12], self.catalog.revision)
            return False
        previous = self.catalog.revision
        self._catalog_ref["catalog"] = fresh
        self._failed_catalog_head = None
        await self.db.app_audit("server", "system", "catalog.reload", detail=f"auto: {previous} -> {fresh.revision}")
        log.info("catalog reloaded from commit %s (revision %s)", head[:12], fresh.revision)
        return True

    async def _poll_cancellations(self) -> None:
        if not self._cancel_events:
            return
        for req in await self.db.requests_list(execution_status=[ExecutionStatus.RUNNING.value], limit=200):
            if req.get("cancel_requested_at") and req["id"] in self._cancel_events:
                self._cancel_events[req["id"]].set()

    async def _run_schedules(self) -> None:
        """Recurring bounded audit collection: a schedule is explicit approval of its read template, so its
        runs enter the queue directly (request review satisfied by the schedule) and are released to the
        schedule's audience. Nothing runs while the server is off; gaps are visible as missing runs."""
        now = utcnow()
        for s in await self.db.schedules():
            if not s["enabled"]:
                continue
            if _parse_iso(s["approval_expires_at"]) < now:
                await self.db.update_schedule(s["id"], enabled=0, last_error="approval expired; re-enable to approve the template again")
                continue
            last = _parse_iso(s["last_run_at"]) if s.get("last_run_at") else None
            if last and (now - last).total_seconds() < s["frequency_seconds"]:
                continue
            principal = await self.auth.principal(s["principal_id"])
            if principal is None or principal.revoked or not principal.has(Capability(s["capability"])):
                await self.db.update_schedule(s["id"], enabled=0, last_error="principal revoked or not granted")
                continue
            try:
                spec = self.registry.get(s["operation"])
            except OpsError:
                await self.db.update_schedule(s["id"], enabled=0, last_error="unknown operation")
                continue
            if spec.is_mutation or spec.capability == Capability.WRITE:
                await self.db.update_schedule(s["id"], enabled=0, last_error="schedules may only run read operations")
                continue
            lookback = s["lookback_seconds"]
            if last:
                lookback = max(lookback, int((now - last).total_seconds()) + 60)  # cover the sleep/outage gap
            args = dict(s["template"])
            args["lookback_minutes"] = max(1, lookback // 60)
            args["limits"] = {"max_events": int(s.get("budgets", {}).get("max_events", 500))}
            args.setdefault("reason", f"scheduled collection {s['name']}")
            try:
                sub = await self.requests.submit(principal, s["operation"], args, reason=args["reason"], audience=s.get("disclosure", {}).get("audience") or [principal.id])
                req = await self.db.request(sub.request_id)
                if req and req["execution_status"] == ExecutionStatus.PENDING_REQUEST_REVIEW.value:
                    await self.db.transition_request(sub.request_id, {ExecutionStatus.PENDING_REQUEST_REVIEW.value}, execution_status=ExecutionStatus.QUEUED.value, review_request=0, review_response=0, review_mode=f"schedule:{s['id']}")
                elif req:
                    await self.db.update_request(sub.request_id, review_response=0, review_mode=f"schedule:{s['id']}")
                await self.db.update_schedule(s["id"], last_run_at=iso(now), last_request_id=sub.request_id, last_error=None)
                await self.db.app_audit("scheduler", "system", "schedule.run", sub.request_id, s["name"])
                self.requests.wake.set()
            except OpsError as e:
                await self.db.update_schedule(s["id"], last_run_at=iso(now), last_error=e.message)

    async def _prune(self) -> None:
        r = self.config.retention
        counts = await self.db.prune(collected_days=r.collected_payload_days, released_days=r.released_evidence_days, audit_days=r.audit_event_days, request_days=r.request_metadata_days)
        if any(counts.values()):
            await self.db.app_audit("retention", "system", "prune", detail=str(counts))

    async def _claim_and_dispatch(self) -> None:
        free = self.config.limits.provider_concurrency_global - len(self._tasks)
        if free <= 0:
            return
        stopped = await self.auth.mutations_stopped()
        for req in await self.db.claim_queued(self.token, limit=free):
            spec = self.registry.get(req["operation"])
            if spec.is_mutation and stopped:
                await self.db.update_request(req["id"], execution_status=ExecutionStatus.QUEUED.value, phase="blocked_by_stop_switch", worker_token=None)
                continue
            if spec.is_mutation:
                keys = req["target_key"].split(",") if req.get("target_key") else []
                conflict = await self.db.try_lock(keys, req["id"]) if keys else None
                if conflict:
                    await self.db.update_request(req["id"], execution_status=ExecutionStatus.QUEUED.value, phase=f"waiting_for_lock:{conflict}", worker_token=None)
                    continue
            ev = asyncio.Event()
            if req.get("cancel_requested_at"):
                ev.set()
            self._cancel_events[req["id"]] = ev
            self._tasks[req["id"]] = asyncio.create_task(self._run(req, ev), name=f"op-{req['id']}")

    # ------------------------------------------------------------------ execution
    async def _run(self, req: dict[str, Any], cancel_event: asyncio.Event) -> None:
        rid = req["id"]
        spec = self.registry.get(req["operation"])
        leave_running = False
        try:
            async with self._sem:
                await self._execute(req, spec, cancel_event)
        except asyncio.CancelledError:
            if spec.is_mutation and self._stop.is_set():
                # Shutdown mid-mutation: never finalize here. Leave the request RUNNING; recover() on next
                # start reconciles a dispatched intent or requeues work that was never sent (D6).
                leave_running = True
                log.warning("mutation %s cancelled by shutdown; leaving RUNNING for recover()", rid)
            elif spec.is_mutation:
                # Cooperative request_cancel: reconcile if anything was dispatched, otherwise it is cancelled.
                intents = await self.db.intents(rid)
                if dispatched_intents(intents):
                    await self._reconcile_mutation(req, intents)
                else:
                    await self._finish(req, spec, OperationOutcome(ExecutionStatus.CANCELLED, {"cancelled": True}, public_error={"error": "cancelled", "message": "cancelled before dispatch"}), None)
            else:
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.CANCELLED, {"cancelled": True}, public_error={"error": "cancelled", "message": "cancelled"}), None)
        except Exception as e:  # noqa: BLE001
            intents = await self.db.intents(rid) if spec.is_mutation else []
            if spec.is_mutation and dispatched_intents(intents):
                # The patch/upgrade was already dispatched when wait_for_rollout/get_workload/health
                # checks/etc. raised; never fail this without a receipt -- reconcile through the same
                # path recover() uses, so the terminal status reflects the target's real state.
                log.warning("mutation %s raised after dispatch (%s); reconciling instead of failing without a receipt", rid, type(e).__name__)
                await self._reconcile_mutation(req, intents)
            else:
                scrubbed_tb = _sanitized_traceback(self.sanitizer, e)
                log.error("operation %s failed unexpectedly\n%s", rid, scrubbed_tb)
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.FAILED, {"error": {"error": "internal", "message": "operation failed"}}, public_error={"error": "provider_unavailable", "message": "operation failed"}, private_error=scrubbed_tb), None)
        finally:
            self._tasks.pop(rid, None)
            self._cancel_events.pop(rid, None)
            if spec.is_mutation and not leave_running:
                await self.db.unlock(rid)
            self.requests.wake.set()

    async def _execute(self, req: dict[str, Any], spec: Any, cancel_event: asyncio.Event) -> None:
        rid = req["id"]
        principal = await self.auth.principal(req["principal_id"])
        rev = await self.db.revision(rid)
        assert rev is not None
        # Validate current authorization immediately before dispatch.
        if principal is None or principal.revoked or not principal.has(Capability(req["capability"])):
            await self._finish(req, spec, OperationOutcome(ExecutionStatus.REJECTED, {"error": {"error": "authorization_denied"}}, public_error={"error": "authorization_denied", "message": "credential revoked or grant removed before dispatch"}), None)
            return
        if req["review_request"]:
            ap = await self.db.active_approval(rid)
            if ap is None or ap["args_hash"] != rev["args_hash"] or ap["revision"] != rev["revision"] or ap["implementation_version"] != spec.version:
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.REJECTED, {"error": {"error": "review_required"}}, public_error={"error": "review_required", "message": "no valid approval bound to the current revision"}), None)
                return
            if _parse_iso(ap["expires_at"]) < utcnow():
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.EXPIRED, {"error": {"error": "review_required"}}, public_error={"error": "review_required", "message": "approval expired"}), None)
                return
            if spec.is_mutation and ap.get("catalog_revision") != self.catalog.revision:
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.REJECTED, {"error": {"error": "plan_stale"}}, public_error={"error": "plan_stale", "message": "catalog configuration changed after approval"}), None)
                return
        if cancel_event.is_set():
            raise asyncio.CancelledError
        args = spec.args_model.model_validate(rev["args"])
        budget_seconds = self.config.limits.discovery_budget_seconds if spec.name == "discovery_scan" else (spec.budget_seconds or self.config.limits.interactive_query_budget_seconds)
        budget = Budget(deadline=utcnow() + timedelta(seconds=budget_seconds), max_bytes=self.config.limits.max_result_bytes)
        ctx = OperationContext(db=self.db, config=self.config, catalog=self.catalog, providers=self.providers, sanitizer=self.sanitizer, principal=principal, request=req, budget=budget, cancel_event=cancel_event)
        await self.db.update_request(rid, phase="running")
        try:
            handler_task: asyncio.Task[OperationOutcome] = asyncio.create_task(spec.handler(ctx, args))
            if spec.is_mutation:
                # mutations stop cooperatively between stages (executors consult ctx.cancel_event); never abort mid-dispatch
                outcome: OperationOutcome = await asyncio.wait_for(handler_task, timeout=budget_seconds + 5)
            else:
                cancel_task = asyncio.create_task(cancel_event.wait())
                done, _ = await asyncio.wait({handler_task, cancel_task}, timeout=budget_seconds + 5, return_when=asyncio.FIRST_COMPLETED)
                if handler_task in done:
                    cancel_task.cancel()
                    outcome = handler_task.result()
                else:
                    handler_task.cancel()
                    with contextlib.suppress(BaseException):
                        await handler_task
                    if cancel_task in done:
                        raise asyncio.CancelledError
                    raise TimeoutError
        except TimeoutError:
            if spec.is_mutation:
                outcome = OperationOutcome(ExecutionStatus.OUTCOME_UNKNOWN, {"error": {"error": "outcome_unknown", "message": "operation exceeded its budget after dispatch; reconcile before retrying"}}, public_error={"error": "outcome_unknown", "message": "operation timed out after dispatch"})
            else:
                outcome = OperationOutcome(ExecutionStatus.FAILED, {"error": {"error": "limit_reached", "message": "operation exceeded its time budget"}}, public_error={"error": "limit_reached", "message": "time budget exceeded"})
        except OpsError as e:
            status = ExecutionStatus.OUTCOME_UNKNOWN if e.code == ErrorCode.OUTCOME_UNKNOWN else ExecutionStatus.FAILED
            outcome = OperationOutcome(status, {"error": e.public()}, public_error=e.public(), private_error=e.private_detail)
        await self._finish(req, spec, outcome, ctx)

    async def _finish(self, req: dict[str, Any], spec: Any, outcome: OperationOutcome, ctx: OperationContext | None) -> None:
        rid = req["id"]
        candidate = dict(outcome.result)
        if outcome.coverage is not None:
            candidate["coverage"] = outcome.coverage.model_dump(mode="json")
        evidence_ids = list(ctx.evidence_ids) if ctx else []
        if evidence_ids:
            ev_rows = await self.db.evidence_for_request(rid)
            candidate["evidence"] = [{"evidence_id": e["id"], "source": e["source"], "kind": e["kind"], "summary": e["summary"], "bytes": e["bytes"]} for e in ev_rows]
        if ctx and ctx.notes:
            candidate.setdefault("notes", []).extend(ctx.notes)
        scrubbed, removed = self.sanitizer.scrub(candidate)
        bounded, truncated = bound_payload(scrubbed, self.config.limits.max_result_bytes)
        if truncated:
            bounded["truncated"] = True
        now = iso(utcnow())
        fields: dict[str, Any] = {"execution_status": outcome.execution_status.value, "finished_at": now, "phase": "finished"}
        if outcome.plan is not None:
            fields["plan_id"] = outcome.plan.get("plan_id")
        if outcome.public_error:
            fields["public_error"] = outcome.public_error
        if outcome.private_error:
            fields["private_error"] = outcome.private_error[:4000]
        if req["review_response"]:
            fields["response_status"] = ResponseStatus.PENDING_RESPONSE_REVIEW.value
        await self.db.finalize_request(rid, fields, bounded, {"removed": removed}, evidence_ids, truncated, auto_release=not req["review_response"], audience=req["audience"])
        await self.db.app_audit("worker", "system", "request.finish", rid, f"{outcome.execution_status.value} bytes={len(canonical_json(bounded))}")

    # ------------------------------------------------------------------ recovery
    async def recover(self) -> None:
        """On startup, never blindly retry a mutation found mid-flight: reconcile first."""
        self.recovery_report = []
        for req in await self.db.requests_list(execution_status=[ExecutionStatus.RUNNING.value], limit=1000):
            spec = self.registry.get(req["operation"])
            intents = await self.db.intents(req["id"])
            dispatched = dispatched_intents(intents)
            if not spec.is_mutation:
                await self.db.update_request(req["id"], execution_status=ExecutionStatus.QUEUED.value, phase="requeued_after_restart", worker_token=None)
                self.recovery_report.append({"request_id": req["id"], "action": "requeued", "reason": "read-only operation interrupted by restart"})
                continue
            if not dispatched and req.get("cancel_requested_at"):
                await self._finish(req, spec, OperationOutcome(ExecutionStatus.CANCELLED, {"cancelled": True}, public_error={"error": "cancelled", "message": "cancelled before dispatch"}), None)
                await self.db.unlock(req["id"])
                self.recovery_report.append({"request_id": req["id"], "action": "cancelled", "reason": "cancel requested and no provider intent was recorded"})
                continue
            if not dispatched:
                await self.db.unlock(req["id"])
                await self.db.update_request(req["id"], execution_status=ExecutionStatus.QUEUED.value, phase="requeued_after_restart", worker_token=None)
                self.recovery_report.append({"request_id": req["id"], "action": "requeued", "reason": "mutation interrupted before any provider intent was recorded"})
                continue
            classification = await self._reconcile_mutation(req, intents)
            self.recovery_report.append({"request_id": req["id"], "action": "reconciled", **classification})

    async def _reconcile_mutation(self, req: dict[str, Any], intents: list[dict[str, Any]]) -> dict[str, Any]:
        from local_ops.executors.base import reconcile_request  # local import to avoid cycles

        principal = await self.auth.principal(req["principal_id"])
        ctx = OperationContext(db=self.db, config=self.config, catalog=self.catalog, providers=self.providers, sanitizer=self.sanitizer, principal=principal, request=req, budget=Budget(deadline=utcnow() + timedelta(seconds=120), max_bytes=self.config.limits.max_result_bytes))  # type: ignore[arg-type]
        try:
            outcome = await reconcile_request(ctx, req, intents)
        except Exception as e:  # noqa: BLE001
            outcome = OperationOutcome(ExecutionStatus.OUTCOME_UNKNOWN, {"reconciliation": {"status": "uncertain", "error": "reconciliation failed"}}, public_error={"error": "outcome_unknown", "message": "state could not be determined after restart; explicit handling required"}, private_error=_sanitized_traceback(self.sanitizer, e))
        spec = self.registry.get(req["operation"])
        await self._finish(req, spec, outcome, ctx)
        await self.db.unlock(req["id"])
        return {"classification": outcome.execution_status.value, "detail": outcome.result.get("reconciliation")}
