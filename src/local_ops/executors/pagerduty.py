"""Reviewed PagerDuty configuration executor.

The adapter owns all HTTP and credential handling.  This executor only turns the
typed catalog configuration into one exact provider mutation and treats an
interrupted write as unknown until the exact resource can be re-read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from local_ops.catalog import Binding, OperationConfig, ServiceSpec
from local_ops.executors.base import intent_record, new_plan, receipt_from
from local_ops.models import (
    ActionPlan,
    ErrorCode,
    ExecutionStatus,
    HealthCheckResult,
    OpsError,
    Receipt,
    canonical_json,
    sha256_hex,
    utcnow,
)
from local_ops.operations.base import OperationContext
from local_ops.pagerduty_contracts import PagerDutyConfiguration


def _value(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _dump(value: Any) -> dict[str, Any]:
    return value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)


def _domain(item: dict[str, Any]) -> str | None:
    url = item.get("html_url")
    host = urlparse(url).hostname if isinstance(url, str) else None
    return host.lower() if host else None


def _reference_ids(policy: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for rule in policy.get("escalation_rules", policy.get("rules", [])) or []:
        for target in rule.get("targets", []) or []:
            if target.get("type") in {"schedule_reference", "schedule_v3_reference"} and target.get("id"):
                found.add(str(target["id"]))
    return found


class PagerDutyConfigurationExecutor:
    name = "pagerduty_configuration"

    def _adapter(self, ctx: OperationContext, binding: Binding) -> Any:
        adapter = ctx.providers.get(binding.provider_id)
        if adapter is None or getattr(adapter, "kind", None) != "pagerduty":
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} does not reference a PagerDuty provider")
        return adapter

    def _target(self, binding: Binding) -> Any:
        target = getattr(binding, "pagerduty_target", None)
        if target is None:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"binding {binding.id} has no PagerDuty target")
        return target

    @staticmethod
    def _verify(item: dict[str, Any], target: Any, *, id_required: bool = True) -> None:
        wanted_id, wanted_name, domain = _value(target, "id"), _value(target, "name"), _value(target, "account_domain")
        if id_required and item.get("id") != wanted_id:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty resource id differs from the approved target")
        if item.get("name") != wanted_name:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty resource name differs from the approved target")
        if _domain(item) != domain:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "PagerDuty resource belongs to a different account domain")

    async def _get(self, ctx: OperationContext, binding: Binding, target: Any) -> dict[str, Any] | None:
        rid = _value(target, "id")
        if not rid:
            return None
        item = await self._adapter(ctx, binding).configuration_get(_value(target, "resource_type"), rid, ctx.budget, execution=True)
        if item is not None:
            self._verify(item, target)
        return item

    async def _complete(self, ctx: OperationContext, binding: Binding, resource_type: str) -> list[dict[str, Any]]:
        return await self._adapter(ctx, binding).configuration_list(resource_type, ctx.budget, execution=True)

    async def _validate_references(self, ctx: OperationContext, binding: Binding, desired: dict[str, Any]) -> None:
        kind = desired["kind"]
        if kind == "schedule":
            users = {str(x.get("id")): x for x in await self._complete(ctx, binding, "user")}
            missing = [uid for uid in desired["user_ids"] if uid not in users]
            if missing:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "a configured PagerDuty user is absent from the execution account")
            if any(_domain(users[uid]) != _value(self._target(binding), "account_domain") for uid in desired["user_ids"]):
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "a configured PagerDuty user belongs to a different account domain")
        elif kind == "escalation_policy":
            schedules = {str(x.get("id")): x for x in await self._complete(ctx, binding, "schedule")}
            users = {str(x.get("id")): x for x in await self._complete(ctx, binding, "user")}
            for rule in desired["rules"]:
                for ref in rule["targets"]:
                    allowed = schedules if ref["type"] == "schedule_reference" else users
                    if ref["id"] not in allowed:
                        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "a configured PagerDuty escalation target is absent from the execution account")
                    if _domain(allowed[ref["id"]]) != _value(self._target(binding), "account_domain"):
                        raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "a configured PagerDuty escalation target belongs to a different account domain")
        elif kind == "service_routing":
            policies = {str(x.get("id")): x for x in await self._complete(ctx, binding, "escalation_policy")}
            if desired["escalation_policy_id"] not in policies:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "configured escalation policy is absent from the execution account")
            if _domain(policies[desired["escalation_policy_id"]]) != _value(self._target(binding), "account_domain"):
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "configured escalation policy belongs to a different account domain")
        elif kind == "incident_reassignment":
            policies = {str(x.get("id")): x for x in await self._complete(ctx, binding, "escalation_policy")}
            if desired["escalation_policy_id"] not in policies or _domain(policies[desired["escalation_policy_id"]]) != _value(self._target(binding), "account_domain"):
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "configured incident escalation policy is absent from the execution account")

    async def _validate_incident_actor(self, ctx: OperationContext, binding: Binding, actor_id: str) -> None:
        users = {str(x.get("id")): x for x in await self._complete(ctx, binding, "user")}
        if actor_id not in users or _domain(users[actor_id]) != _value(self._target(binding), "account_domain"):
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "approved PagerDuty incident actor is absent from the execution account")

    async def _delete_allowed(self, ctx: OperationContext, binding: Binding, schedule_id: str) -> None:
        # configuration_list is complete-or-raises.  A partial view must never authorize deletion.
        policies = await self._complete(ctx, binding, "escalation_policy")
        if any(schedule_id in _reference_ids(policy) for policy in policies):
            raise OpsError(ErrorCode.CONFLICT, "schedule is still referenced by an escalation policy")

    def _mutation(self, target: Any, desired: dict[str, Any], current: dict[str, Any] | None, actor_user_id: str | None = None) -> dict[str, Any]:
        target_type, target_id = _value(target, "resource_type"), _value(target, "id")
        if desired["kind"] == "schedule":
            if target_type != "schedule" or target_id is not None:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "a schedule configuration creates a new, unbound schedule only")
            if desired["name"] != _value(target, "name"):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "new schedule name must exactly match the approved target")
            start = desired["rotation_start"]
            layer = {"start": start, "rotation_virtual_start": start, "rotation_turn_length_seconds": desired["rotation_turn_length_seconds"], "users": [{"user": {"id": uid, "type": "user_reference"}} for uid in desired["user_ids"]]}
            schedule = {"type": "schedule", "name": desired["name"], "time_zone": desired["time_zone"], "schedule_layers": [layer]}
            if desired.get("description") is not None:
                schedule["description"] = desired["description"]
            return {"method": "POST", "resource_type": "schedule", "resource_id": None, "payload": {"schedule": schedule}}
        if desired["kind"] == "schedule_delete":
            if target_type != "schedule" or not target_id or desired["confirm_name"] != _value(target, "name"):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "schedule deletion requires the exact bound name confirmation")
            return {"method": "DELETE", "resource_type": "schedule", "resource_id": target_id, "payload": None}
        if desired["kind"] == "escalation_policy":
            if target_type != "escalation_policy":
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "escalation policy configuration needs an escalation-policy target")
            if target_id is None and desired["name"] != _value(target, "name"):
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "new escalation policy name must exactly match the approved target")
            rules = [{"escalation_delay_in_minutes": r["delay_minutes"], "targets": r["targets"]} for r in desired["rules"]]
            policy: dict[str, Any] = {"type": "escalation_policy", "name": desired["name"], "num_loops": desired["num_loops"], "escalation_rules": rules}
            if current:
                old_rules = current.get("rules", [])
                if any("assignment_strategy" in rule for rule in old_rules):
                    if len(old_rules) != len(rules):
                        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "existing escalation assignment strategy cannot be preserved across a changed rule count")
                    for old, new in zip(old_rules, rules, strict=True):
                        if "assignment_strategy" in old:
                            new["escalation_rule_assignment_strategy"] = old["assignment_strategy"]
                for key in ("teams", "description", "on_call_handoff_notifications"):
                    if key in current:
                        policy[key] = current[key]
            return {"method": "PUT" if target_id else "POST", "resource_type": "escalation_policy", "resource_id": target_id, "payload": {"escalation_policy": policy}}
        if desired["kind"] == "service_routing":
            if target_type != "service" or not target_id:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "service routing needs an existing service target")
            return {"method": "PUT", "resource_type": "service", "resource_id": target_id, "payload": {"service": {"type": "service", "escalation_policy": {"id": desired["escalation_policy_id"], "type": "escalation_policy_reference"}}}}
        if desired["kind"] == "incident_reassignment":
            if target_type != "incident" or not target_id or not actor_user_id:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, "incident reassignment requires an exact incident and approved actor")
            return {"method": "PUT", "resource_type": "incident", "resource_id": target_id, "actor_user_id": actor_user_id, "payload": {"incident": {"type": "incident_reference", "escalation_policy": {"id": desired["escalation_policy_id"], "type": "escalation_policy_reference"}}}}
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "unsupported PagerDuty configuration")

    async def prepare(self, ctx: OperationContext, service: ServiceSpec, binding: Binding, op: OperationConfig, action: str, desired_artifact: str | None, reason: str | None, *, desired_configuration: PagerDutyConfiguration | None = None) -> ActionPlan:
        if action != "configure" or desired_artifact is not None or desired_configuration is None:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty configuration requires typed desired_configuration and no artifact")
        target, adapter, desired = self._target(binding), self._adapter(ctx, binding), _dump(desired_configuration)
        current = await self._get(ctx, binding, target)
        if desired["kind"] == "incident_reassignment" and (current is None or current.get("status") not in {"triggered", "acknowledged"}):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "incident is no longer active and cannot be reassigned")
        if desired["kind"] == "schedule":
            schedules = await self._complete(ctx, binding, "schedule")
            v3_schedules = await self._complete(ctx, binding, "schedule_v3")
            if any(s.get("name") == desired["name"] for s in schedules + v3_schedules):
                raise OpsError(ErrorCode.CONFLICT, "a schedule with the requested name already exists")
        await self._validate_references(ctx, binding, desired)
        if desired["kind"] == "incident_reassignment":
            await self._validate_incident_actor(ctx, binding, op.pagerduty_actor_user_id or "")
        if desired["kind"] == "schedule_delete":
            if current is None:
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "bound schedule is absent")
            await self._delete_allowed(ctx, binding, str(_value(target, "id")))
        mutation = self._mutation(target, desired, current, op.pagerduty_actor_user_id)
        before = current or {"absent": True}
        domain = _value(target, "account_domain")
        safe_desired, removed = ctx.sanitizer.scrub(desired)
        if removed or safe_desired != desired:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty configuration contains protected credential-like text")
        safe_before, before_removed = ctx.sanitizer.scrub(before)
        if before_removed or safe_before != before:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "PagerDuty configuration projection contained protected content")
        safe_mutation, mutation_removed = ctx.sanitizer.scrub(mutation)
        if mutation_removed or safe_mutation != mutation:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "PagerDuty configuration contains protected credential-like text")
        fp = sha256_hex(canonical_json(safe_before))
        disruption = "PagerDuty incident reassignment may page or notify the current responder/on-call" if desired["kind"] == "incident_reassignment" else "PagerDuty configuration change; paging delivery is not exercised"
        return new_plan(ctx, service_id=service.id, binding_id=binding.id, action="configure", environment=binding.environment, executor=self.name, mechanism="PagerDuty reviewed configuration", target={"provider_id": binding.provider_id, "resource_type": _value(target, "resource_type"), "id": _value(target, "id"), "name": _value(target, "name"), "account_domain": domain}, target_fingerprint=fp, current_artifact=None, requested_artifact=None, provider_mutations=[{**mutation, "before": before}], health_checks=["pagerduty_configuration_matches"], unavailable_health_checks=[], timeout_seconds=op.readiness_timeout_seconds, expected_disruption=disruption, rollback={"supported": False, "note": "a reversal requires a separate reviewed configuration plan"}, dependencies=service.depends_on, dependents=ctx.catalog.dependents_of(service.id), locks=[f"pagerduty:{adapter.base_url}:{domain}"], preconditions=["execution credential resolves in the approved PagerDuty account", "target id, name and html_url domain match the binding"], pre_reads=["exact target read", "complete reference lists"], post_reads=["exact configuration verification"], notes=["PagerDuty has no conditional configuration write; the target is reread immediately before dispatch"])

    async def _revalidate_local_authority(self, ctx: OperationContext) -> None:
        row = await ctx.db.principal(ctx.principal.id)
        if row is None or row.get("revoked_at") is not None or "write" not in row.get("grants", []):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "write credential is no longer authorized")
        if await ctx.db.get_setting("mutations_stopped", False):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "mutations are stopped")
        request_plan_id = ctx.request.get("plan_id")
        if not isinstance(request_plan_id, str):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "PagerDuty request has no released plan")
        plan_row = await ctx.db.plan(request_plan_id)
        if plan_row is None or ctx.principal.id not in plan_row.get("released_to", []):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "released PagerDuty plan is no longer available to this principal")
        if datetime.fromisoformat(plan_row["expires_at"].replace("Z", "+00:00")) <= utcnow():
            raise OpsError(ErrorCode.PLAN_STALE, "released PagerDuty plan expired")
        if ctx.request.get("review_request"):
            approval = await ctx.db.active_approval(ctx.request_id)
            revision = await ctx.db.revision(ctx.request_id)
            if approval is None or revision is None or approval.get("revision") != revision.get("revision") or approval.get("args_hash") != revision.get("args_hash") or approval.get("catalog_revision") != ctx.catalog.revision or datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00")) <= utcnow():
                raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "PagerDuty request approval is no longer active")

    async def _dispatch_guard(self, ctx: OperationContext, plan: ActionPlan) -> None:
        """Runs in the adapter immediately before its HTTP write, after credential/actor work."""
        ctx.check_cancel()
        if plan.expires_at <= utcnow() or plan.catalog_revision != ctx.catalog.revision:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty plan expired or catalog changed before provider dispatch")
        await self._revalidate_local_authority(ctx)

    @staticmethod
    def _not_applied(intents: list[dict[str, Any]]) -> bool:
        return any(i.get("result", {}).get("status") == "not_applied" for i in intents)

    async def _validate_mutation_references(self, ctx: OperationContext, binding: Binding, mutation: dict[str, Any]) -> None:
        domain = _value(self._target(binding), "account_domain")
        payload = mutation.get("payload") or {}
        if mutation["resource_type"] == "schedule":
            ids = [u["user"]["id"] for u in payload.get("schedule", {}).get("schedule_layers", [{}])[0].get("users", [])]
            rows = {r.get("id"): r for r in await self._complete(ctx, binding, "user")}
        elif mutation["resource_type"] == "escalation_policy":
            refs = [ref for rule in payload.get("escalation_policy", {}).get("escalation_rules", []) for ref in rule.get("targets", [])]
            ids = [r["id"] for r in refs]
            rows = {}
            for typ in ("user", "schedule"):
                rows.update({r.get("id"): r for r in await self._complete(ctx, binding, typ)})
        elif mutation["resource_type"] == "service":
            ids = [payload["service"]["escalation_policy"]["id"]]
            rows = {r.get("id"): r for r in await self._complete(ctx, binding, "escalation_policy")}
        elif mutation["resource_type"] == "incident":
            ids = [payload["incident"]["escalation_policy"]["id"], mutation["actor_user_id"]]
            rows = {r.get("id"): r for r in await self._complete(ctx, binding, "escalation_policy")}
            rows.update({r.get("id"): r for r in await self._complete(ctx, binding, "user")})
        else:
            return
        if any(i not in rows or _domain(rows[i]) != domain for i in ids):
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, "PagerDuty referenced configuration changed during pre-dispatch checks")

    @staticmethod
    def _matches(mutation: dict[str, Any], after: dict[str, Any] | None) -> bool:
        if mutation["method"] == "DELETE":
            return after is None
        if after is None:
            return False
        expected = mutation["payload"][mutation["resource_type"]]
        if mutation["resource_type"] == "service":
            return (after.get("escalation_policy") or {}).get("id") == expected["escalation_policy"]["id"]
        if mutation["resource_type"] == "incident":
            return after.get("id") == mutation["resource_id"] and after.get("status") in {"triggered", "acknowledged"} and (after.get("escalation_policy") or {}).get("id") == expected["escalation_policy"]["id"]
        if mutation["resource_type"] == "escalation_policy":
            actual_rules = after.get("rules")
            wanted_rules = expected["escalation_rules"]
            if after.get("name") != expected["name"] or after.get("num_loops") != expected["num_loops"] or not isinstance(actual_rules, list) or len(actual_rules) != len(wanted_rules):
                return False
            return all(a.get("delay_minutes") == w["escalation_delay_in_minutes"] and [(t.get("id"), t.get("type")) for t in a.get("targets", [])] == [(t.get("id"), t.get("type")) for t in w["targets"]] for a, w in zip(actual_rules, wanted_rules, strict=True))
        layer = (after.get("schedule_layers") or [None])[0]
        wanted_layer = expected["schedule_layers"][0]
        def same_instant(one: Any, two: Any) -> bool:
            try:
                return datetime.fromisoformat(str(one).replace("Z", "+00:00")) == datetime.fromisoformat(str(two).replace("Z", "+00:00"))
            except ValueError:
                return False
        return len(after.get("schedule_layers") or []) == 1 and isinstance(layer, dict) and after.get("name") == expected["name"] and after.get("time_zone") == expected["time_zone"] and same_instant(layer.get("start"), wanted_layer["start"]) and same_instant(layer.get("rotation_virtual_start"), wanted_layer["rotation_virtual_start"]) and layer.get("rotation_turn_length_seconds") == wanted_layer["rotation_turn_length_seconds"] and [u.get("id") for u in layer.get("users", [])] == [u["user"]["id"] for u in wanted_layer["users"]]

    async def execute(self, ctx: OperationContext, plan: ActionPlan) -> Receipt:
        started = utcnow()
        service_doc = ctx.catalog.service(plan.service_id)
        binding = service_doc.spec.binding(plan.binding_id) if service_doc else None
        if binding is None:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty binding no longer exists")
        target, adapter, mutation = self._target(binding), self._adapter(ctx, binding), plan.provider_mutations[0]
        current = await self._get(ctx, binding, target)
        if mutation["resource_type"] == "incident" and (current is None or current.get("status") not in {"triggered", "acknowledged"}):
            raise OpsError(ErrorCode.PLAN_STALE, "incident is no longer active")
        before = current or {"absent": True}
        safe_before, before_removed = ctx.sanitizer.scrub(before)
        if before_removed or safe_before != before:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "PagerDuty configuration projection contained protected content")
        if sha256_hex(canonical_json(safe_before)) != plan.target_fingerprint:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty target changed since the plan was prepared")
        if mutation["method"] == "POST":
            listed = await self._complete(ctx, binding, mutation["resource_type"])
            if mutation["resource_type"] == "schedule":
                listed += await self._complete(ctx, binding, "schedule_v3")
            name = mutation["payload"][mutation["resource_type"]]["name"]
            if any(item.get("name") == name for item in listed):
                raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty resource name appeared after planning")
        if mutation["method"] == "DELETE":
            await self._delete_allowed(ctx, binding, str(mutation["resource_id"]))
        await self._validate_mutation_references(ctx, binding, mutation)
        reread = await self._get(ctx, binding, target)
        safe_reread, reread_removed = ctx.sanitizer.scrub(reread or {"absent": True})
        if reread_removed or safe_reread != (reread or {"absent": True}) or sha256_hex(canonical_json(safe_reread)) != plan.target_fingerprint:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty target changed during pre-dispatch checks")
        if plan.expires_at <= utcnow() or plan.catalog_revision != ctx.catalog.revision:
            raise OpsError(ErrorCode.PLAN_STALE, "PagerDuty plan expired or catalog changed during pre-dispatch reads")
        ctx.check_cancel()
        await self._revalidate_local_authority(ctx)
        intent_id = await ctx.record_intent("dispatching", plan.locks[0], f"PagerDuty {mutation['method']} {mutation['resource_type']}", intent_record(plan, mutation))
        dispatched = utcnow()
        try:
            kwargs = {"actor_user_id": mutation["actor_user_id"], "account_domain": plan.target["account_domain"]} if mutation["resource_type"] == "incident" else {}
            written = await adapter.configuration_write(mutation["method"], mutation["resource_type"], mutation["resource_id"], mutation["payload"], dispatch_guard=lambda: self._dispatch_guard(ctx, plan), **kwargs)
        except OpsError as exc:
            status_code = exc.data.get("http_status")
            if exc.code in (ErrorCode.AUTH_REQUIRED, ErrorCode.AUTHORIZATION_DENIED) or status_code in {400, 401, 403, 404, 409, 422, 429}:
                await ctx.db.complete_intent(intent_id, {"status": "not_applied", "error": exc.code.value, **({"http_status": status_code} if status_code else {})})
                return receipt_from(plan, ctx, before=ctx.scrub(before), after=ctx.scrub(before), before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="not_started", outcome="PagerDuty definitively rejected the configuration write", checks=[HealthCheckResult(check_id="pagerduty_configuration_matches", kind="pagerduty_configuration_matches", passed=False, detail="provider rejected the configuration write")])
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "error": exc.code.value})
            status, detail = await self.reconcile(ctx, plan, await ctx.db.intents(ctx.request_id), uncertain_if_absent=True)
            return receipt_from(plan, ctx, before=before, after=detail.get("observed", {}), before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="ran" if status == ExecutionStatus.SUCCEEDED else "uncertain", outcome=detail.get("summary", "PagerDuty write outcome unknown"), checks=[HealthCheckResult.model_validate(c) for c in detail.get("checks", [])], notes=["write was not replayed after an uncertain provider response"])
        except Exception as exc:  # no resend: a failed connection can have accepted the write
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "error": type(exc).__name__})
            status, detail = await self.reconcile(ctx, plan, await ctx.db.intents(ctx.request_id), uncertain_if_absent=True)
            return receipt_from(plan, ctx, before=before, after=detail.get("observed", {}), before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="ran" if status == ExecutionStatus.SUCCEEDED else "uncertain", outcome=detail.get("summary", "PagerDuty write outcome unknown"), checks=[HealthCheckResult.model_validate(c) for c in detail.get("checks", [])], notes=["write was not replayed after an uncertain provider response"])
        created_id = (written or {}).get("id") if mutation["method"] == "POST" else mutation["resource_id"]
        safe_created_id = ctx.scrub(created_id)
        if safe_created_id != created_id:
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "reason": "create response id contained protected content"})
            return receipt_from(plan, ctx, before=before, after={}, before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="uncertain", outcome="create response did not establish a safe resource identity", checks=[])
        if mutation["method"] == "POST" and not created_id:
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "reason": "create response had no resource id"})
            return receipt_from(plan, ctx, before=before, after={}, before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="uncertain", outcome="create response did not establish resource ownership", checks=[HealthCheckResult(check_id="pagerduty_configuration_matches", kind="pagerduty_configuration_matches", passed=None, detail="created resource id was not returned")])
        if mutation["method"] == "POST" and (not isinstance(written, dict) or written.get("name") != mutation["payload"][mutation["resource_type"]]["name"] or _domain(written) != plan.target["account_domain"]):
            await ctx.db.complete_intent(intent_id, {"status": "uncertain", "reason": "create response did not match the reviewed name and account"})
            return receipt_from(plan, ctx, before=before, after={}, before_artifact=None, after_artifact=None, provider_ids=[intent_id], started_at=started, dispatched_at=dispatched, ran="uncertain", outcome="create response did not establish exact resource identity", checks=[HealthCheckResult(check_id="pagerduty_configuration_matches", kind="pagerduty_configuration_matches", passed=None, detail="created resource identity was not verified")])
        await ctx.db.complete_intent(intent_id, {"status": "accepted", **({"created_target_id": created_id} if mutation["method"] == "POST" else {})})
        await ctx.set_phase("verifying")
        if mutation["method"] == "DELETE":
            after = await adapter.configuration_get("schedule", mutation["resource_id"], ctx.budget, execution=True)
        else:
            verify_id = created_id or mutation["resource_id"]
            after = await adapter.configuration_get(mutation["resource_type"], verify_id, ctx.budget, execution=True)
        passed = self._matches(mutation, after) and (after is None or _domain(after) == plan.target["account_domain"])
        check = HealthCheckResult(check_id="pagerduty_configuration_matches", kind="pagerduty_configuration_matches", passed=passed, detail="configuration matched exact post-write read" if passed else "configuration did not match exact post-write read")
        return receipt_from(plan, ctx, before=ctx.scrub(before), after=ctx.scrub(after or {"absent": True}), before_artifact=None, after_artifact=None, provider_ids=[intent_id] + ([str(safe_created_id)] if mutation["method"] == "POST" else []), started_at=started, dispatched_at=dispatched, ran="ran", outcome="PagerDuty configuration verified" if passed else "PagerDuty configuration verification failed", checks=[check], notes=["health claim covers configuration only; paging delivery was not exercised"])

    async def reconcile(self, ctx: OperationContext, plan: ActionPlan, intents: list[dict[str, Any]], *, uncertain_if_absent: bool = False) -> tuple[ExecutionStatus, dict[str, Any]]:
        mutation = plan.provider_mutations[0]
        if self._not_applied(intents):
            return ExecutionStatus.FAILED, {"summary": "provider definitively rejected the write before applying it", "observed": {}, "checks": [], "ran": "not_started"}
        incident_unconfirmed = mutation["resource_type"] == "incident" and not any(i.get("result", {}).get("status") == "accepted" for i in intents)
        if mutation["method"] == "POST":
            created = next((i.get("result", {}).get("created_target_id") for i in intents if i.get("result")), None)
            if not created:
                return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "create identity was not confirmed; same-name resources are not assumed owned", "observed": {}}
            rid = created
        else:
            rid = mutation["resource_id"]
        try:
            service_doc = ctx.catalog.service(plan.service_id)
            binding = service_doc.spec.binding(plan.binding_id) if service_doc else None
            if binding is None:
                return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "binding no longer exists", "observed": {}}
            item = await self._adapter(ctx, binding).configuration_get(mutation["resource_type"], rid, ctx.budget, execution=True)
        except Exception as exc:  # reconciliation remains read-only
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": f"target could not be inspected: {type(exc).__name__}", "observed": {}}
        applied = self._matches(mutation, item) and (item is None or _domain(item) == plan.target["account_domain"])
        if incident_unconfirmed:
            return ExecutionStatus.OUTCOME_UNKNOWN, {"summary": "incident reassignment response was not confirmed; matching policy state cannot prove the write", "observed": ctx.scrub(item or {"absent": True}), "checks": []}
        if not applied:
            return (ExecutionStatus.OUTCOME_UNKNOWN if uncertain_if_absent else ExecutionStatus.FAILED), {"summary": "configuration is absent after interrupted dispatch", "observed": ctx.scrub(item or {"absent": True}), "checks": []}
        return ExecutionStatus.SUCCEEDED, {"summary": "configuration is present after interrupted dispatch", "observed": ctx.scrub(item or {"absent": True}), "checks": [{"check_id": "pagerduty_configuration_matches", "kind": "pagerduty_configuration_matches", "passed": True, "detail": "exact resource was present on reconciliation"}]}
