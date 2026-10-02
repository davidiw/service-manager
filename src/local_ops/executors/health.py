"""Health checks run after a mutation. A check that cannot run reports passed=None, never a pass."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx

from local_ops.catalog import HealthCheckConfig, ServiceSpec
from local_ops.models import HealthCheckResult, utcnow
from local_ops.providers.kube_client import KubeClient
from local_ops.providers.kubernetes import rollout_state

if TYPE_CHECKING:
    pass


async def wait_for_rollout(client: KubeClient, kind: str, namespace: str, name: str, expected_uid: str, timeout_seconds: int, *, expected_images: list[str] | None = None, cancel: asyncio.Event | None = None) -> HealthCheckResult:
    """Poll until the controller converges: observedGeneration>=generation, updated==ready==desired,
    and (when given) the running pods carry the expected images."""
    started_at = utcnow()
    deadline = started_at.timestamp() + timeout_seconds
    last: dict[str, Any] = {}
    while True:
        if cancel is not None and cancel.is_set():
            return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=None, detail="cancelled while waiting for rollout", observed=last)
        wl = await client.get_workload(kind, namespace, name)
        if wl is None or wl["metadata"]["uid"] != expected_uid:
            return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=False, detail="workload disappeared or was recreated during rollout", observed=last)
        rs = rollout_state(wl)
        last = rs
        if rs["converged"]:
            if expected_images:
                pods = await client.list_pods(namespace, label_selector=",".join(f"{k}={v}" for k, v in ((wl.get("spec", {}).get("selector") or {}).get("match_labels") or {}).items()) or None)
                live = [p for p in pods if not (p.get("metadata", {}).get("deletion_timestamp") or p.get("metadata", {}).get("deletionTimestamp"))]
                statuses = [cs for p in live for cs in (p.get("status", {}).get("container_statuses") or [])]
                running = [f"{cs.get('image')} ({cs.get('image_id', cs.get('imageID'))})" for cs in statuses]
                ready = [bool(cs.get("ready")) for cs in statuses]
                matched = [cs for cs in statuses if _image_matches(cs, expected_images)]
                if not statuses or not all(ready) or not matched or len(matched) < rs["desired"]:
                    last = {**rs, "running_images": running, "ready_flags": ready, "matched": len(matched)}
                else:
                    return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=True, detail="rollout converged with expected images", observed={**rs, "running_images": running})
            else:
                return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=True, detail="rollout converged", observed=rs)
        # crash-loop detection: only this workload's pods (by selector) count; other workloads' pods are irrelevant
        selector = ",".join(f"{k}={v}" for k, v in ((wl.get("spec", {}).get("selector") or {}).get("match_labels") or {}).items()) or None
        pods = await client.list_pods(namespace, label_selector=selector)
        crash = [p["metadata"]["name"] for p in pods if _pod_is_new_and_crashing(p, started_at)]
        if crash and utcnow().timestamp() > deadline - timeout_seconds * 0.5:
            return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=False, detail=f"pods crash-looping: {crash[:5]}", observed={**rs, "crashlooping": crash[:10]})
        if utcnow().timestamp() > deadline:
            return HealthCheckResult(check_id="ready_replicas", kind="ready_replicas", passed=False, detail="rollout did not converge before timeout", observed={**rs, "crashlooping": crash[:10]})
        await asyncio.sleep(1.0)


def _image_matches(cs: dict[str, Any], expected: list[str]) -> bool:
    """A container runs an expected artifact when its reported image or image id carries the expected
    reference or the expected digest (runtimes report digests in either field)."""
    image = str(cs.get("image") or "")
    image_id = str(cs.get("image_id") or cs.get("imageID") or "")
    for exp in expected:
        if exp == image:
            return True
        digest = exp.split("@", 1)[1] if "@" in exp else None
        if digest and (digest in image or digest in image_id):
            return True
    return False


def _pod_is_new_and_crashing(pod: dict[str, Any], started_at: Any) -> bool:
    """Only pods created by this rollout and not already terminating count as crash signals."""
    md = pod.get("metadata", {})
    if md.get("deletion_timestamp") or md.get("deletionTimestamp"):
        return False
    created = str(md.get("creation_timestamp") or md.get("creationTimestamp") or "")
    if created and created[:19] < started_at.isoformat()[:19]:
        return False
    for cs in pod.get("status", {}).get("container_statuses") or []:
        waiting = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
        if waiting == "CrashLoopBackOff":
            return True
        terminated = ((cs.get("last_state") or cs.get("lastState") or {}).get("terminated") or {}).get("reason")
        if terminated == "Error" and int(cs.get("restart_count", cs.get("restartCount", 0)) or 0) >= 2:
            return True
    return False


def _json_path(data: Any, path: str) -> tuple[bool, Any]:
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return False, None
    return True, cur


def _as_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


async def http_check(hc: HealthCheckConfig, http: httpx.AsyncClient, *, expected_version: str | None = None) -> HealthCheckResult:
    """Run one declared check. What "healthy" means is entirely the service file's data."""
    if not hc.url:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=None, detail="no URL configured")
    try:
        r = await http.get(hc.url, timeout=hc.timeout_seconds)
    except httpx.HTTPError as e:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail=f"request failed: {type(e).__name__}", observed={"url": hc.url})
    if hc.kind == "http_status":
        ok = r.status_code == hc.expected_status
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=ok, detail=f"HTTP {r.status_code} (expected {hc.expected_status})", observed={"url": hc.url, "status": r.status_code, "body": r.text[:500]})
    if hc.kind != "http_json":
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=None, detail="unsupported check kind")
    field = hc.json_field or ""
    observed: dict[str, Any] = {"url": hc.url, "status": r.status_code, "field": field}
    if r.status_code != hc.expected_status:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail=f"HTTP {r.status_code} (expected {hc.expected_status})", observed=observed)
    try:
        found, value = _json_path(r.json(), field)
    except ValueError:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail="response is not JSON", observed=observed)
    observed["value"] = value
    if not found:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail=f"field {field!r} missing", observed=observed)
    problems: list[str] = []
    if hc.equals is not None and str(value) != hc.equals:
        problems.append(f"{field}={value!r}, expected {hc.equals!r}")
    if hc.equals_artifact_version:
        if expected_version is None:
            return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=None, detail="artifact has no version label to compare against", observed=observed)
        if str(value) != expected_version:
            problems.append(f"{field}={value!r}, expected artifact version {expected_version!r}")
    if hc.increases and not problems:
        before = _as_number(value)
        await asyncio.sleep(hc.interval_seconds)
        try:
            r2 = await http.get(hc.url, timeout=hc.timeout_seconds)
            _, value2 = _json_path(r2.json(), field)
        except (httpx.HTTPError, ValueError) as e:
            return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail=f"second read failed: {type(e).__name__}", observed=observed)
        after = _as_number(value2)
        observed["value_after"] = value2
        if before is None or after is None:
            problems.append(f"{field} is not numeric ({value!r} -> {value2!r})")
        elif after <= before:
            problems.append(f"{field} did not increase over {hc.interval_seconds}s ({value!r} -> {value2!r})")
    if problems:
        return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=False, detail="; ".join(problems), observed=observed)
    return HealthCheckResult(check_id=hc.id, kind=hc.kind, passed=True, detail=f"{field}={value!r}" + (f" -> {observed['value_after']!r}" if "value_after" in observed else ""), observed=observed)


async def run_service_checks(service: ServiceSpec, check_ids: list[str], http: httpx.AsyncClient, *, expected_version: str | None, settle_seconds: float = 45.0) -> list[HealthCheckResult]:
    out: list[HealthCheckResult] = []
    for cid in check_ids:
        if cid in ("ready_replicas", "helm_release_deployed"):
            continue  # built-in controller checks run inside the executor
        hc = service.health_check(cid)
        if hc is None:
            out.append(HealthCheckResult(check_id=cid, kind=cid, passed=None, detail="check not configured for this service"))
            continue
        # Endpoints and load balancers lag the controller: retry a failing check within a bounded settle
        # window before reporting it. A check that never passes in the window is a real failure.
        deadline = asyncio.get_running_loop().time() + settle_seconds
        attempts = 0
        while True:
            attempts += 1
            res = await http_check(hc, http, expected_version=expected_version)
            if res.passed is not False or asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(2.0)
        res.observed["attempts"] = attempts
        out.append(res)
    return out
