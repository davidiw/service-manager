"""Regression coverage for fixes to D6 (intent before side effect; reconcile, never retry):

- shutdown mid-mutation leaves the request RUNNING for recover(), never finalized CANCELLED (review B1)
- an exception raised after dispatch (not just the provider call itself) is reconciled, not failed
  without a receipt (review B2)
- a transport error that leaves the target looking unchanged is outcome_unknown, not failed (review B5)
- the stored private_error (and the log line) is scrubbed like any other persisted/logged material (B6)
- helm values files: content changes invalidate the plan, and a path outside the catalog root is refused
  (B4), tested at the level of the pure helper functions since no helm fixture exists in the unit suite
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from local_ops.executors.base import dispatched_intents
from local_ops.executors.helm import resolve_values_file, values_files_fingerprint
from local_ops.models import ErrorCode, OpsError
from local_ops.worker import Worker
from tests.conftest import Env
from tests.test_execution import finish, prepare, submit


@pytest.fixture
async def yolo(env: Env) -> Env:
    await env.set_mode("write-default", "mutation", "yolo")
    return env


async def test_shutdown_mid_mutation_leaves_running_for_recover(yolo: Env) -> None:
    """Worker.stop() cancelling a dispatched mutation must never finalize it as CANCELLED (that would
    discard approved work without reconciling); it must leave the request RUNNING so recover() reconciles
    it on next start, exactly like a real process restart."""
    env = yolo
    env.kube.auto_converge = False  # rollout never converges on its own: stop() will land mid-verify
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    sub = await submit(env, plan)
    rid = sub["request_id"]
    req = None
    for _ in range(50):
        req = await env.core.db.request(rid)
        if req["phase"] == "verifying":
            break
        await asyncio.sleep(0.1)
    assert req is not None and req["phase"] == "verifying"
    assert len(env.kube.patch_log) == 1

    await env.core.worker.stop()

    req = await env.core.db.request(rid)
    assert req["execution_status"] == "running"  # not cancelled; D6 leaves it for recover()
    assert await env.core.db.locks() != []  # lock preserved across shutdown
    intents = await env.core.db.intents(rid)
    assert dispatched_intents(intents)

    w2 = Worker(env.core.db, env.core.config_ref, env.core.auth, env.core.registry, env.core.providers_ref, env.core.sanitizer, env.core.requests, env.core.catalog_ref)
    await w2.recover()
    assert w2.recovery_report and w2.recovery_report[0]["action"] == "reconciled"
    req = await env.core.db.request(rid)
    assert req["execution_status"] in ("succeeded", "partial", "outcome_unknown")
    rc = await env.core.db.receipt_for_request(rid)
    assert rc is not None
    assert len(env.kube.patch_log) == 1  # never re-sent
    assert await env.core.db.locks() == []


async def test_exception_after_dispatch_during_verify_is_reconciled_not_failed(yolo: Env) -> None:
    """An exception from get_workload/wait_for_rollout *after* a successful patch must not become a bare
    FAILED with no receipt: the worker reconciles through the same path recover() uses."""
    env = yolo
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    # Fires on the first get_workload call after the patch is actually sent (wait_for_rollout's first
    # poll), not on the pre-dispatch staleness re-read.
    env.kube.fail_once_after_next_patch("get_workload", RuntimeError("simulated provider error during rollout verification"))
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] in ("succeeded", "partial", "outcome_unknown"), out
    rc = out["receipt"]
    assert rc is not None
    assert "no mutation was re-sent" in " ".join(rc["notes"])
    assert len(env.kube.patch_log) == 1


async def test_transport_error_with_no_applied_change_is_outcome_unknown(yolo: Env) -> None:
    """A dropped connection that the re-read shows as *not* applied is still ambiguous (the request may
    not have reached the provider, or may still be in flight) -- it must not be reported as a confirmed
    failure."""
    env = yolo
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    env.kube.crash_before_patch = True
    sub = await submit(env, plan)
    out = await finish(env, sub["request_id"])
    assert out["_status"]["execution_status"] == "outcome_unknown", out
    assert out["_status"]["public_error"]["error"] == "outcome_unknown"
    assert env.kube.patch_log == []
    rc = out["receipt"]
    assert rc["ran"] == "uncertain"


async def test_provider_exception_message_is_scrubbed_in_private_error_and_log(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    """A provider exception that escapes to the worker's generic handler stores a scrubbed traceback, and
    the log line it writes is scrubbed too -- not just the disclosed candidate."""
    import logging

    env.demo.fail_next = True  # raises RuntimeError("...token=secret-should-not-leak-AKIAIOSFODNN7EXAMPLE")
    with caplog.at_level(logging.ERROR, logger="local_ops.worker"):
        sub = await env.call("read", "evidence_query", {"source_id": "demo-fake", "query_type": "cloudtrail_events"})
        rid = sub["request_id"]
        await env.approve(rid)
        st = await env.wait("read", rid)
        assert st["execution_status"] == "failed"
        await env.release(rid)
    row = await env.core.db.request(rid)
    private = row.get("private_error") or ""
    assert "AKIAIOSFODNN7EXAMPLE" not in private
    assert "secret-should-not-leak" not in private
    assert "[REDACTED" in private
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "AKIAIOSFODNN7EXAMPLE" not in logged
    assert "secret-should-not-leak" not in logged


async def test_helm_runner_uses_credential_context_over_provider_context(yolo: Env) -> None:
    """Helm and the verified client share KubernetesAdapter.connection(): the credential's declared
    context wins over the provider's static config, so helm can never target a different cluster."""
    from local_ops.config import ProviderConfig, ServerConfig
    from local_ops.providers.credentials import CredentialResolver
    from local_ops.providers.kubernetes import KubernetesAdapter
    from local_ops.release import Sanitizer

    server_cfg = ServerConfig.model_validate({"credentials": [{"id": "kc", "kind": "kubeconfig_context", "context": "cred-ctx", "kubeconfig": "/tmp/does-not-need-to-exist-for-this-test"}]})
    resolver = CredentialResolver(server_cfg, Sanitizer())
    provider_cfg = ProviderConfig(id="k", kind="kubernetes", context="provider-ctx", credential="kc")
    adapter = KubernetesAdapter(provider_cfg, server_cfg, resolver)
    context, kubeconfig = await adapter.connection()
    assert context == "cred-ctx"  # not "provider-ctx": the credential's declared context wins
    assert kubeconfig == "/tmp/does-not-need-to-exist-for-this-test"


def test_values_file_outside_catalog_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    (root / "charts").mkdir(parents=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("x: 1\n")
    with pytest.raises(OpsError) as ei:
        resolve_values_file(root, "../outside.yaml")
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


def test_values_files_fingerprint_changes_with_content(tmp_path: Path) -> None:
    root = tmp_path / "catalog"
    vdir = root / "charts"
    vdir.mkdir(parents=True)
    vf = vdir / "values-prod.yaml"
    vf.write_text("replicaCount: 1\n")
    fp1 = values_files_fingerprint(root, ["charts/values-prod.yaml"])
    fp_again = values_files_fingerprint(root, ["charts/values-prod.yaml"])
    assert fp1 == fp_again  # stable for unchanged content
    vf.write_text("replicaCount: 2\n")  # an edit after prepare must invalidate the plan (plan_stale)
    fp2 = values_files_fingerprint(root, ["charts/values-prod.yaml"])
    assert fp1 != fp2
    with pytest.raises(OpsError) as ei:
        values_files_fingerprint(root, ["charts/missing.yaml"])
    assert ei.value.code == ErrorCode.SCOPE_UNRESOLVED


async def _claimed_mutation(env: Env) -> tuple[Worker, dict[str, object]]:
    plan = (await prepare(env, action="restart", artifact=None))["plan"]
    await env.core.worker.stop()
    rid = (await submit(env, plan))["request_id"]
    w = Worker(env.core.db, env.core.config_ref, env.core.auth, env.core.registry, env.core.providers_ref, env.core.sanitizer, env.core.requests, env.core.catalog_ref)
    claimed = await env.core.db.claim_queued(w.token, 1)
    assert claimed and claimed[0]["id"] == rid
    req = claimed[0]
    assert await env.core.db.try_lock(req["target_key"].split(",") if req.get("target_key") else [], rid) is None
    await env.core.db.transition_request(rid, ("running",), cancel_requested_at="2026-01-01T00:00:00Z")
    return w, req


async def test_user_cancel_before_dispatch_is_cancelled_and_unlocked(yolo: Env) -> None:
    """A cooperative request_cancel is not a shutdown: with nothing dispatched the mutation ends CANCELLED
    and releases its lock, rather than being left RUNNING and stranding the target's lock."""
    w, req = await _claimed_mutation(yolo)
    ev = asyncio.Event()
    ev.set()
    await w._run(req, ev)
    r = await yolo.core.db.request(str(req["id"]))
    assert r["execution_status"] == "cancelled"
    assert await yolo.core.db.locks() == []
    assert yolo.kube.patch_log == []


async def test_recover_cancels_undispatched_mutation_with_cancel_requested(yolo: Env) -> None:
    """A restart after a cancel request must not requeue the work into a state claim_queued never picks."""
    w, req = await _claimed_mutation(yolo)
    await w.recover()
    r = await yolo.core.db.request(str(req["id"]))
    assert r["execution_status"] == "cancelled"
    assert await yolo.core.db.locks() == []
    assert yolo.kube.patch_log == []
