"""Slow providers do not freeze status or the review UI; provider concurrency stays bounded; cancellation
releases the worker slot; one failing provider does not stall others; no blocking calls in async paths."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from tests.conftest import Env

SRC = Path(__file__).resolve().parents[1] / "src" / "local_ops"


async def _yolo_discovery(env: Env) -> None:
    r = await env.set_mode("read-default", "inventory", "yolo")
    assert r.status_code == 303


async def _submit_scan(env: Env, reason: str) -> str:
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"], "reason": reason})
    assert "__error__" not in sub, sub
    assert sub["execution_status"] in ("queued", "running")
    return sub["request_id"]


async def _wait_all(env: Env, rids: list[str], timeout: float = 40) -> dict[str, dict]:  # type: ignore[type-arg]  # noqa: ASYNC109
    out = {}
    for rid in rids:
        out[rid] = await env.run_until(rid, timeout=timeout)
    return out


async def test_slow_provider_does_not_freeze_status_or_ui(env: Env) -> None:
    await _yolo_discovery(env)
    env.demo.simulate_delay = 3.0
    rids = [await _submit_scan(env, f"slow-{i}") for i in range(3)]
    c = await env.reviewer()
    try:
        # while the provider calls are sleeping, every control path must answer promptly
        await asyncio.sleep(0.3)
        running = await env.core.db.requests_list(execution_status=["running", "queued"])
        assert len(running) == 3
        for rid in rids:
            t0 = time.perf_counter()
            st = await env.call("read", "request_status", {"request_id": rid})
            assert time.perf_counter() - t0 < 1.0
            assert st["execution_status"] in ("queued", "running") and st["poll_after_ms"] == 500
        t0 = time.perf_counter()
        page = await c.get("/review")
        assert time.perf_counter() - t0 < 1.0 and page.status_code == 200
        assert "Queued / running" in page.text and all(rid in page.text for rid in rids)
        t0 = time.perf_counter()
        api = await c.get("/api/ui/queue")
        assert time.perf_counter() - t0 < 1.0 and api.status_code == 200
        assert api.json()["active"] == 3
        t0 = time.perf_counter()
        detail = await c.get(f"/review/{rids[0]}")
        assert time.perf_counter() - t0 < 1.0 and "Running" in detail.text
    finally:
        await c.aclose()
    done = await _wait_all(env, rids)
    assert all(r["execution_status"] == "succeeded" for r in done.values())


async def test_concurrency_is_bounded_and_everything_finishes(env: Env) -> None:
    await _yolo_discovery(env)
    env.demo.simulate_delay = 1.0
    limit = env.core.config.limits.provider_concurrency_global
    assert limit == 4
    rids = [await _submit_scan(env, f"bounded-{i}") for i in range(6)]
    peak = 0
    deadline = time.perf_counter() + 30
    while time.perf_counter() < deadline:
        rows = await env.core.db.requests_list(limit=50)
        mine = [r for r in rows if r["id"] in rids]
        running = [r for r in mine if r["execution_status"] == "running"]
        assert len(running) <= limit, [r["id"] for r in running]
        assert len(env.core.worker._tasks) <= limit
        peak = max(peak, len(running))
        if mine and all(r["execution_status"] not in ("queued", "running") for r in mine):
            break
        await asyncio.sleep(0.05)
    done = await _wait_all(env, rids)
    assert all(r["execution_status"] == "succeeded" for r in done.values()), {k: v["execution_status"] for k, v in done.items()}
    assert peak >= 2, "expected some overlap between the six one-second scans"
    assert len(env.demo.calls) == 6
    assert env.core.worker._tasks == {}


async def test_cancel_before_dispatch_releases_immediately(env: Env) -> None:
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"]})
    assert sub["execution_status"] == "pending_request_review"
    st = await env.call("read", "request_cancel", {"request_id": sub["request_id"]})
    assert st["execution_status"] == "cancelled"
    assert env.demo.calls == [] and env.core.worker._tasks == {}


async def test_cancel_after_dispatch_ends_cancelled_and_releases_slot(env: Env) -> None:
    await _yolo_discovery(env)
    env.demo.simulate_delay = 5.0
    rid = await _submit_scan(env, "cancel-me")
    for _ in range(50):
        req = await env.core.db.request(rid)
        if req["execution_status"] == "running":
            break
        await asyncio.sleep(0.05)
    assert req["execution_status"] == "running"
    t0 = time.perf_counter()
    st = await env.call("read", "request_cancel", {"request_id": rid})
    assert st["execution_status"] in ("running", "cancelled")
    while True:
        st = await env.call("read", "request_status", {"request_id": rid})
        if st["execution_status"] not in ("queued", "running"):
            break
        assert time.perf_counter() - t0 < 7.0, f"still {st['execution_status']} after cancel"
        await asyncio.sleep(0.1)
    assert st["execution_status"] == "cancelled"
    for _ in range(20):
        if rid not in env.core.worker._tasks:
            break
        await asyncio.sleep(0.1)
    assert rid not in env.core.worker._tasks
    assert rid not in env.core.worker._cancel_events


async def test_provider_failure_does_not_stall_other_requests(env: Env) -> None:
    await _yolo_discovery(env)
    env.demo.fail_next = True
    bad = await _submit_scan(env, "will-fail")
    good = await _submit_scan(env, "will-succeed")
    done = await _wait_all(env, [bad, good], timeout=20)
    assert done[bad]["execution_status"] in ("failed", "partial")
    assert done[good]["execution_status"] == "succeeded"
    assert env.demo.fail_next is False
    assert env.core.worker._tasks == {}
    # the failure is reported through the typed public error, never the provider's text
    st = await env.call("read", "request_status", {"request_id": bad})
    assert "secret-should-not-leak" not in str(st)
    again = await _submit_scan(env, "after-failure")
    assert (await env.run_until(again))["execution_status"] == "succeeded"


BLOCKING_TOKENS = ("subprocess.run(", "time.sleep(", "requests.get(", "import boto3")
# `gitops.py` is the one module allowed to call `subprocess.run` (fixed argv, no shell, for the Git
# commands catalog/overlay acceptance needs, D24/D29): every async caller offloads it with
# `asyncio.to_thread`, verified by `test_git_helpers_are_always_offloaded_from_async_code` below, so the
# file-wide ban stays exactly as strict as it was before that module existed.
ALLOWLISTED_FILES = {"gitops.py"}
GIT_HELPER_TOKENS = ("commit_catalog_path(", "git_revision_excluding_config(", "committed_change(", "load_catalog(")


def _async_line_ranges(path: Path) -> list[tuple[int, int]]:
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ranges = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            ranges.append((node.lineno, node.end_lineno or node.lineno))
    return ranges


def _blocking_call_sites() -> list[str]:
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in ALLOWLISTED_FILES:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for tok in BLOCKING_TOKENS:
                idx = line.find(tok)
                if idx < 0:
                    continue
                if "#" in line[:idx]:
                    continue  # comment before the token
                if re.match(r'\s*("""|\'\'\')', line):
                    continue  # docstring opener on the same line
                hits.append(f"{path.relative_to(SRC.parent.parent)}:{lineno}: {line.strip()}")
    return hits


def _unoffloaded_git_helper_calls() -> list[str]:
    """Every call to a `gitops`-backed helper (directly, or `catalog.load_catalog`/`committed_change`,
    which call into it) from inside an `async def` must be wrapped with `asyncio.to_thread` on the same
    line, so it can never block the event loop the way a bare `subprocess.run` would."""
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in ALLOWLISTED_FILES:
            continue
        async_ranges = _async_line_ranges(path)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not any(lo <= lineno <= hi for lo, hi in async_ranges):
                continue
            for tok in GIT_HELPER_TOKENS:
                if tok in line and "def " not in line and "asyncio.to_thread" not in line:
                    hits.append(f"{path.relative_to(SRC.parent.parent)}:{lineno}: {line.strip()}")
    return hits


def test_no_blocking_calls_in_async_paths() -> None:
    assert _blocking_call_sites() == []


def test_git_helpers_are_always_offloaded_from_async_code() -> None:
    assert _unoffloaded_git_helper_calls() == []
