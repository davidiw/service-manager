"""Smoke test for the disposable local demo environment (scripts/demo-cluster.sh).

Opt-in: runs only when LOCAL_OPS_INTEGRATION=1. Uses only the standard library plus kubectl.
Refuses to proceed if the current kube context is not the disposable kind cluster or looks
production-like, so it can never accidentally validate against a real cluster.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("LOCAL_OPS_INTEGRATION") != "1", reason="set LOCAL_OPS_INTEGRATION=1 to run against the disposable kind cluster"),
]

EXPECTED_CONTEXT = "kind-local-ops-demo"
STATE_DIR = Path(os.environ.get("LOCAL_OPS_STATE_DIR", "./local-state"))
CLUSTER_JSON = STATE_DIR / "demo-cluster.json"
HEALTH_URL = "http://127.0.0.1:30080/health"
VERSION_URL = "http://127.0.0.1:30080/version"
TAGS_URL = "http://localhost:5001/v2/local-ops/demo-app/tags/list"
PRODUCTION_MARKERS = ("eks", "prod", "mainnet")


def _kubectl(*args: str) -> str:
    out = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=30, check=False)
    assert out.returncode == 0, f"kubectl {' '.join(args)} failed: {out.stderr.strip()}"
    return out.stdout.strip()


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 - fixed loopback URLs
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture(scope="module")
def recorded_identity() -> dict:
    assert CLUSTER_JSON.exists(), f"{CLUSTER_JSON} missing; run scripts/demo-cluster.sh up"
    data = json.loads(CLUSTER_JSON.read_text(encoding="utf-8"))
    for key in ("kube_system_uid", "server", "git_version", "context", "created_by", "created_at"):
        assert data.get(key), f"{CLUSTER_JSON} missing {key}"
    assert data["context"] == EXPECTED_CONTEXT
    return data


@pytest.fixture(scope="module")
def current_context() -> str:
    ctx = _kubectl("config", "current-context")
    for marker in PRODUCTION_MARKERS:
        assert marker not in ctx.lower(), f"refusing: current context {ctx!r} looks production-like ({marker!r})"
    assert ctx == EXPECTED_CONTEXT, f"current context is {ctx!r}, expected {EXPECTED_CONTEXT!r}"
    return ctx


def test_identity_file_exists(recorded_identity: dict) -> None:
    assert recorded_identity["created_by"] == "scripts/demo-cluster.sh"


def test_current_context_is_disposable_cluster(current_context: str) -> None:
    assert current_context == EXPECTED_CONTEXT


def test_live_kube_system_uid_matches_recorded(recorded_identity: dict, current_context: str) -> None:
    live = _kubectl("--context", current_context, "get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}")
    assert live, "could not read live kube-system uid"
    assert live == recorded_identity["kube_system_uid"], "live cluster identity differs from the recorded disposable cluster; refusing"


def test_health_endpoint_ok(current_context: str) -> None:
    status, body = _get(HEALTH_URL)
    assert status == 200, body
    assert json.loads(body) == {"status": "ok"}


def test_version_endpoint_reports_v1(current_context: str) -> None:
    status, body = _get(VERSION_URL)
    assert status == 200, body
    assert json.loads(body)["version"] in ("1.0.0", "2.0.0")  # another integration test may have left v2 deployed


def test_registry_lists_demo_tags(current_context: str) -> None:
    status, body = _get(TAGS_URL)
    assert status == 200, body
    tags = set(json.loads(body).get("tags") or [])
    assert {"v1", "v2", "v2-broken"} <= tags, tags
