"""GitHub adapter tests against an httpx.MockTransport fake of the REST API. No network."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from local_ops.auth import Principal
from local_ops.catalog import load_catalog
from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import ErrorCode, OpsError, utcnow
from local_ops.operations.base import Budget, OperationContext
from local_ops.providers.base import DiscoveryScope, ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.github import (
    AUDIT_RETENTION_NOTE,
    MAX_FILE_BYTES,
    GitHubAdapter,
    safe_repo_path,
    validate_repo_full_name,
)
from local_ops.release import Sanitizer
from local_ops.storage import Database

TOKEN = "ghp_" + "x" * 36
BASE = "https://ghe.test/api/v3"

_open_dbs: list[Database] = []


async def make_ctx(tmp_path: Path, config: ServerConfig, sanitizer: Sanitizer) -> OperationContext:
    db = Database(tmp_path / "s.db", tmp_path / "ev")
    await db.open()
    _open_dbs.append(db)
    cat_dir = tmp_path / "catalog"
    (cat_dir / "services").mkdir(parents=True, exist_ok=True)
    (cat_dir / "catalog.yaml").write_text("name: t\n", encoding="utf-8")
    budget = Budget(deadline=utcnow() + timedelta(seconds=60), max_bytes=1_000_000)
    return OperationContext(db=db, config=config, catalog=load_catalog(cat_dir), providers=ProviderRegistry(), sanitizer=sanitizer, principal=Principal(id="p1", name="t", grants=frozenset()), request={"id": "req_x", "review_mode": "yolo"}, budget=budget)


@pytest.fixture(autouse=True)
async def _close_dbs() -> Any:
    yield
    while _open_dbs:
        await _open_dbs.pop().close()


@pytest.fixture
def gh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TEST_TOKEN", TOKEN)


def gh_config(*, org: str | None = "example", repositories: list[str] | None = None, url: str = BASE) -> ServerConfig:
    return ServerConfig(credentials=[CredentialRef(id="gh", kind="env", env_var="GH_TEST_TOKEN")], providers=[ProviderConfig(id="gh", kind="github", credential="gh", org=org, repositories=repositories or [], url=url, audit_log=True)])


class FakeGitHub:
    """Minimal GitHub REST fake with Link pagination for audit log and workflow runs."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.audit_pages: list[list[dict[str, Any]]] = [[]]
        self.audit_status = 200
        self.runs: list[dict[str, Any]] = []
        self.rate_limit_once = False
        self.files: dict[str, bytes] = {}
        self.file_types: dict[str, str] = {}
        self.deployments: list[dict[str, Any]] | None = None
        self.commits: dict[str, dict[str, Any]] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["x-github-api-version"] == "2022-11-28"
        assert str(request.url).startswith(BASE)
        path = request.url.path.removeprefix("/api/v3")
        params = dict(request.url.params)
        if self.rate_limit_once:
            self.rate_limit_once = False
            return httpx.Response(429, headers={"retry-after": "0"}, json={"message": "slow down"})
        if path == "/user":
            return httpx.Response(200, headers={"x-oauth-scopes": "repo, read:audit_log"}, json={"login": "alice", "type": "User"})
        if path == "/orgs/example/repos":
            return httpx.Response(200, json=[{"full_name": "example/demo-app"}, {"full_name": "example/gone"}])
        if path == "/repos/example/demo-app":
            return httpx.Response(200, json={"id": 1, "node_id": "R_1", "full_name": "example/demo-app", "default_branch": "main", "visibility": "private", "private": True, "pushed_at": "2026-09-30T09:00:00Z", "archived": False, "html_url": "https://ghe.test/example/demo-app"})
        if path == "/repos/example/gone":
            return httpx.Response(404, json={"message": "Not Found"})
        if path == "/repos/example/demo-app/actions/workflows":
            return httpx.Response(200, json={"total_count": 1, "workflows": [{"id": 10, "name": "deploy", "path": ".github/workflows/deploy.yml", "state": "active"}]})
        if path == "/repos/example/demo-app/actions/workflows/10/runs":
            return httpx.Response(200, json={"workflow_runs": [{"id": 101, "name": "deploy", "head_sha": "deadbeef", "event": "push", "status": "completed", "conclusion": "success", "actor": {"login": "carol-departed"}, "created_at": "2026-09-30T10:24:00Z"}]})
        if path == "/repos/example/demo-app/deployments":
            if self.deployments is not None:
                return httpx.Response(200, json=self.deployments)
            return httpx.Response(200, json=[{"id": 7, "sha": "deadbeef", "ref": "main", "environment": "production", "creator": {"login": "carol-departed"}, "created_at": "2026-09-30T10:25:00Z"}])
        if path == "/orgs/example/audit-log":
            if self.audit_status != 200:
                return httpx.Response(self.audit_status, json={"message": "Resource not accessible by integration"})
            idx = int(params.get("after", "0") or 0)
            headers = {}
            if idx + 1 < len(self.audit_pages):
                headers["Link"] = f'<{BASE}/orgs/example/audit-log?after={idx + 1}&per_page={params.get("per_page")}>; rel="next"'
            return httpx.Response(200, headers=headers, json=self.audit_pages[idx])
        if path == "/repos/example/demo-app/actions/runs":
            page = int(params.get("page", "1"))
            per = int(params["per_page"])
            chunk = self.runs[(page - 1) * per : page * per]
            headers = {}
            if page * per < len(self.runs):
                headers["Link"] = f'<{BASE}/repos/example/demo-app/actions/runs?per_page={per}&page={page + 1}>; rel="next"'
            return httpx.Response(200, headers=headers, json={"total_count": len(self.runs), "workflow_runs": chunk})
        if path.startswith("/repos/example/demo-app/contents/"):
            fpath = path.removeprefix("/repos/example/demo-app/contents/")
            if fpath not in self.files:
                return httpx.Response(404, json={"message": "Not Found"})
            data = self.files[fpath]
            ftype = self.file_types.get(fpath, "file")
            return httpx.Response(200, json={"type": ftype, "path": fpath, "sha": "abc", "size": len(data), "encoding": "base64", "content": base64.b64encode(data).decode(), "html_url": f"https://ghe.test/example/demo-app/blob/main/{fpath}"})
        if path.startswith("/repos/example/demo-app/commits/"):
            csha = path.removeprefix("/repos/example/demo-app/commits/")
            if csha not in self.commits:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json=self.commits[csha])
        return httpx.Response(500, json={"message": f"unexpected {path}"})


def adapter_for(fake: FakeGitHub, cfg: ServerConfig, sanitizer: Sanitizer | None = None) -> GitHubAdapter:
    return GitHubAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer or Sanitizer()), http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))


# ---------------------------------------------------------------- availability


async def test_check_availability_captures_login_and_scopes(gh_env: None) -> None:
    cfg = gh_config()
    av = await adapter_for(FakeGitHub(), cfg).check_availability(live=True)
    assert av.available and av.checked_live
    assert av.identity == {"login": "alice", "type": "User", "scopes": ["repo", "read:audit_log"], "base_url": BASE}
    assert TOKEN not in json.dumps(av.model_dump())


async def test_check_availability_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GH_TEST_TOKEN", raising=False)
    cfg = gh_config()
    av = await adapter_for(FakeGitHub(), cfg).check_availability(live=True)
    assert not av.available and av.reason == "credential_not_configured"


def test_describe_lists_retention_and_404_limitations() -> None:
    cfg = gh_config()
    d = GitHubAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer())).describe()
    assert AUDIT_RETENTION_NOTE in d.limitations
    assert any("404" in lim for lim in d.limitations)
    assert sorted(op.name for op in d.operations) == ["discover", "github_audit", "github_commit", "github_file", "github_runs_for_sha", "github_workflow_runs"]


# ---------------------------------------------------------------- discovery


async def test_discover_repositories_workflows_deployments_and_404(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()  # org set, repositories empty -> enumerate org repos
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    a = adapter_for(fake, cfg, sanitizer)
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await a.discover(ctx, DiscoveryScope(), ctx.budget)

    by_type = {}
    for o in report.observations:
        by_type.setdefault(o.resource_type, []).append(o)
    assert sorted(by_type) == ["github/deployment", "github/repository", "github/workflow"]
    repo = by_type["github/repository"][0]
    assert repo.resource_key == "gh:example/demo-app"
    assert repo.attributes["default_branch"] == "main" and repo.attributes["visibility"] == "private"
    assert repo.attributes["pushed_at"] == "2026-09-30T09:00:00Z" and repo.attributes["archived"] is False
    wf = by_type["github/workflow"][0]
    assert wf.resource_key == "gh:example/demo-app:workflow:10"
    assert wf.attributes["recent_runs"][0]["id"] == 101 and wf.attributes["recent_runs"][0]["actor"] == "carol-departed"
    assert {"kind": "owner", "target": "gh:example/demo-app"} in wf.relationships
    dep = by_type["github/deployment"][0]
    assert dep.resource_key == "gh:example/demo-app:deployment:7" and dep.attributes["environment"] == "production"
    assert sorted(report.completed_scopes) == sorted(["gh/example/demo-app", "gh/example/demo-app/workflows", "gh/example/demo-app/deployments"])
    missing = [u for u in report.unavailable if u["source"] == "gh/example/gone"]
    assert missing and missing[0]["reason"] == "repository_not_found_or_no_access"
    assert "not proof" in missing[0]["detail"]
    assert all(o.evidence_id for o in report.observations)
    rows = await ctx.db.evidence_for_request(ctx.request_id)
    assert len(rows) == 1 and rows[0]["kind"] == "github_repository_snapshot"
    assert TOKEN not in ctx.db.evidence_bytes(rows[0]).decode()


async def test_discover_explicit_repositories_only(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter_for(fake, cfg, sanitizer).discover(ctx, DiscoveryScope(), ctx.budget)
    assert not any(r.url.path.endswith("/orgs/example/repos") for r in fake.requests)
    assert report.unavailable == [] and len([o for o in report.observations if o.resource_type == "github/repository"]) == 1


async def test_discover_requested_repository_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter_for(fake, cfg, sanitizer).discover(ctx, DiscoveryScope(repositories=["example/demo-app", "other-org/other-repo"]), ctx.budget)
    assert not any(r.url.path == "/repos/other-org/other-repo" for r in fake.requests)
    refused = [u for u in report.unavailable if u["reason"] == "repository_outside_configured_scope"]
    assert refused and refused[0]["source"] == "gh/other-org/other-repo"
    assert len([o for o in report.observations if o.resource_type == "github/repository"]) == 1


def test_validate_repo_full_name_rejects_malformed_or_traversal() -> None:
    for bad in ("not-a-repo", "a/b/c", "./x/y", "x/..", "../x", ""):
        with pytest.raises(OpsError) as ei:
            validate_repo_full_name(bad)
        assert ei.value.code == ErrorCode.INVALID_ARGUMENT
    assert validate_repo_full_name("example/demo-app") == "example/demo-app"


async def test_discover_invalid_repository_reference_is_refused_not_fetched(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["../etc/passwd"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter_for(fake, cfg, sanitizer).discover(ctx, DiscoveryScope(), ctx.budget)
    assert fake.requests == []
    assert any(u["reason"] == "invalid_argument" for u in report.unavailable)


async def test_discover_capped_workflows_and_deployments_are_partial_not_completed(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    # 10 deployments == RECENT_DEPLOYMENTS cap: cannot prove there isn't an 11th (older) one.
    fake.deployments = [{"id": i, "sha": "deadbeef", "ref": "main", "environment": "production", "created_at": "2026-09-30T10:25:00Z"} for i in range(10)]
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    report = await adapter_for(fake, cfg, sanitizer).discover(ctx, DiscoveryScope(), ctx.budget)
    assert "gh/example/demo-app/deployments" in report.partial_scopes
    assert "gh/example/demo-app/deployments" not in report.completed_scopes
    deployment_keys = {o.resource_key for o in report.observations if o.resource_type == "github/deployment"}
    assert len(deployment_keys) == 10


# ---------------------------------------------------------------- audit log


async def test_audit_403_is_unavailable_not_error(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.audit_status = 403
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_audit", "filters": {"actor": "carol-departed"}}, ctx.budget)
    assert res.events == [] and res.items == []
    assert [u.reason for u in res.coverage.unavailable_scopes] == ["audit_log_not_available_for_plan_or_token"]
    assert res.coverage.unavailable_scopes[0].source == "gh/example/audit-log"
    assert res.coverage.source_retention_note == AUDIT_RETENTION_NOTE
    assert res.coverage.source_retention_known is False
    assert "not evidence" in res.coverage.conclusion_scope


async def test_audit_link_pagination_phrase_and_normalization(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.audit_pages = [
        [{"@timestamp": 1790000000000, "_document_id": "d1", "action": "repo.remove_branch_protection", "actor": "carol-departed", "repo": "example/demo-app", "actor_ip": "192.0.2.44"}],
        [{"@timestamp": 1790000060000, "_document_id": "d2", "action": "workflows.created_workflow", "actor": "carol-departed", "repo": "example/demo-app", "workflow": ".github/workflows/x.yml"}],
        [{"@timestamp": 1790000120000, "_document_id": "d3", "action": "org.update_member", "actor": "alice", "org": "example"}],
    ]
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_audit", "filters": {"actor": "carol-departed", "action": "repo"}, "time_range": {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}, "limits": {"max_events": 50, "max_pages": 10}}, ctx.budget)
    audit_reqs = [r for r in fake.requests if r.url.path.endswith("/audit-log")]
    assert len(audit_reqs) == 3
    first = dict(audit_reqs[0].url.params)
    assert first["phrase"] == "actor:carol-departed action:repo created:>=2026-09-01 created:<=2026-10-01"
    assert first["per_page"] == "50"
    assert dict(audit_reqs[1].url.params)["after"] == "1" and dict(audit_reqs[2].url.params)["after"] == "2"
    assert [e["event_id"] for e in res.events] == ["d1", "d2", "d3"]
    assert res.events[0]["provider"] == "github" and res.events[0]["account"] == "example"
    assert res.events[0]["event_key"] == "github:example:d1" and res.events[0]["source_ip"] == "192.0.2.44"
    assert res.events[0]["action"] == "repo.remove_branch_protection" and res.events[0]["resource"] == "example/demo-app"
    assert res.coverage.pagination_complete and res.coverage.completed_scopes == ["gh/example/audit-log"]
    assert res.coverage.source_retention_note == AUDIT_RETENTION_NOTE and AUDIT_RETENTION_NOTE in res.notes
    assert res.coverage.time_range_observed["first_event"] < res.coverage.time_range_observed["last_event"]  # type: ignore[operator]
    assert res.cursor is None and sorted(res.coverage.filters_provider_side) == ["action", "actor", "created"]
    rows = await ctx.db.evidence_for_request(ctx.request_id)
    assert len(rows) == 1 and rows[0]["kind"] == "github_audit"

    # max_pages stops early, exposes the `after` cursor for resumption
    fake.requests.clear()
    res2 = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_audit", "limits": {"max_pages": 1}}, ctx.budget)
    assert len(res2.events) == 1 and not res2.coverage.pagination_complete and res2.cursor == "1"
    assert any("max_pages" in g for g in res2.coverage.collection_gaps)
    res3 = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_audit", "limits": {"max_pages": 1}, "cursor": res2.cursor}, ctx.budget)
    assert [e["event_id"] for e in res3.events] == ["d2"] and res3.cursor == "2"


async def test_audit_requires_org(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(org=None, repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    with pytest.raises(OpsError) as ei:
        await adapter_for(FakeGitHub(), cfg, sanitizer).query(ctx, {"query_type": "github_audit"}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


async def test_audit_requested_org_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()  # configured org is "example"
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_audit", "scope": {"org": "someone-elses-org"}}, ctx.budget)
    assert not any(r.url.path.endswith("/audit-log") for r in fake.requests)
    assert [u.reason for u in res.coverage.unavailable_scopes] == ["org_outside_configured_scope"]
    assert res.events == [] and res.items == []


# ---------------------------------------------------------------- workflow runs


async def test_workflow_runs_normalized_and_paginated(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.runs = [
        {"id": 201, "name": "deploy", "workflow_id": 10, "head_sha": "deadbeef", "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "actor": {"login": "carol-departed"}, "created_at": "2026-09-30T10:24:00Z", "run_number": 41, "html_url": "https://ghe.test/example/demo-app/actions/runs/201"},
        {"id": 202, "name": "deploy", "workflow_id": 10, "head_sha": "cafef00d", "head_branch": "main", "event": "push", "status": "completed", "conclusion": "failure", "actor": {"login": "alice"}, "created_at": "2026-09-30T11:00:00Z", "run_number": 42},
        {"id": 203, "name": "ci", "workflow_id": 11, "head_sha": "0badf00d", "head_branch": "feat", "event": "pull_request", "status": "in_progress", "conclusion": None, "actor": {"login": "bob"}, "created_at": "2026-09-30T11:30:00Z", "run_number": 43},
    ]
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    res = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_workflow_runs", "scope": {"repository": "example/demo-app"}, "time_range": {"start": "2026-09-30T00:00:00Z", "end": "2026-10-01T00:00:00Z"}, "limits": {"max_events": 2, "max_pages": 5}}, ctx.budget)
    run_reqs = [r for r in fake.requests if r.url.path.endswith("/actions/runs")]
    assert dict(run_reqs[0].url.params) == {"per_page": "2", "created": "2026-09-30T00:00:00Z..2026-10-01T00:00:00Z"}
    assert len(res.items) == 2 and res.coverage.truncated and not res.coverage.pagination_complete
    assert res.items[0] == {"id": 201, "name": "deploy", "workflow_id": 10, "head_sha": "deadbeef", "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "actor": "carol-departed", "created_at": "2026-09-30T10:24:00Z", "updated_at": None, "run_number": 41, "html_url": "https://ghe.test/example/demo-app/actions/runs/201"}
    e0, e1 = res.events
    assert e0["event_key"] == "github:example/demo-app:run:201" and e0["action"] == "workflow_run:success" and e0["outcome"] == "success"
    assert e0["actor"] == "carol-departed" and e0["actor_type"] == "github_user" and e0["resource"] == "example/demo-app"
    assert e0["fields"]["head_sha"] == "deadbeef" and e0["fields"]["event"] == "workflow_dispatch" and e0["category"] == "deployment"
    assert e1["action"] == "workflow_run:failure" and e1["outcome"] == "failure"
    assert res.coverage.time_range_observed == {"first_event": "2026-09-30T10:24:00Z", "last_event": "2026-09-30T11:00:00Z"}

    res_all = await adapter_for(fake, cfg, sanitizer).query(ctx, {"query_type": "github_workflow_runs", "scope": {"repository": "example/demo-app"}, "limits": {"max_events": 100}}, ctx.budget)
    assert len(res_all.events) == 3 and res_all.coverage.pagination_complete
    assert res_all.events[2]["action"] == "workflow_run:in_progress" and res_all.events[2]["outcome"] is None


# ---------------------------------------------------------------- file reads


@pytest.mark.parametrize("bad", ["../secrets.yaml", "docs/../../x", "/etc/passwd", "~/x", "a//b", "a/./b/", "dir/", "", "C:\\x", "https://evil/x"])
def test_github_file_refuses_traversal_and_absolute(bad: str) -> None:
    with pytest.raises(OpsError) as ei:
        safe_repo_path(bad)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    "bad",
    [
        "configs/prod.tfvars?.yaml",  # `?` turns into a query string, landing on the refused prod.tfvars
        "configs/.env#.yaml",  # `#` turns into a fragment, landing on the refused .env
        "configs/app.yaml%2F..%2F..%2Fsecrets",  # percent-encoded path separator/traversal
        "configs%2Fapp.yaml",  # percent-encoded '/'
        "configs/app%2e%2e.yaml",  # percent-encoded '..'
        "configs/app.yaml%3Ffoo",  # percent-encoded '?'
        "configs/app .yaml",  # whitespace
        "configs/app\t.yaml",
    ],
)
def test_github_file_refuses_url_reinterpretable_characters(bad: str) -> None:
    """D30 review BLOCK 1: `?`, `#` and `%`-encoded separators/traversal must be rejected by the strict
    path charset before the allowlist regex ever runs, since httpx/GitHub would resolve them to a
    different, unvalidated path than the one the allowlist regex matched."""
    with pytest.raises(OpsError) as ei:
        safe_repo_path(bad)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


async def test_github_file_request_path_matches_validated_path_exactly(tmp_path: Path, gh_env: None) -> None:
    """D30 review BLOCK 1: the request actually sent to GitHub must carry exactly the validated,
    allowlisted path -- not something httpx or GitHub reinterprets via '?', '#' or percent-decoding."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/app.yaml"] = b"name: app\n"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    sent = fake.requests[-1]
    assert sent.url.raw_path.decode() == "/api/v3/repos/example/demo-app/contents/configs/app.yaml"


async def test_github_file_bounded_read(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/deploy.yaml"] = b"replicas: 3\nimage: repo:v1\n"
    fake.files["big.yaml"] = b"x: " + b"x" * (MAX_FILE_BYTES + 100)
    fake.file_types["big.yaml"] = "file"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/deploy.yaml", "ref": "main"}}, ctx.budget)
    assert res.items[0]["text"] == "replicas: 3\nimage: repo:v1\n"
    assert dict(fake.requests[-1].url.params) == {"ref": "main"} and fake.requests[-1].url.path.endswith("/contents/configs/deploy.yaml")
    assert res.coverage.completed_scopes == ["gh/example/demo-app/configs/deploy.yaml"] and res.raw_evidence_ids

    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "../../.env"}}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT
    assert not any("contents/.." in str(r.url) for r in fake.requests)

    missing = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/nope.yaml"}}, ctx.budget)
    assert missing.items == [] and missing.coverage.unavailable_scopes[0].reason == "file_or_repository_not_found_or_no_access"

    # configs/big.yaml does not exist in the fake; register it under its allowlisted name instead.
    fake.files["configs/big.yaml"] = fake.files.pop("big.yaml")
    big = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/big.yaml"}}, ctx.budget)
    assert big.items == [] and big.coverage.unavailable_scopes[0].reason == "file_too_large"


@pytest.mark.parametrize("path", ["runbooks/deploy.md", "configs/app.tfvars", "secrets.yaml", "configs/nested/app.yaml", "other.tf"])
def test_github_file_path_outside_allowlist_is_refused(path: str) -> None:
    from local_ops.providers.github import validate_allowlisted_path

    with pytest.raises(OpsError) as ei:
        validate_allowlisted_path(path)
    assert ei.value.code == ErrorCode.AUTHORIZATION_DENIED


@pytest.mark.parametrize("path", ["configs/app.yaml", "configs/app.yml", "backend.tf", ".github/workflows/deploy.yml", ".github/workflows/deploy.yaml", "catalog/services/app.yaml"])
def test_github_file_allowlisted_paths_pass(path: str) -> None:
    from local_ops.providers.github import validate_allowlisted_path

    assert validate_allowlisted_path(path) == path


async def test_github_file_refuses_symlink_submodule_and_binary(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/link.yaml"] = b"irrelevant"
    fake.file_types["configs/link.yaml"] = "symlink"
    fake.files["configs/sub.yaml"] = b"irrelevant"
    fake.file_types["configs/sub.yaml"] = "submodule"
    fake.files["configs/bin.yaml"] = b"\x00\x01binary"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)

    link = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/link.yaml"}}, ctx.budget)
    assert link.items == [] and link.coverage.unavailable_scopes[0].reason == "not_a_plain_file"

    sub = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/sub.yaml"}}, ctx.budget)
    assert sub.items == [] and sub.coverage.unavailable_scopes[0].reason == "not_a_plain_file"

    binary = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/bin.yaml"}}, ctx.budget)
    assert binary.items == [] and binary.coverage.unavailable_scopes[0].reason == "binary_content_refused"


async def test_github_file_redacts_committed_secret_in_evidence_and_result(tmp_path: Path, gh_env: None) -> None:
    """D30 (BLOCK 2a): a committed `password: foo` in an allowlisted YAML file is parsed and scrubbed
    structurally, so the adapter never returns or stores the original text -- not only at the
    evidence-store boundary (D18/D17), but in the in-process `items` result too, since the free-text
    scrub alone cannot apply field-name rules to an opaque blob."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/app.yaml"] = b"name: app\npassword: super-secret-value\n"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    # The adapter now scrubs YAML content structurally before returning it at all.
    assert "super-secret-value" not in res.items[0]["text"]
    assert "name: app" in res.items[0]["text"] and "password" in res.items[0]["text"]

    # Evidence storage sanitizes before writing (ctx.store_evidence) too; confirm the persisted copy is scrubbed.
    record = await ctx.db.evidence(res.raw_evidence_ids[0])
    assert record is not None
    stored_text = ctx.db.evidence_bytes(record).decode("utf-8")
    assert "super-secret-value" not in stored_text and "password" in stored_text

    # worker.py scrubs the same `items` structure with this Sanitizer before a response is ever
    # stored/released; applying it here demonstrates the released result stays redacted.
    released, removed = sanitizer.scrub({"items": res.items})
    assert "super-secret-value" not in json.dumps(released)


async def test_github_file_yaml_with_compound_and_env_style_secrets_is_scrubbed(tmp_path: Path, gh_env: None) -> None:
    """D30 review BLOCK 2: field-name rules (`db_password`, env-style `STRIPE_KEY`) only ever applied to
    structured data; a free-text scrub of the whole file missed them because of the old `password_assignment`
    pattern's `\\b` boundary. Parsing the YAML and scrubbing it structurally closes that."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/app.yaml"] = b"db_password: Sup3rS3cretValue\nvariables:\n  STRIPE_KEY: sk_live_abc\n  LOG_LEVEL: info\n"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    text = res.items[0]["text"]
    assert "Sup3rS3cretValue" not in text and "sk_live_abc" not in text
    assert "LOG_LEVEL: info" in text


async def test_github_file_unparseable_yaml_is_refused(tmp_path: Path, gh_env: None) -> None:
    """D30 review BLOCK 2a: a `.yaml` path that fails to parse must be refused outright, not disclosed
    as raw, unscrubbed text."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/app.yaml"] = b"this: is: not: valid: yaml: [}\n"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    assert res.items == []
    assert res.coverage.unavailable_scopes[0].reason == "unparseable_yaml"
    assert res.raw_evidence_ids == []


async def test_github_file_long_value_under_suffix_secret_key_is_fully_redacted(tmp_path: Path, gh_env: None) -> None:
    """Delta review BLOCK: re-serialization wrapped long values at 80 columns and the line-based text pass
    redacted only the first line. Keys like `faucet_signing_key` / `rpc_auth` are now redacted structurally
    and dumps never wrap."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid"
    fake.files["configs/app.yaml"] = f'faucet_signing_key: "{phrase}"\nrpc_auth: "user verylongpassphrase that keeps going on and on for sure yes"\nregion: us-west-2\n'.encode()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    text = res.items[0]["text"]
    for word in ("abandon", "achieve", "acid", "verylongpassphrase", "for sure yes"):
        assert word not in text
    assert "region: us-west-2" in text
    stored = await ctx.db.evidence(res.raw_evidence_ids[0])
    assert "acid" not in str(stored) and "verylongpassphrase" not in str(stored)


async def test_github_file_yaml_aliases_are_refused(tmp_path: Path, gh_env: None) -> None:
    """Delta review: alias expansion makes scrub/dump cost unbounded (alias bombs); aliases are refused."""
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    fake.files["configs/app.yaml"] = b"a: &a [x, x, x]\nb: [*a, *a, *a]\n"
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "example/demo-app", "path": "configs/app.yaml"}}, ctx.budget)
    assert res.items == []
    assert res.coverage.unavailable_scopes[0].reason == "unparseable_yaml"
    assert res.raw_evidence_ids == []


# ---------------------------------------------------------------- commit / runs-for-sha


async def test_github_commit_by_full_and_prefix_sha(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    sha = "a" * 40
    fake.commits[sha] = {
        "sha": sha, "html_url": f"https://ghe.test/example/demo-app/commit/{sha}",
        "commit": {"author": {"name": "Alice", "date": "2026-09-30T10:00:00Z"}, "message": "Deploy v2\n\nmore detail"},
        "parents": [{"sha": "b" * 40}],
    }
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_commit", "scope": {"repository": "example/demo-app", "sha": sha}}, ctx.budget)
    assert res.items[0] == {"repository": "example/demo-app", "sha": sha, "author_name": "Alice", "author_date": "2026-09-30T10:00:00Z", "message": "Deploy v2", "parents": ["b" * 40], "html_url": f"https://ghe.test/example/demo-app/commit/{sha}"}
    assert res.coverage.completed_scopes == [f"gh/example/demo-app/commit/{sha}"] and res.raw_evidence_ids

    missing = await a.query(ctx, {"query_type": "github_commit", "scope": {"repository": "example/demo-app", "sha": "f" * 10}}, ctx.budget)
    assert missing.items == [] and missing.coverage.unavailable_scopes[0].reason == "commit_or_repository_not_found_or_no_access"

    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "github_commit", "scope": {"repository": "example/demo-app", "sha": "not-hex!"}}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


async def test_github_runs_for_sha(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    sha = "c" * 40
    fake.runs = [{"id": 301, "name": "deploy", "path": ".github/workflows/deploy.yml", "event": "push", "status": "completed", "conclusion": "success", "created_at": "2026-09-30T12:00:00Z", "head_branch": "main", "head_sha": sha, "html_url": "https://ghe.test/x"}]
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_runs_for_sha", "scope": {"repository": "example/demo-app", "sha": sha}}, ctx.budget)
    assert res.items == [{"workflow_name": "deploy", "workflow_path": ".github/workflows/deploy.yml", "event": "push", "conclusion": "success", "created_at": "2026-09-30T12:00:00Z", "head_branch": "main", "run_id": 301, "html_url": "https://ghe.test/x"}]
    run_req = next(r for r in fake.requests if r.url.path.endswith("/actions/runs"))
    assert dict(run_req.url.params)["head_sha"] == sha

    with pytest.raises(OpsError) as ei:
        await a.query(ctx, {"query_type": "github_runs_for_sha", "scope": {"repository": "example/demo-app", "sha": sha[:10]}}, ctx.budget)
    assert ei.value.code == ErrorCode.INVALID_ARGUMENT


# ---------------------------------------------------------------- repository scope (D30 review, BLOCK 3)


async def test_github_commit_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_commit", "scope": {"repository": "other-org/other-repo", "sha": "a" * 40}}, ctx.budget)
    assert res.items == [] and res.raw_evidence_ids == []
    assert res.coverage.unavailable_scopes[0].reason == "repository_outside_configured_scope"
    assert not any("other-org" in str(r.url) for r in fake.requests)


async def test_github_runs_for_sha_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_runs_for_sha", "scope": {"repository": "other-org/other-repo", "sha": "c" * 40}}, ctx.budget)
    assert res.items == [] and res.raw_evidence_ids == []
    assert res.coverage.unavailable_scopes[0].reason == "repository_outside_configured_scope"
    assert not any("other-org" in str(r.url) for r in fake.requests)


async def test_github_workflow_runs_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_workflow_runs", "scope": {"repository": "other-org/other-repo"}}, ctx.budget)
    assert res.items == [] and res.events == [] and res.raw_evidence_ids == []
    assert res.coverage.unavailable_scopes[0].reason == "repository_outside_configured_scope"
    assert not any("other-org" in str(r.url) for r in fake.requests)


async def test_github_file_outside_configured_scope_is_refused(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config(repositories=["example/demo-app"])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_file", "scope": {"repository": "other-org/other-repo", "path": "configs/app.yaml"}}, ctx.budget)
    assert res.items == [] and res.raw_evidence_ids == []
    assert res.coverage.unavailable_scopes[0].reason == "repository_outside_configured_scope"
    assert not any("other-org" in str(r.url) for r in fake.requests)


async def test_github_commit_refused_with_neither_repositories_nor_org_configured(tmp_path: Path, gh_env: None) -> None:
    """Fail closed: with no `repositories` allowlist and no `org`, every repository is out of scope."""
    cfg = gh_config(org=None, repositories=[])
    sanitizer = Sanitizer()
    fake = FakeGitHub()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    a = adapter_for(fake, cfg, sanitizer)
    res = await a.query(ctx, {"query_type": "github_commit", "scope": {"repository": "example/demo-app", "sha": "a" * 40}}, ctx.budget)
    assert res.items == []
    assert res.coverage.unavailable_scopes[0].reason == "repository_outside_configured_scope"


# ---------------------------------------------------------------- rate limiting / misc


async def test_rate_limit_single_bounded_retry(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    fake = FakeGitHub()
    fake.rate_limit_once = True
    av = await adapter_for(fake, cfg).check_availability(live=True)
    assert av.available and av.identity is not None and av.identity["login"] == "alice"
    assert [r.url.path for r in fake.requests].count("/api/v3/user") == 2

    def always_limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0", "retry-after": "3600"}, json={"message": "API rate limit exceeded"})

    sanitizer = Sanitizer()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    b = GitHubAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer), http=httpx.AsyncClient(transport=httpx.MockTransport(always_limited)))
    res = await b.query(ctx, {"query_type": "github_audit"}, ctx.budget)
    assert res.events == [] and not res.coverage.pagination_complete and any("rate limited" in g for g in res.coverage.collection_gaps)
    av2 = await b.check_availability(live=True)
    assert not av2.available and av2.reason == "rate_limited"


async def test_unsupported_query(tmp_path: Path, gh_env: None) -> None:
    cfg = gh_config()
    sanitizer = Sanitizer()
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    with pytest.raises(OpsError) as ei:
        await adapter_for(FakeGitHub(), cfg, sanitizer).query(ctx, {"query_type": "github_checkout"}, ctx.budget)
    assert ei.value.code == ErrorCode.UNSUPPORTED_OPERATION
