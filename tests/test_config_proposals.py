"""Assistants propose provider connections; the server verifies, a human approves, the server applies
(DECISIONS D29). Service-level tests against `ConfigProposalService` directly, with a fake Kubernetes
client and no real cluster/AWS, per the fragility checkpoint in docs/agents/workflow.md."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from local_ops.auth import AuthService
from local_ops.config import ServerConfig, load_server_config
from local_ops.config_proposals import ConfigProposalService
from local_ops.models import Capability, OpsError
from local_ops.providers.base import ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.kube_fake import FakeKubeClient
from local_ops.providers.kubernetes import KubernetesAdapter
from local_ops.release import Sanitizer
from local_ops.storage import Database
from tests.conftest import Env, git_init_catalog

pytestmark = pytest.mark.asyncio

LIVE_ENDPOINT = "https://cluster-endpoint.example.invalid"


def _write_server_yaml(path: Path, state_dir: Path) -> None:
    path.write_text(textwrap.dedent(f"""
        schema_version: 1
        server:
          bind_host: 127.0.0.1
          port: 8765
          state_dir: {state_dir}
        credentials:
          - {{id: aws-main-sso, kind: aws_sso, profile: main-ro, purpose: read}}
        providers:
          - id: kube-unpinned
            kind: kubernetes
            context: fake-context
            namespaces: []
          - id: aws-main
            kind: aws
            expected_account_id: "111111111111"
            regions: [us-east-1]
          - id: aws-noacct
            kind: aws
            regions: [us-east-1]
    """).strip() + "\n", encoding="utf-8")


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.catalog_dir = tmp_path / "catalog"
        self.state_dir = tmp_path / "state"
        self.config_path = tmp_path / "server.yaml"
        self.db: Database
        self.config: ServerConfig
        self.svc: ConfigProposalService
        self.fake_kube: FakeKubeClient
        self.auth: AuthService

    async def build(self) -> None:
        (self.catalog_dir / "services").mkdir(parents=True)
        (self.catalog_dir / "catalog.yaml").write_text("name: t\nexecution_allowed: false\n", encoding="utf-8")
        git_init_catalog(self.catalog_dir)
        _write_server_yaml(self.config_path, self.state_dir)
        self.config = load_server_config(self.config_path, self.catalog_dir)
        self.db = Database(self.state_dir / "db.sqlite", self.state_dir / "evidence")
        await self.db.open()
        self.auth = AuthService(self.db, self.config)
        sanitizer = Sanitizer()
        resolver = CredentialResolver(self.config, sanitizer)
        self.fake_kube = FakeKubeClient(identity={"kube_system_uid": "live-uid-1", "server": LIVE_ENDPOINT, "git_version": "v1.29", "context": "fake-context"})
        kube_cfg = self.config.provider("kube-unpinned")
        assert kube_cfg is not None
        adapter = KubernetesAdapter(kube_cfg, self.config, None, client=self.fake_kube)
        registry = ProviderRegistry()
        registry.register(adapter)
        self.overrides: dict[str, Any] = {"kube-unpinned": adapter}
        self.config_ref = {"config": self.config}
        self.providers_ref = {"providers": registry}
        self.svc = ConfigProposalService(self.db, self.config_ref, self.providers_ref, resolver, sanitizer, self.catalog_dir, self.auth, self.overrides)

    async def close(self) -> None:
        await self.db.close()

    async def principal(self, name: str = "agent") -> Any:
        p, _ = await self.auth.create_key(name, [Capability.READ])
        return p

    async def observation(self, *, account: str = "111111111111", endpoint: str = LIVE_ENDPOINT, released: bool = True, principal_id: str | None = None) -> str:
        rows = await self.db.upsert_observations("req_scan", [{
            "provider_id": "aws-main", "resource_key": "arn:aws:eks:us-east-1:111111111111:cluster/demo",
            "resource_type": "aws/eks_cluster", "identity": {"account": account, "region": "us-east-1", "arn": "arn:aws:eks:us-east-1:111111111111:cluster/demo", "name": "demo"},
            "attributes": {"endpoint": endpoint},
        }])
        oid = rows[0]
        if released:
            async with self.db.tx() as c:
                await c.execute("UPDATE observations SET released_to=? WHERE id=?", (json.dumps([principal_id]), oid))
        return oid


@pytest.fixture(autouse=True)
def _home_is_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A proposed kubeconfig must resolve under the server user's own `~/.kube/`; every test treats
    `tmp_path` as that home so fixtures stay self-contained instead of touching the real one."""
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.fixture
async def h(tmp_path: Path):  # type: ignore[no-untyped-def]
    harness = Harness(tmp_path)
    await harness.build()
    try:
        yield harness
    finally:
        await harness.close()


def _kubeconfig(tmp_path: Path) -> Path:
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir(exist_ok=True)
    p = kube_dir / "kubeconfig"
    p.write_text(textwrap.dedent("""
        apiVersion: v1
        kind: Config
        current-context: good-context
        clusters:
          - name: c1
            cluster: {server: "https://x.invalid"}
        contexts:
          - name: good-context
            context: {cluster: c1, user: u1}
          - name: badexec-context
            context: {cluster: c1, user: u2}
          - name: roleexec-context
            context: {cluster: c1, user: u3}
          - name: unknownprofile-context
            context: {cluster: c1, user: u4}
          - name: noexec-context
            context: {cluster: c1, user: u5}
        users:
          - name: u1
            user:
              exec: {command: aws, args: ["eks", "get-token", "--cluster-name", "demo", "--region", "us-east-1", "--profile", "main-ro"]}
          - name: u2
            user:
              exec: {command: kubectl-oidc-login, args: ["get-token"]}
          - name: u3
            user:
              exec: {command: aws, args: ["eks", "get-token", "--cluster-name", "demo", "--role-arn", "arn:aws:iam::1:role/x"]}
          - name: u4
            user:
              exec: {command: aws, args: ["eks", "get-token", "--profile", "ghost-profile"]}
          - name: u5
            user:
              client-certificate: /tmp/does-not-matter.crt
    """).strip() + "\n", encoding="utf-8")
    p.chmod(0o600)
    return p


# ------------------------------------------------------------------ kubernetes_connection


async def test_connection_with_read_profile_exec_is_accepted(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    res = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "good-context", "allow_exec_plugins": True}, "reason")
    assert res["status"] == "pending_review"
    out = await h.svc.accept(res["proposal_id"], "reviewer", None)
    assert out["commit"]
    merged = h.svc._current_merged()
    assert merged.provider("kube-new") is not None and merged.credential("kube-new-cred") is not None


async def test_connection_with_unknown_profile_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="not a configured aws_sso credential"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "unknownprofile-context", "allow_exec_plugins": True}, None)


async def test_connection_with_non_aws_exec_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="only the read-only"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "badexec-context", "allow_exec_plugins": True}, None)


async def test_connection_with_role_arn_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="role-arn"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "roleexec-context", "allow_exec_plugins": True}, None)


async def test_connection_with_missing_context_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="no context"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "nope"}, None)


async def test_connection_with_credential_shaped_reason_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="credential-shaped"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "good-context"}, "token ghp_" + "a" * 36)


async def test_connection_colliding_provider_id_is_refused(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    with pytest.raises(OpsError, match="already exists"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-unpinned", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "good-context"}, None)


async def test_connection_with_path_env_override_is_refused_at_propose(h: Harness, tmp_path: Path) -> None:
    """The exec-shape check applies at propose too, not only at runtime connect."""
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir(exist_ok=True)
    kc = kube_dir / "evil-kubeconfig"
    kc.write_text(textwrap.dedent("""
        apiVersion: v1
        kind: Config
        current-context: c
        clusters: [{name: k, cluster: {server: "https://x.invalid"}}]
        contexts: [{name: c, context: {cluster: k, user: u}}]
        users:
          - name: u
            user:
              exec: {command: aws, args: ["eks", "get-token", "--profile", "main-ro"], env: [{name: PATH, value: "/tmp/evil"}]}
    """).strip() + "\n", encoding="utf-8")
    kc.chmod(0o600)
    p = await h.principal()
    with pytest.raises(OpsError, match="PATH"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "c", "allow_exec_plugins": True}, None)


async def test_connection_kubeconfig_outside_dot_kube_is_refused(h: Harness, tmp_path: Path) -> None:
    outside = tmp_path / "not-dot-kube"
    outside.mkdir()
    kc = outside / "kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\ncontexts: []\n", encoding="utf-8")
    kc.chmod(0o600)
    p = await h.principal()
    with pytest.raises(OpsError, match=r"\.kube"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "c"}, None)


async def test_connection_group_writable_kubeconfig_is_refused(h: Harness, tmp_path: Path) -> None:
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir(exist_ok=True)
    kc = kube_dir / "writable-kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\ncontexts: []\n", encoding="utf-8")
    kc.chmod(0o664)
    p = await h.principal()
    with pytest.raises(OpsError, match="writable"):
        await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-new", "credential_id": "kube-new-cred", "kubeconfig": str(kc), "context": "c"}, None)


async def test_connection_accept_commits_the_resolved_kubeconfig_path_not_the_raw_string(h: Harness, tmp_path: Path) -> None:
    """Finding 5a: the overlay must hold the fully resolved path the server actually validated, never
    whatever (possibly symlinked, relative, or un-expanded) string the proposer supplied."""
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir(exist_ok=True)
    real = kube_dir / "real-kubeconfig"
    real.write_text(textwrap.dedent("""
        apiVersion: v1
        kind: Config
        current-context: good-context
        clusters: [{name: c1, cluster: {server: "https://x.invalid"}}]
        contexts: [{name: good-context, context: {cluster: c1, user: u1}}]
        users: [{name: u1, user: {}}]
    """).strip() + "\n", encoding="utf-8")
    real.chmod(0o600)
    link = kube_dir / "link-kubeconfig"
    link.symlink_to(real)
    p = await h.principal()
    res = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-sym", "credential_id": "kube-sym-cred", "kubeconfig": str(link), "context": "good-context"}, None)
    await h.svc.accept(res["proposal_id"], "reviewer", None)
    overlay = yaml.safe_load((h.catalog_dir / "config" / "overlay.yaml").read_text(encoding="utf-8"))
    stored = next(c["kubeconfig"] for c in overlay["credentials"] if c["id"] == "kube-sym-cred")
    assert stored == str(real.resolve())
    assert stored != str(link)


async def test_connection_stale_at_accept_marks_status_stale_not_rejected(h: Harness, tmp_path: Path) -> None:
    """A collision discovered on re-validation at accept must land on `stale` (like cluster_pin), so the
    distinct human decision to reject is never silently recorded on the proposer's behalf."""
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    res = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-race", "credential_id": "kube-race-cred", "kubeconfig": str(kc), "context": "good-context", "allow_exec_plugins": True}, None)
    # Someone else's provider with the same id lands first.
    overlay_file = h.catalog_dir / "config" / "overlay.yaml"
    overlay_file.parent.mkdir(exist_ok=True)
    overlay_file.write_text(yaml.safe_dump({"providers": [{"id": "kube-race", "kind": "kubernetes", "context": "other", "namespaces": []}]}), encoding="utf-8")
    _git_add_commit(h.catalog_dir, "config/overlay.yaml", "race")
    with pytest.raises(OpsError, match="stale"):
        await h.svc.accept(res["proposal_id"], "reviewer", None)
    row = await h.db.config_proposal(res["proposal_id"])
    assert row is not None and row["status"] == "stale"


async def test_concurrent_accepts_both_land_in_the_overlay(h: Harness, tmp_path: Path) -> None:
    import asyncio

    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    res1 = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-c1", "credential_id": "kube-c1-cred", "kubeconfig": str(kc), "context": "good-context", "allow_exec_plugins": True}, None)
    res2 = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-c2", "credential_id": "kube-c2-cred", "kubeconfig": str(kc), "context": "good-context", "allow_exec_plugins": True}, None)
    out1, out2 = await asyncio.gather(h.svc.accept(res1["proposal_id"], "reviewer", None), h.svc.accept(res2["proposal_id"], "reviewer", None))
    assert out1["commit"] and out2["commit"] and out1["commit"] != out2["commit"]
    merged = h.svc._current_merged()
    assert merged.provider("kube-c1") is not None and merged.provider("kube-c2") is not None


# ------------------------------------------------------------------ cluster_pin


async def test_pin_with_matching_endpoint_is_accepted_and_uses_live_identity(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(released=True, principal_id=p.id)
    res = await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)
    assert res["status"] == "pending_review"
    out = await h.svc.accept(res["proposal_id"], "reviewer", None)
    assert out["commit"]
    merged = h.svc._current_merged()
    pinned = merged.provider("kube-unpinned")
    assert pinned is not None and pinned.cluster_identity == {"kube_system_uid": "live-uid-1", "eks_arn": "arn:aws:eks:us-east-1:111111111111:cluster/demo"}


async def test_pin_with_endpoint_mismatch_is_refused(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(endpoint="https://other-cluster.invalid", released=True, principal_id=p.id)
    with pytest.raises(OpsError, match="does not match"):
        await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)


async def test_pin_on_unreleased_observation_is_refused(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(released=False)
    with pytest.raises(OpsError, match="not released"):
        await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)


async def test_pin_from_aws_provider_without_expected_account_id_is_refused(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(account="222222222222", released=True, principal_id=p.id)
    with pytest.raises(OpsError, match="does not match any configured AWS provider"):
        await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)


async def test_pin_reverification_failure_at_accept_marks_stale(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(released=True, principal_id=p.id)
    res = await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)
    h.fake_kube.identity["server"] = "https://moved.invalid"
    with pytest.raises(OpsError, match="stale"):
        await h.svc.accept(res["proposal_id"], "reviewer", None)
    row = await h.db.config_proposal(res["proposal_id"])
    assert row is not None and row["status"] == "stale"


# ------------------------------------------------------------------ accept/reject/hot-reload


async def test_reject_leaves_the_overlay_unchanged(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(released=True, principal_id=p.id)
    res = await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)
    overlay_path = h.catalog_dir / "config" / "overlay.yaml"
    assert not overlay_path.exists()
    await h.svc.reject(res["proposal_id"], "reviewer", "no thanks")
    assert not overlay_path.exists()
    row = await h.db.config_proposal(res["proposal_id"])
    assert row is not None and row["status"] == "rejected"


def _last_commit_paths(root: Path) -> list[str]:
    import subprocess

    out = subprocess.run(["git", "-C", str(root), "show", "--name-only", "--format=", "HEAD"], capture_output=True, text=True, check=True)
    return [ln.strip() for ln in out.stdout.strip().splitlines() if ln.strip()]


async def test_accept_commits_exactly_one_path(h: Harness) -> None:
    p = await h.principal()
    oid = await h.observation(released=True, principal_id=p.id)
    res = await h.svc.propose_pin(p, Capability.READ, {"provider_id": "kube-unpinned", "observation_id": oid}, None)
    await h.svc.accept(res["proposal_id"], "reviewer", None)
    assert _last_commit_paths(h.catalog_dir) == ["config/overlay.yaml"]


async def test_hot_reload_adds_the_new_provider_and_keeps_unchanged_adapter_identity(h: Harness, tmp_path: Path) -> None:
    p = await h.principal()
    kc = _kubeconfig(tmp_path)
    before_adapter = h.providers_ref["providers"].get("kube-unpinned")
    res = await h.svc.propose_connection(p, Capability.READ, {"provider_id": "kube-brand-new", "credential_id": "kube-brand-new-cred", "kubeconfig": str(kc), "context": "good-context", "allow_exec_plugins": True}, None)
    await h.svc.accept(res["proposal_id"], "reviewer", None)
    registry = h.providers_ref["providers"]
    assert registry.get("kube-brand-new") is not None  # new provider now live, no restart
    assert registry.get("kube-unpinned") is before_adapter  # unchanged provider's adapter object reused
    assert h.config_ref["config"].provider("kube-brand-new") is not None


# ------------------------------------------------------------------ MCP + web route wiring (same core path)


async def test_mcp_and_web_route_wiring(env: Env, tmp_path: Path) -> None:
    """Both the MCP tool and the reviewer web routes call the same `core.config_proposals`; exercised
    together to cover the new surfaces end to end (CSRF/session, banner count), per DECISIONS D29."""
    kc = _kubeconfig(tmp_path)
    # env's shared config has no aws_sso credential, so this uses a context without an exec plugin.
    sub = await env.call("read", "config_propose", {"kind": "kubernetes_connection", "fields": {"provider_id": "kube-mcp-new", "credential_id": "kube-mcp-new-cred", "kubeconfig": str(kc), "context": "noexec-context"}, "reason": "mcp smoke test"})
    assert "__error__" not in sub and sub["status"] == "pending_review"
    pid = sub["proposal_id"]

    listed = await env.call("read", "config_proposals", {})
    assert pid in [p["proposal_id"] for p in listed["proposals"]]

    bad = await env.call("read", "config_propose", {"kind": "not_a_kind", "fields": {}})
    assert bad["__error__"]["error"] == "invalid_argument"

    c = await env.reviewer()
    page = await c.get("/proposals")
    assert page.status_code == 200 and pid in page.text
    review_page = await c.get("/review")
    assert "config proposals" in review_page.text  # banner shown on another page too

    csrf = await env.csrf(c)
    bad_csrf = await c.post(f"/config-proposals/{pid}/accept", data={"csrf": "wrong"})
    assert bad_csrf.status_code == 403

    r = await c.post(f"/config-proposals/{pid}/accept", data={"csrf": csrf, "note": "looks fine"})
    assert r.status_code == 303
    row = await env.core.db.config_proposal(pid)
    assert row is not None and row["status"] == "accepted" and row["overlay_commit"]
    assert env.core.providers.get("kube-mcp-new") is not None  # hot-reloaded, no restart
    assert env.core.config.provider("kube-mcp-new") is not None


def _git_add_commit(root: Path, path: str, message: str) -> None:
    import subprocess

    subprocess.run(["git", "-C", str(root), "add", path], check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(root), "commit", "-q", "-m", message], check=True, capture_output=True)


async def test_overlay_only_commit_leaves_catalog_revision_unchanged(env: Env) -> None:
    before = env.core.catalog.revision
    (env.catalog_dir / "config").mkdir(exist_ok=True)
    (env.catalog_dir / "config" / "overlay.yaml").write_text("providers: []\n", encoding="utf-8")
    _git_add_commit(env.catalog_dir, "config/overlay.yaml", "overlay only")
    env.core.reload_catalog()
    assert env.core.catalog.revision == before

    f = env.catalog_dir / "services" / "demo-app.md"
    f.write_text(f.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    _git_add_commit(env.catalog_dir, "services/demo-app.md", "real change")
    env.core.reload_catalog()
    assert env.core.catalog.revision != before
