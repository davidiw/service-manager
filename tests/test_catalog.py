"""Catalog loader validation, gaps, Markdown export, revision tracking, the shipped catalogs, and the
observed/approved split through the live server (observations never grant authority)."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from local_ops.catalog import (
    Catalog,
    CredentialReference,
    ServiceSpec,
    catalog_index_markdown,
    load_catalog,
    service_to_markdown,
)
from tests.conftest import write_catalog

REPO_ROOT = Path(__file__).resolve().parents[1]


def _service(front_matter: str, body: str = "notes") -> str:
    return "---\n" + textwrap.dedent(front_matter).strip() + "\n---\n" + body + "\n"


def _load(tmp_path: Path, *, extra: str = "", execution_allowed: bool = True) -> Catalog:
    root = tmp_path / "catalog"
    write_catalog(root, execution_allowed=execution_allowed, health_port=1, extra_services=extra)
    return load_catalog(root)


def _errors(cat: Catalog) -> list[str]:
    return [i.message for i in cat.errors]


# ----------------------------------------------------------------------------- validation errors


def test_baseline_fixture_catalog_is_clean(tmp_path: Path) -> None:
    cat = _load(tmp_path)
    assert cat.errors == []
    assert set(cat.services) == {"demo-app", "demo-app-alias", "demo-db", "doc-only", "gitops-app"}
    assert cat.meta.execution_allowed is True
    assert ("demo-app", "update") in cat.executable_operations()
    assert ("doc-only", "restart") not in cat.executable_operations()


def test_duplicate_service_id_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: demo-app
        name: Impostor
    """))
    assert any("duplicate service id demo-app" in m for m in _errors(cat))
    assert cat.services["demo-app"].spec.name == "Demo application"  # first file wins; duplicate never replaces it


def test_binding_environment_not_in_environments_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: env-mismatch
        name: Env mismatch
        environments: [demo]
        bindings:
          - id: b1
            environment: prod
            provider_id: kube-demo
    """))
    assert any("binding b1 environment 'prod' not in environments" in m for m in _errors(cat))
    assert "env-mismatch" not in cat.services


def test_execution_enabled_binding_missing_fields_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: half-bound
        name: Half bound
        environments: [demo]
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
            namespace: demo
            execution_enabled: true
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: b1
            health_checks: [ready_replicas]
    """))
    msgs = _errors(cat)
    assert any("has execution_enabled but is missing" in m and "workload_kind" in m and "cluster_identity" in m for m in msgs)


def test_unknown_health_check_id_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: bad-hc
        name: Bad health check
        environments: [demo]
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: b1
            health_checks: [ping_the_moon]
    """))
    assert any("names health check 'ping_the_moon', which is neither built in" in m for m in _errors(cat))


def test_unknown_executor_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: bad-exec
        name: Bad executor
        environments: [demo]
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
        operations:
          restart:
            executor: ssh_script
            kind: rollout_restart
            binding_id: b1
    """))
    assert any("unknown executor 'ssh_script'" in m for m in _errors(cat))


def test_operation_referencing_unknown_binding_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: dangling-op
        name: Dangling operation
        environments: [demo]
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
        operations:
          restart:
            executor: kubernetes_native
            kind: rollout_restart
            binding_id: nope
            health_checks: [ready_replicas]
    """))
    assert any("operation restart references unknown binding 'nope'" in m for m in _errors(cat))


def test_documentary_binding_is_valid_for_discovery_but_never_executable(tmp_path: Path) -> None:
    cat = _load(tmp_path, execution_allowed=False)
    # the documentary-only service loads fine (discovery can use it) ...
    assert "doc-only" in cat.services
    doc = cat.services["doc-only"].spec
    assert doc.bindings[0].source_state == "documentary" and doc.bindings[0].execution_enabled is False
    assert "restart" in doc.operations
    # ... but nothing is executable when the catalog disallows execution
    assert cat.executable_operations() == []


def test_execution_enabled_binding_under_execution_allowed_false_is_an_error(tmp_path: Path) -> None:
    cat = _load(tmp_path, execution_allowed=False)
    msgs = _errors(cat)
    assert any("demo-app: binding demo-deployment enables execution but catalog.execution_allowed is false" in m for m in msgs)
    assert any("gitops-app: binding gitops-binding enables execution" in m for m in msgs)
    assert not any("doc-only" in m for m in msgs)


def test_unknown_front_matter_fields_are_rejected(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: extra-field
        name: Extra field
        kube_password: hunter2
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
            ssh_key: abc
    """))
    msgs = _errors(cat)
    assert any("extra-field" not in cat.services and "kube_password" in m and "Extra inputs are not permitted" in m for m in msgs)
    assert any("ssh_key" in m for m in msgs)
    with pytest.raises(ValidationError):
        CredentialReference.model_validate({"id": "x", "kind": "k8s_secret", "held_in": "cluster", "value": "s3cr3t"})
    with pytest.raises(ValidationError):
        ServiceSpec.model_validate({"id": "x", "name": "x", "secret_value": "nope"})


# ----------------------------------------------------------------------------- gaps and exports


def test_gaps_report_the_expected_kinds(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: lonely
        name: Lonely service
        environments: [demo]
        depends_on: [ghost-service]
        knowledge_holders:
          - name: Carol
            role: original author
            status: departed
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
    """))
    assert cat.errors == []
    gaps = cat.gaps()
    kinds = {(g["service_id"], g["kind"]) for g in gaps}
    assert ("demo-db", "unknown_owner") in kinds
    assert ("demo-db", "contradiction") in kinds
    assert ("lonely", "knowledge_holder_departed") in kinds
    assert ("lonely", "dangling_dependency") in kinds
    assert ("demo-db", "missing_alert_source") in kinds
    assert ("demo-app", "missing_alert_source") not in kinds  # demo-app records an alerts source
    contra = next(g for g in gaps if g["service_id"] == "demo-db" and g["kind"] == "contradiction")
    assert contra["severity"] == "high" and "local-1" in contra["detail"] and "local-2" in contra["detail"]
    departed = next(g for g in gaps if g["kind"] == "knowledge_holder_departed")
    assert "Carol (original author) has departed" in departed["detail"]
    assert all(g["basis"] == "catalog" for g in gaps)


def test_service_to_markdown_renders_contradictions_and_never_secret_values(tmp_path: Path) -> None:
    cat = _load(tmp_path, extra=_service("""
        schema_version: 1
        id: with-creds
        name: Credentialed service
        environments: [demo]
        bindings:
          - id: b1
            environment: demo
            provider_id: kube-demo
        credential_refs:
          - id: db-admin-password
            kind: onepassword_item
            held_in: 1Password vault ops
            status: verified
            note: rotated quarterly
        contradictions:
          - topic: owner
            claims:
              - statement: owned by team A
                source: wiki
                dated: "2026-01-01"
              - statement: owned by team B
                source: pagerduty
            resolution_hint: ask both teams
    """))
    assert cat.errors == []
    md = service_to_markdown(cat.services["with-creds"], gaps=[g for g in cat.gaps() if g["service_id"] == "with-creds"])
    assert "## Contradictions requiring verification" in md
    assert "- **owner** (unresolved)" in md
    assert "owned by team A — wiki (2026-01-01)" in md
    assert "how to resolve: ask both teams" in md
    cred_section = md.split("## Credentials and signing identities referenced (never values)", 1)[1].split("## ", 1)[0]
    assert "`db-admin-password` (onepassword_item) held in: 1Password vault ops" in cred_section
    assert "status=verified" in cred_section and "rotated quarterly" in cred_section
    rendered_fields = {ln.strip() for ln in cred_section.splitlines() if ln.strip()}
    assert len(rendered_fields) == 1  # exactly the one reference line: id, kind, held_in, status, note
    for forbidden in ("value", "secret", "password=", "token"):
        assert forbidden not in cred_section.lower().replace("db-admin-password", "")
    assert "## Open gaps" in md and "unknown_owner" in md
    db_md = service_to_markdown(cat.services["demo-db"])
    assert "## Contradictions requiring verification" in db_md and "runs in local-2 — doc B" in db_md
    app_md = service_to_markdown(cat.services["demo-app"])
    assert "## Contradictions requiring verification" not in app_md
    assert "Observed runtime state" not in app_md  # no observed section without observations
    observed_md = service_to_markdown(cat.services["demo-app"], observed={"workloads": ["Deployment/demo-app ns=demo"]})
    assert "## Observed runtime state (released observations)" in observed_md


def test_catalog_index_markdown_lists_services(tmp_path: Path) -> None:
    cat = _load(tmp_path)
    md = catalog_index_markdown(cat, cat.gaps())
    assert md.startswith("# Service map: test-demo")
    assert f"Catalog revision `{cat.revision}` · execution_allowed=True · 5 services" in md
    for sid, doc in cat.services.items():
        assert f"[{doc.spec.name}]({sid}.md)" in md
    assert "| restart, update, rollback |" in md or "| rollback, restart, update |" in md
    assert "## Gap summary" in md and "contradiction: 1" in md
    seed = catalog_index_markdown(_load(tmp_path / "ro", execution_allowed=False))
    assert "execution_allowed=False" in seed
    assert "| none |" in seed and "| restart, update, rollback |" not in seed


def test_revision_changes_when_a_file_changes(tmp_path: Path) -> None:
    cat1 = _load(tmp_path)
    cat1b = load_catalog(tmp_path / "catalog")
    assert cat1.revision == cat1b.revision
    p = tmp_path / "catalog" / "services" / "demo-db.md"
    p.write_text(p.read_text(encoding="utf-8").replace("Fixture dependency.", "Fixture dependency (edited)."), encoding="utf-8")
    cat2 = load_catalog(tmp_path / "catalog")
    assert cat2.revision != cat1.revision
    assert cat2.services["demo-db"].file_hash != cat1.services["demo-db"].file_hash
    assert cat2.services["demo-app"].file_hash == cat1.services["demo-app"].file_hash
    ipath = tmp_path / "catalog" / "identities.yaml"
    ipath.write_text(ipath.read_text(encoding="utf-8") + "  - id: dave\n    kind: human\n    status: current\n", encoding="utf-8")
    cat3 = load_catalog(tmp_path / "catalog")
    assert cat3.revision != cat2.revision and len(cat3.identities) == len(cat2.identities) + 1


def test_demo_catalog_loads_clean_with_execution_allowed() -> None:
    cat = load_catalog(REPO_ROOT / "catalog" / "demo")
    assert cat.errors == []
    assert cat.meta.execution_allowed is True and cat.meta.seed is False
    assert ("demo-app", "update") in cat.executable_operations()


# ----------------------------------------------------------------------------- live server: observed vs approved


def _contains_key(obj: Any, key: str) -> bool:
    if isinstance(obj, dict):
        return key in obj or any(_contains_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_key(v, key) for v in obj)
    return False


async def _released_scan(env: Any) -> str:
    r = await env.set_mode("discovery-default", "discovery", "yolo")
    assert r.status_code == 303
    sub = await env.call("discovery", "discovery_scan", {"providers": ["kube-demo", "demo-fake"]})
    st = await env.wait("discovery", sub["request_id"])
    assert st["execution_status"] == "succeeded" and st["response_status"] == "released"
    return str(sub["request_id"])


@pytest.mark.asyncio
async def test_observed_state_joins_catalog_without_granting_authority(env: Any) -> None:
    rid = await _released_scan(env)
    cat = await env.call("discovery", "catalog_read", {})
    services = {s["spec"]["id"]: s for s in cat["services"]}
    # the demo-app Deployment is matched by cluster+namespace+kind+name to one of the services binding it
    matched = [(sid, w) for sid, s in services.items() for w in s["observed"]["workloads"] if w["name"] == "demo-app"]
    # the workload is claimed by two catalog services; both views show it, each marked as shared with the other
    assert {sid for sid, _ in matched} == {"demo-app", "demo-app-alias"}, matched
    assert all(w["shared_with"] for _, w in matched)
    owner, wl = matched[0]
    assert owner in ("demo-app", "demo-app-alias")
    assert wl["match_confidence"] == "observed"
    assert wl["match_basis"].startswith("cluster+namespace+kind+name")
    assert wl["namespace"] == "demo" and wl["kind"] == "Deployment" and wl["provider_id"] == "kube-demo"
    assert wl["desired_images"] and wl["rollout"]
    orphan = [o for o in cat["unresolved_observations"] if o["identity"].get("name") == "orphan-app"]
    assert len(orphan) == 1 and orphan[0]["match_service_id"] is None
    assert not any(o["resource_type"].startswith("k8s/") and o["identity"].get("name") == "demo-app" for o in cat["unresolved_observations"])

    gaps = await env.call("discovery", "catalog_gaps", {})
    assert any(g["kind"] == "unresolved_workload" and "orphan-app" in g["detail"] and g["basis"] == "observation" for g in gaps["gaps"])
    assert any(g["service_id"] == "demo-db" and g["kind"] in ("ambiguous_match", "contradiction") for g in gaps["gaps"])
    assert gaps["recent_scans"] and gaps["recent_scans"][0]["request_id"] == rid

    exp = await env.call("discovery", "catalog_export", {"format": "markdown"})
    assert "Observed runtime state" in exp["files"][f"{owner}.md"]
    assert "Deployment/demo-app ns=demo" in exp["files"][f"{owner}.md"]
    assert "Contradictions requiring verification" in exp["files"]["demo-db.md"]
    assert "Observed runtime state" not in exp["files"]["demo-db.md"]
    assert "# Service map" in exp["files"]["README.md"]

    # observed data never grants authority: the spec is exactly what the file says and observations carry no flags
    spec_bindings = {b["id"]: b for b in services["demo-app"]["spec"]["bindings"]}
    assert spec_bindings["demo-deployment"]["execution_enabled"] is True
    db_spec = {b["id"]: b for b in services["demo-db"]["spec"]["bindings"]}
    assert db_spec["db-doc"]["execution_enabled"] is False and db_spec["db-doc"]["source_state"] == "documentary"
    doc_only = {b["id"]: b for b in services["doc-only"]["spec"]["bindings"]}
    assert doc_only["prod-doc"]["execution_enabled"] is False
    for s in services.values():
        assert not _contains_key(s["observed"], "execution_enabled"), s["spec"]["id"]
    assert not _contains_key(cat["unresolved_observations"], "execution_enabled")
    # the catalog on disk is untouched by discovery
    assert env.core.catalog.revision == cat["catalog"]["revision"]
    assert env.core.catalog.service("demo-db").spec.bindings[0].execution_enabled is False
    assert env.core.catalog.executable_operations() == load_catalog(env.catalog_dir).executable_operations()


@pytest.mark.asyncio
async def test_shared_workload_is_attributed_to_the_primary_service_or_flagged(env: Any) -> None:
    await _released_scan(env)
    cat = await env.call("discovery", "catalog_read", {"service_id": "demo-app"})
    wl = [w for w in cat["services"][0]["observed"]["workloads"] if w["name"] == "demo-app"]
    assert wl and wl[0]["match_confidence"] == "observed"
    gaps = await env.call("discovery", "catalog_gaps", {"kinds": ["ambiguous_match"]})
    assert any("demo-app" in g["detail"] for g in gaps["gaps"])
