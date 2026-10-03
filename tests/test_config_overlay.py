"""The D29 provider-connection overlay: add-only merge onto the base server config, loaded from
`config/overlay.yaml` inside the catalog repository."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from local_ops.config import load_server_config, merge_config_overlay


def _write_base(path: Path) -> None:
    path.write_text(textwrap.dedent("""
        schema_version: 1
        server:
          bind_host: 127.0.0.1
          port: 8765
          state_dir: ./state
        credentials:
          - {id: base-cred, kind: env, env_var: X}
        providers:
          - id: base-kube
            kind: kubernetes
            context: base-context
            namespaces: []
    """).strip() + "\n", encoding="utf-8")


def test_merge_is_add_only_for_new_ids() -> None:
    base = {"providers": [{"id": "p1", "kind": "kubernetes", "context": "c1"}], "credentials": [{"id": "c1", "kind": "env", "env_var": "X"}]}
    overlay = {"providers": [{"id": "p2", "kind": "kubernetes", "context": "c2", "namespaces": []}], "credentials": [{"id": "c2", "kind": "kubeconfig_context", "context": "c2", "purpose": "read"}]}
    merged = merge_config_overlay(base, overlay)
    assert {p["id"] for p in merged["providers"]} == {"p1", "p2"}
    assert {c["id"] for c in merged["credentials"]} == {"c1", "c2"}


def test_merge_rejects_a_provider_id_collision() -> None:
    base = {"providers": [{"id": "p1", "kind": "kubernetes", "context": "c1"}]}
    overlay = {"providers": [{"id": "p1", "kind": "kubernetes", "context": "other"}]}
    with pytest.raises(ValueError, match="already exists"):
        merge_config_overlay(base, overlay)


def test_merge_rejects_a_credential_id_collision() -> None:
    base = {"credentials": [{"id": "c1", "kind": "env", "env_var": "X"}]}
    overlay = {"credentials": [{"id": "c1", "kind": "env", "env_var": "Y"}]}
    with pytest.raises(ValueError, match="already exists"):
        merge_config_overlay(base, overlay)


def test_pin_onto_provider_with_existing_identity_or_file_fails() -> None:
    base = {"providers": [{"id": "p1", "kind": "kubernetes", "context": "c1", "cluster_identity": {"kube_system_uid": "u"}}]}
    overlay = {"cluster_identity_pins": {"p1": {"kube_system_uid": "u2", "eks_arn": "arn:x"}}}
    with pytest.raises(ValueError, match="already has a cluster identity"):
        merge_config_overlay(base, overlay)

    base2 = {"providers": [{"id": "p2", "kind": "kubernetes", "context": "c2", "cluster_identity_file": "./x.json"}]}
    overlay2 = {"cluster_identity_pins": {"p2": {"kube_system_uid": "u2", "eks_arn": "arn:x"}}}
    with pytest.raises(ValueError, match="already has a cluster identity"):
        merge_config_overlay(base2, overlay2)


def test_pin_onto_non_kubernetes_or_unknown_provider_fails() -> None:
    base = {"providers": [{"id": "p1", "kind": "aws", "regions": ["us-east-1"]}]}
    with pytest.raises(ValueError, match="non-kubernetes"):
        merge_config_overlay(base, {"cluster_identity_pins": {"p1": {"kube_system_uid": "u"}}})
    with pytest.raises(ValueError, match="unknown provider"):
        merge_config_overlay(base, {"cluster_identity_pins": {"nope": {"kube_system_uid": "u"}}})


def test_pin_applies_cleanly_onto_an_eligible_provider() -> None:
    base = {"providers": [{"id": "p1", "kind": "kubernetes", "context": "c1"}]}
    merged = merge_config_overlay(base, {"cluster_identity_pins": {"p1": {"kube_system_uid": "u1", "eks_arn": "arn:x"}}})
    assert merged["providers"][0]["cluster_identity"] == {"kube_system_uid": "u1", "eks_arn": "arn:x"}


def test_config_hash_changes_with_the_overlay(tmp_path: Path) -> None:
    cfg_path = tmp_path / "server.yaml"
    _write_base(cfg_path)
    catalog = tmp_path / "catalog"
    (catalog / "config").mkdir(parents=True)
    without = load_server_config(cfg_path, catalog)
    (catalog / "config" / "overlay.yaml").write_text(
        "providers:\n  - {id: overlay-kube, kind: kubernetes, context: overlay-context, namespaces: []}\n"
        "credentials:\n  - {id: overlay-cred, kind: kubeconfig_context, context: overlay-context, kubeconfig: /tmp/kc, purpose: read}\n",
        encoding="utf-8",
    )
    with_overlay = load_server_config(cfg_path, catalog)
    assert with_overlay.config_hash != without.config_hash
    assert with_overlay.provider("overlay-kube") is not None
    assert without.provider("overlay-kube") is None
    # loading without a catalog_path at all behaves exactly as before (no overlay merge)
    bare = load_server_config(cfg_path)
    assert bare.provider("overlay-kube") is None
    assert bare.config_hash == without.config_hash


def test_overlay_conflict_fails_config_load_loudly(tmp_path: Path) -> None:
    cfg_path = tmp_path / "server.yaml"
    _write_base(cfg_path)
    catalog = tmp_path / "catalog"
    (catalog / "config").mkdir(parents=True)
    (catalog / "config" / "overlay.yaml").write_text("providers:\n  - {id: base-kube, kind: kubernetes, context: other}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        load_server_config(cfg_path, catalog)
