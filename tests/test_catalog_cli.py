"""Catalog CLI stays a presentation layer over the approved catalog loader."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from local_ops.catalog import CatalogMeta, IdentityRecord, ServiceSpec
from local_ops.cli import app


def _documentary_catalog(tmp_path: Path) -> Path:
    root = tmp_path / "catalog"
    (root / "services").mkdir(parents=True)
    (root / "catalog.yaml").write_text("name: documentary\nexecution_allowed: false\n", encoding="utf-8")
    (root / "services" / "service.md").write_text(
        "---\nid: docs\nname: Documentation\nunknowns: [runtime location]\n---\n", encoding="utf-8"
    )
    return root


def test_catalog_validate_preserves_default_text_output(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["catalog", "validate", str(_documentary_catalog(tmp_path))])

    assert result.exit_code == 0
    assert "1 services, revision" in result.output
    assert "execution_allowed=False" in result.output


def test_catalog_validate_strict_rejects_missing_empty_and_warnings(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    result = CliRunner().invoke(app, ["catalog", "validate", str(missing), "--strict", "--format", "json"])

    assert result.exit_code == 1
    body = json.loads(result.output)
    assert body["valid"] is False
    assert {issue["message"] for issue in body["errors"]} >= {
        "catalog path is missing",
        "catalog.yaml is missing",
        "catalog has no services",
    }

    empty = tmp_path / "empty"
    empty.mkdir()
    result = CliRunner().invoke(app, ["catalog", "validate", str(empty), "--strict", "--format", "json"])
    assert result.exit_code == 1
    assert "catalog path is missing" not in {issue["message"] for issue in json.loads(result.output)["errors"]}

    root = _documentary_catalog(tmp_path)
    (root / "services" / "service.md").write_text(
        "---\nid: docs\nname: Documentation\ndepends_on: [missing]\n---\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["catalog", "validate", str(root), "--strict", "--format", "json"])
    assert result.exit_code == 1
    assert "strict validation rejects warning" in {issue["message"] for issue in json.loads(result.output)["errors"]}


def test_catalog_validate_documentary_refuses_enabled_catalog(tmp_path: Path) -> None:
    root = _documentary_catalog(tmp_path)
    (root / "catalog.yaml").write_text("name: executable\nexecution_allowed: true\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["catalog", "validate", str(root), "--documentary", "--format", "json"])

    assert result.exit_code == 1
    assert "documentary catalogs must set execution_allowed to false" in result.output


def test_catalog_report_is_documentary_and_includes_unknowns(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["catalog", "report", str(_documentary_catalog(tmp_path))])

    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["basis"] == "catalog_configuration"
    assert body["approval_verified"] is False
    assert body["live_verified"] is False
    assert body["services"][0]["unknowns"] == ["runtime location"]
    assert "not verified approved, executable or ready" in body["limitations"][1]


def test_catalog_report_rejects_missing_or_empty_catalog_and_never_claims_approval(tmp_path: Path) -> None:
    runner = CliRunner()
    for path in (tmp_path / "missing", tmp_path / "empty"):
        if path.name == "empty":
            path.mkdir()
        result = runner.invoke(app, ["catalog", "report", str(path)])
        assert result.exit_code == 1
        body = json.loads(result.output)
        assert body["valid"] is False
        assert body["approval_verified"] is False
        assert body["basis"] == "catalog_configuration"


def test_catalog_report_of_a_valid_draft_is_not_approval_or_operability(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["catalog", "report", str(_documentary_catalog(tmp_path))])

    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["valid"] is True
    assert body["approval_verified"] is False
    assert body["live_verified"] is False
    assert "approved_configuration" not in body


def test_catalog_schema_uses_canonical_models_and_rejects_invalid_kind() -> None:
    runner = CliRunner()
    for kind, model in (("service", ServiceSpec), ("catalog", CatalogMeta), ("identity", IdentityRecord)):
        result = runner.invoke(app, ["catalog", "schema", "--kind", kind])
        assert result.exit_code == 0
        assert json.loads(result.output) == model.model_json_schema()

    assert runner.invoke(app, ["catalog", "schema", "--kind", "bad"]).exit_code == 2


def test_catalog_validate_invalid_metadata_is_controlled(tmp_path: Path) -> None:
    root = _documentary_catalog(tmp_path)
    secret = "metadata-secret-value"
    (root / "catalog.yaml").write_text(f"name: [{secret}]\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["catalog", "validate", str(root), "--format", "json"])

    assert result.exit_code == 1
    assert secret not in result.output
    issue = json.loads(result.output)["errors"][0]
    assert issue["message"] == "invalid catalog metadata"
    assert issue["error_type"] == "ValidationError"


def test_catalog_validate_invalid_service_identity_and_yaml_do_not_echo_input(tmp_path: Path) -> None:
    root = _documentary_catalog(tmp_path)
    secret = "very-secret-input-value"
    (root / "services" / "service.md").write_text(
        f"---\nid: docs\nname: [{secret}]\n---\n", encoding="utf-8"
    )
    (root / "identities.yaml").write_text(
        f"identities:\n  - name: [{secret}]\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["catalog", "validate", str(root), "--format", "json"])
    assert result.exit_code == 1
    assert secret not in result.output
    messages = {issue["message"] for issue in json.loads(result.output)["errors"]}
    assert messages == {"invalid service definition", "invalid identity definitions"}

    (root / "services" / "service.md").write_text("---\nid: [\n---\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["catalog", "validate", str(root), "--format", "json"])
    assert result.exit_code == 1
    assert "invalid service definition" in {issue["message"] for issue in json.loads(result.output)["errors"]}


def test_catalog_commands_reject_invalid_options_without_building_core(monkeypatch, tmp_path: Path) -> None:
    def fail_core(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("catalog commands must remain offline")

    monkeypatch.setattr("local_ops.cli._core", fail_core)
    runner = CliRunner()
    root = _documentary_catalog(tmp_path)
    assert runner.invoke(app, ["catalog", "validate", str(root), "--format", "json"]).exit_code == 0
    assert runner.invoke(app, ["catalog", "report", str(root)]).exit_code == 0
    assert runner.invoke(app, ["catalog", "schema", "--kind", "service"]).exit_code == 0
    assert runner.invoke(app, ["catalog", "validate", str(root), "--format", "yaml"]).exit_code == 2
    assert runner.invoke(app, ["catalog", "schema", "--kind", "bad"]).exit_code == 2
