"""Headless human configuration and adapter contracts; no real account calls."""
from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import ErrorCode, OpsError
from local_ops.providers.credentials import CredentialResolver
from local_ops.release import Sanitizer


def cli_config(vaults: list[str] | None = None) -> ServerConfig:
    return ServerConfig(credentials=[CredentialRef(id="op-user", kind="onepassword_cli", account="moveindustries", purpose="read")], providers=[ProviderConfig(id="onepassword-main", kind="onepassword", credential="op-user", vaults=vaults or [])])


def test_cli_config_validates_and_account_is_explicit() -> None:
    ref = cli_config().credentials[0]
    assert ref.account == "moveindustries" and ref.profile is None and ref.context is None
    assert cli_config().providers[0].vaults == []


@pytest.mark.parametrize("fields", [{}, {"account": None}, {"account": ""}, {"account": " "}, {"account": "-x"}, {"account": "a\nb"}, {"profile": "moveindustries"}, {"account": "moveindustries", "password": "forbidden"}])
def test_cli_config_rejects_missing_invalid_and_extra_fields(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        CredentialRef.model_validate({"id": "op-user", "kind": "onepassword_cli", **fields})


async def test_cli_resolver_is_nonsecret_and_never_resolves_items(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = cli_config()
    cfg.credentials.append(CredentialRef(id="secret", kind="onepassword_item", via="op-user", vault_id="v1", item_id="i1"))
    resolver = CredentialResolver(cfg, Sanitizer())
    monkeypatch.setattr("local_ops.providers.credentials.shutil.which", lambda _: "/fake/op")
    assert resolver.configured("op-user")
    credential = await resolver.resolve("op-user")
    assert credential.secret is None and credential.env is None and credential.ref.account == "moveindustries"
    assert not resolver.configured("secret")
    with pytest.raises(OpsError) as failure:
        await resolver.resolve("secret")
    assert failure.value.code == ErrorCode.UNSUPPORTED_OPERATION
    monkeypatch.setattr("local_ops.providers.credentials.shutil.which", lambda _: None)
    assert not resolver.configured("op-user")


async def test_installed_op_help_contract_without_account_access(tmp_path: Path) -> None:
    """Only help/version; skip on CI hosts without op, never consult a real account."""
    binary = shutil.which("op")
    if binary is None:
        pytest.skip("op not installed; installed CLI syntax contract unavailable")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path), "OP_BIOMETRIC_UNLOCK_ENABLED": "false"}

    async def help_text(*args: str) -> str:
        process = await asyncio.create_subprocess_exec(binary, *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=environment, start_new_session=True)
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), 10)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == 0
        assert len(stdout) < 65536
        return stdout.decode()

    assert (await help_text("--version")).strip().startswith("2.")
    global_help = await help_text("--help")
    for flag in ("--account", "--format", "--iso-timestamps", "--cache"):
        assert flag in global_help
    assert "json" in global_help
    for command in (("account", "list"), ("whoami",), ("user", "get"), ("vault", "list"), ("item", "list")):
        assert "Usage:" in await help_text(*command, "--help")
    item_help = await help_text("item", "list", "--help")
    assert "--vault" in item_help and "--include-archive" in item_help


class FakeProcess:
    def __init__(self, payload: bytes, *, code: int = 0, error: bytes = b""):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(payload)
        self.stdout.feed_eof()
        self.stderr.feed_data(error)
        self.stderr.feed_eof()
        self.returncode = code
        self.pid = None

    async def wait(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


@pytest.mark.parametrize("configured,requested,expected", [([], [], ["v1", "v2"]), (["v1"], [], ["v1"]), (["Second"], [], ["v2"]), (["v1"], ["v2"], [])])
async def test_cli_discovery_and_doctor_share_safe_metadata_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: list[str], requested: list[str], expected: list[str]) -> None:
    import json

    from local_ops.providers import onepassword_cli
    from local_ops.providers.base import DiscoveryScope
    from local_ops.providers.onepassword import OnePasswordAdapter
    from tests.providers.test_onepassword import _open_dbs, evidence_texts, make_ctx

    calls: list[tuple[str, ...]] = []
    session = "session-canary-987654321"
    field = "secret-field-canary-123456"
    monkeypatch.setenv("OP_SESSION_moveindustries", session)
    monkeypatch.setattr("shutil.which", lambda _: "/fake/op")

    async def runner(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(argv)
        assert "--account" in argv and argv[argv.index("--account") + 1] == "moveindustries"
        assert session not in str(argv)
        if "whoami" in argv:
            payload: object = {"account_uuid": "acct", "user_uuid": "private-user", "email": "private@example.invalid", "url": "https://moveindustries.1password.com"}
        elif "vault" in argv and "list" in argv:
            payload = [{"id": "v1", "name": "First"}, {"id": "v2", "name": "Second"}]
        else:
            vault = argv[argv.index("--vault") + 1]
            payload = [{"id": f"item-{vault}", "title": "Overview " + session, "category": "LOGIN", "vault": {"id": vault}, "tags": ["ops"], "urls": [{"href": "https://example.invalid"}], "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-02-01T00:00:00Z", "fields": [{"value": field}], "notesPlain": field, "username": field}]
        return FakeProcess(json.dumps(payload).encode())

    real_client = onepassword_cli.CliClient
    monkeypatch.setattr(onepassword_cli, "CliClient", lambda account, sanitizer: real_client(account, sanitizer, runner=runner))
    cfg = cli_config(configured)
    sanitizer = Sanitizer()
    resolver = CredentialResolver(cfg, sanitizer)
    adapter = OnePasswordAdapter(cfg.providers[0], cfg, resolver)
    availability = await adapter.check_availability(live=True)
    assert availability.available and availability.checked_live
    assert availability.identity == {"auth": "onepassword_cli", "account": "moveindustries", "visible_vault_count": 2, "scope": "vaults visible to authenticated CLI user for configured account"}
    assert resolver._onepassword_resolver is None
    assert "resolve_item_secret" not in [operation.name for operation in adapter.describe().operations]
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    try:
        report = await adapter.discover(ctx, DiscoveryScope(vaults=requested), ctx.budget)
        assert [o.identity["vault_id"] for o in report.observations if o.resource_type == "onepassword/vault"] == expected
        items = [o for o in report.observations if o.resource_type == "onepassword/item"]
        assert len(items) == len(expected)
        for item in items:
            assert item.attributes["fields_available"] is False
            assert item.attributes["websites"] == ["https://example.invalid"]
            assert item.attributes["created_at"] == "2026-01-01T00:00:00Z"
        text = str(report.model_dump()) + str(await evidence_texts(ctx)) + str(availability.model_dump())
        for private in (session, field, "private-user", "private@example.invalid"):
            assert private not in text
        assert session not in sanitizer.scrub_text(session)[0]
        assert len([argv for argv in calls if "whoami" in argv]) == 2
        assert len([argv for argv in calls if "--vault" in argv]) == len(expected)
    finally:
        await ctx.db.close()
        _open_dbs.remove(ctx.db)


async def test_cli_missing_binary_availability(monkeypatch: pytest.MonkeyPatch) -> None:
    from local_ops.providers.onepassword import OnePasswordAdapter

    monkeypatch.setattr("shutil.which", lambda _: None)
    cfg = cli_config()
    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, Sanitizer()))
    result = await adapter.check_availability(live=True)
    assert not result.available and result.reason == "op_missing" and result.checked_live


@pytest.mark.parametrize("failure_stage", ["initial", "after_doctor", "items"])
async def test_cli_auth_failure_never_falls_back_or_completes_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str) -> None:
    import json

    from local_ops.providers import onepassword_cli
    from local_ops.providers.base import DiscoveryScope
    from local_ops.providers.onepassword import OnePasswordAdapter
    from tests.providers.test_onepassword import _open_dbs, evidence_texts, make_ctx

    calls: list[tuple[str, ...]] = []
    expired = failure_stage == "initial"
    token = "human-session-private-canary-98765"
    monkeypatch.setenv("OP_SESSION_moveindustries", token)
    monkeypatch.setattr("shutil.which", lambda _: "/fake/op")

    async def runner(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(argv)
        assert argv[argv.index("--account") + 1] == "moveindustries"
        if expired or (failure_stage == "items" and "--vault" in argv):
            return FakeProcess(b"", code=1, error=f"session expired or wrong account {token}".encode())
        payload = {"account_uuid": "acct"} if "whoami" in argv else [{"id": "v1", "name": "First"}]
        return FakeProcess(json.dumps(payload).encode())

    real_client = onepassword_cli.CliClient
    monkeypatch.setattr(onepassword_cli, "CliClient", lambda account, sanitizer: real_client(account, sanitizer, runner=runner))
    cfg = cli_config()
    sanitizer = Sanitizer()
    adapter = OnePasswordAdapter(cfg.providers[0], cfg, CredentialResolver(cfg, sanitizer))
    if failure_stage == "after_doctor":
        assert (await adapter.check_availability(live=True)).available
        expired = True
    ctx = await make_ctx(tmp_path, cfg, sanitizer)
    try:
        report = await adapter.discover(ctx, DiscoveryScope(), ctx.budget)
        assert report.unavailable[0]["reason"] == "auth_required"
        assert not report.observations and not report.completed_scopes
        assert token not in str(report.model_dump()) + str(await evidence_texts(ctx))
        if failure_stage == "initial":
            assert len(calls) == 1 and "whoami" in calls[0]
    finally:
        await ctx.db.close()
        _open_dbs.remove(ctx.db)


def test_doctor_live_uses_fake_cli_and_returns_only_safe_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from typer.testing import CliRunner

    from local_ops.cli import app
    from local_ops.providers import onepassword_cli

    monkeypatch.setattr("shutil.which", lambda name: "/fake/op" if name == "op" else None)
    calls: list[tuple[str, ...]] = []

    async def runner(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append(argv)
        payload = {"account_uuid": "private-account-id", "email": "private@example.invalid", "user_uuid": "private-user-id"} if "whoami" in argv else [{"id": "v1", "name": "First"}]
        return FakeProcess(json.dumps(payload).encode())

    real_client = onepassword_cli.CliClient
    monkeypatch.setattr(onepassword_cli, "CliClient", lambda account, sanitizer: real_client(account, sanitizer, runner=runner))
    config = tmp_path / "server.yaml"
    config.write_text("credentials:\n  - id: op-user\n    kind: onepassword_cli\n    account: moveindustries\n    purpose: read\nproviders:\n  - id: onepassword-main\n    kind: onepassword\n    credential: op-user\n    vaults: []\n")
    result = CliRunner().invoke(app, ["doctor", "--config", str(config), "--live"])
    assert result.exit_code == 0, result.output
    assert '"visible_vault_count": 1' in result.output
    assert '"account": "moveindustries"' in result.output
    assert "private@example.invalid" not in result.output and "private-user-id" not in result.output and "private-account-id" not in result.output
    assert len(calls) == 2 and "whoami" in calls[0] and "vault" in calls[1]
