from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any

import pytest

import local_ops.providers.onepassword_cli as onepassword_cli
from local_ops.models import ErrorCode, OpsError
from local_ops.providers.onepassword_cli import CliClient
from local_ops.release import Sanitizer


class FakeProcess:
    def __init__(self, stdout: bytes = b"[]", stderr: bytes = b"", returncode: int = 0, *, close: bool = True) -> None:
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stderr.feed_data(stderr)
        if close:
            self.stdout.feed_eof()
            self.stderr.feed_eof()
        self.returncode = returncode
        self.killed = False
        self._done = asyncio.Event()
        if close:
            self._done.set()
        self.pid = None

    async def wait(self) -> int:
        await self._done.wait()
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()


def runner_for(process: FakeProcess, calls: list[tuple[tuple[str, ...], dict[str, Any]]]) -> Any:
    async def runner(*argv: str, **kwargs: Any) -> FakeProcess:
        calls.append((argv, kwargs))
        return process

    return runner


async def test_fixed_argv_and_metadata_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    monkeypatch.setenv("OP_SESSION_test", "desktop-session-token-abcdefgh")
    monkeypatch.setenv("OP_SESSION", "desktop-session-token-abcdefgh")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/op-config")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "do-not-pass")
    monkeypatch.setenv("OP_CONNECT_TOKEN", "do-not-pass")
    monkeypatch.setenv("OP_ACCOUNT", "wrong-account")
    client = CliClient(
        "chosen.1password.com",
        Sanitizer(),
        runner_for(FakeProcess(json.dumps([{"id": "v1", "name": "Desktop"}]).encode()), calls),
    )

    assert await client.vaults.list() == [{"id": "v1", "title": "Desktop"}]
    argv, kwargs = calls.pop()
    assert argv == (
        "op", "--account", "chosen.1password.com", "--format", "json", "--iso-timestamps", "--cache=false",
        "vault", "list",
    )
    assert kwargs["stdin"] is asyncio.subprocess.DEVNULL
    assert kwargs["stdout"] is asyncio.subprocess.PIPE and kwargs["stderr"] is asyncio.subprocess.PIPE
    assert kwargs["start_new_session"] is True
    assert kwargs["env"]["OP_BIOMETRIC_UNLOCK_ENABLED"] == "false"
    assert kwargs["env"]["OP_DEBUG"] == "false"
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in kwargs["env"] and "OP_CONNECT_TOKEN" not in kwargs["env"]
    assert "OP_ACCOUNT" not in kwargs["env"]
    assert kwargs["env"]["OP_SESSION"] == "desktop-session-token-abcdefgh"
    assert kwargs["env"]["OP_SESSION_test"] == "desktop-session-token-abcdefgh"
    assert kwargs["env"]["HOME"] and kwargs["env"]["PATH"] and kwargs["env"]["XDG_CONFIG_HOME"] == "/tmp/op-config"

    client = CliClient("chosen", Sanitizer(), runner_for(FakeProcess(b'[{"id":"i1","title":"x","category":"Login","urls":[{"href":"https://x"}]}]'), calls))
    assert await client.items.list("v1") == [{"id": "i1", "title": "x", "category": "Login", "vault_id": "v1", "tags": [], "websites": [{"url": "https://x"}]}]
    assert calls.pop()[0][-5:] == ("item", "list", "--vault", "v1", "--include-archive")


async def test_missing_nonzero_and_malformed_errors_are_safe() -> None:
    async def missing(*args: Any, **kwargs: Any) -> FakeProcess:
        raise FileNotFoundError()

    with pytest.raises(OpsError) as missing_error:
        await CliClient("a", Sanitizer(), missing).vaults.list()
    assert missing_error.value.code == ErrorCode.PROVIDER_UNAVAILABLE
    assert missing_error.value.data == {"reason": "op_missing"}

    token = "ops_" + "A" * 40
    with pytest.raises(OpsError) as auth_error:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b"", f"not signed in {token}".encode(), 1), [])).vaults.list()
    assert auth_error.value.code == ErrorCode.AUTH_REQUIRED
    assert token not in str(auth_error.value) and auth_error.value.private_detail is None

    with pytest.raises(OpsError) as generic_error:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b"", b"failure", 1), [])).vaults.list()
    assert generic_error.value.code == ErrorCode.PROVIDER_UNAVAILABLE and generic_error.value.private_detail is None

    with pytest.raises(OpsError) as malformed:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b"not json"), [])).vaults.list()
    assert malformed.value.code == ErrorCode.PROVIDER_UNAVAILABLE


async def test_timeout_oversize_and_cancel_reap_processes() -> None:
    timeout_process = FakeProcess(close=False)
    with pytest.raises(OpsError) as timeout:
        await CliClient("a", Sanitizer(), runner_for(timeout_process, []), timeout_seconds=0.01).vaults.list()
    assert timeout.value.code == ErrorCode.LIMIT_REACHED and timeout_process.killed

    oversized = FakeProcess(b"[" + b"x" * 32 + b"]")
    with pytest.raises(OpsError) as size:
        await CliClient("a", Sanitizer(), runner_for(oversized, []), max_stdout_bytes=8).vaults.list()
    assert size.value.code == ErrorCode.LIMIT_REACHED and oversized.killed

    stderr_oversized = FakeProcess(b"[]", b"x" * 32)
    with pytest.raises(OpsError) as stderr_size:
        await CliClient("a", Sanitizer(), runner_for(stderr_oversized, []), max_stderr_bytes=8).vaults.list()
    assert stderr_size.value.code == ErrorCode.LIMIT_REACHED and stderr_oversized.killed

    cancelled = FakeProcess(close=False)
    task = asyncio.create_task(CliClient("a", Sanitizer(), runner_for(cancelled, [])).vaults.list())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.killed


async def test_malformed_lists_fail_closed_and_whoami_does_not_return_identity() -> None:
    with pytest.raises(OpsError) as bad_list:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b'[{"id":"v1","name":3}]'), [])).vaults.list()
    assert bad_list.value.code == ErrorCode.PROVIDER_UNAVAILABLE
    with pytest.raises(OpsError) as bad_urls:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b'[{"id":"i","title":"x","category":"Login","urls":"secret"}]'), [])).items.list("v")
    assert bad_urls.value.code == ErrorCode.PROVIDER_UNAVAILABLE
    assert await CliClient("a", Sanitizer(), runner_for(FakeProcess(b'{"email":"private@example.test"}'), [])).check_auth() is None
    with pytest.raises(OpsError) as empty_whoami:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b"{}"), [])).check_auth()
    assert empty_whoami.value.code == ErrorCode.PROVIDER_UNAVAILABLE
    with pytest.raises(OpsError) as unknown_account:
        await CliClient("a", Sanitizer(), runner_for(FakeProcess(b"", b"no account", 1), [])).check_auth()
    assert unknown_account.value.code == ErrorCode.AUTH_REQUIRED


async def test_client_has_no_generic_command_or_shell_api() -> None:
    client = CliClient("a", Sanitizer(), runner_for(FakeProcess(), []))
    assert not hasattr(client, "run") and not hasattr(client, "command")
    assert "create_subprocess_shell" not in inspect.getsource(onepassword_cli)


def test_fixed_command_set_excludes_secret_reading_and_login() -> None:
    # Adding another operation requires explicitly revisiting this metadata-only contract.
    assert {operation.value for operation in onepassword_cli._Operation} == {"whoami", "vaults", "items"}
    client = CliClient("moveindustries", Sanitizer())
    for operation in onepassword_cli._Operation:
        argv = client._argv(operation, "vault-id")
        assert argv[:3] == ("op", "--account", "moveindustries")
        assert not {"get", "read", "inject", "run", "document", "signin", "signout", "/bin/sh", "--session"}.intersection(argv)
        assert argv[7:] in (("whoami",), ("vault", "list"), ("item", "list", "--vault", "vault-id", "--include-archive"))
