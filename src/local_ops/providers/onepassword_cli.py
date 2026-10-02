"""Narrow, metadata-only client for the installed 1Password CLI.

This module deliberately exposes only the three read operations needed by the
1Password inventory adapter.  In particular it is not a general command
runner: callers cannot use it to read an item, inject a secret, or execute a
subcommand through ``op run``.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
from collections.abc import Awaitable, Callable
from contextlib import suppress
from enum import StrEnum
from typing import Any, Protocol, cast

from local_ops.models import ErrorCode, OpsError
from local_ops.release import Sanitizer


class _Process(Protocol):
    stdout: asyncio.StreamReader | None
    stderr: asyncio.StreamReader | None
    pid: int | None

    async def wait(self) -> int: ...

    def kill(self) -> None: ...


ProcessRunner = Callable[..., Awaitable[_Process]]


class _Operation(StrEnum):
    WHOAMI = "whoami"
    VAULTS = "vaults"
    ITEMS = "items"


_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_STDOUT_LIMIT = 16 * 1024 * 1024
_DEFAULT_STDERR_LIMIT = 64 * 1024


class CliClient:
    """A fixed-operation ``op`` client bound to one explicitly selected account."""

    def __init__(
        self,
        account: str,
        sanitizer: Sanitizer,
        runner: ProcessRunner | None = None,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_stdout_bytes: int = _DEFAULT_STDOUT_LIMIT,
        max_stderr_bytes: int = _DEFAULT_STDERR_LIMIT,
    ) -> None:
        if not isinstance(account, str) or not account:
            raise ValueError("1Password CLI account must be a non-empty string")
        if timeout_seconds <= 0 or max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
            raise ValueError("CLI runtime limits must be positive")
        self.account = account
        self.sanitizer = sanitizer
        self._runner: ProcessRunner = runner if runner is not None else cast(ProcessRunner, asyncio.create_subprocess_exec)
        self._timeout_seconds = timeout_seconds
        self._max_stdout_bytes = max_stdout_bytes
        self._max_stderr_bytes = max_stderr_bytes
        self.vaults = _Vaults(self)
        self.items = _Items(self)

    async def check_auth(self) -> None:
        """Check the selected account without retaining or returning identity data."""
        result = await self._invoke(_Operation.WHOAMI)
        if not isinstance(result, dict) or not result:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed authentication data")

    def _argv(self, operation: _Operation, vault_id: str | None = None) -> tuple[str, ...]:
        argv = ("op", "--account", self.account, "--format", "json", "--iso-timestamps", "--cache=false")
        if operation is _Operation.WHOAMI:
            return argv + ("whoami",)
        if operation is _Operation.VAULTS:
            return argv + ("vault", "list")
        if operation is _Operation.ITEMS and vault_id is not None:
            return argv + ("item", "list", "--vault", vault_id, "--include-archive")
        raise ValueError("invalid fixed 1Password CLI operation")

    def _env(self) -> dict[str, str]:
        # Keep human CLI session state and normal executable/config discovery, while
        # making service-account and Connect credentials impossible to inherit.
        env = dict(os.environ)
        for key in tuple(env):
            if key == "OP_SERVICE_ACCOUNT_TOKEN" or key in {"OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_ACCOUNT"}:
                env.pop(key, None)
            elif key == "OP_SESSION" or key.startswith("OP_SESSION_"):
                self.sanitizer.register_secret(env[key])
        env["OP_BIOMETRIC_UNLOCK_ENABLED"] = "false"
        env["OP_DEBUG"] = "false"
        return env

    async def _invoke(self, operation: _Operation, vault_id: str | None = None) -> Any:
        if operation is _Operation.ITEMS and (not isinstance(vault_id, str) or not vault_id):
            raise ValueError("vault id must be a non-empty string")
        argv = self._argv(operation, vault_id)
        started = asyncio.get_running_loop().time()
        try:
            process = await asyncio.wait_for(
                self._runner(
                    *argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                    env=self._env(),
                ),
                timeout=self._timeout_seconds,
            )
        except FileNotFoundError:
            raise OpsError(
                ErrorCode.PROVIDER_UNAVAILABLE,
                "1Password CLI executable is unavailable",
                data={"reason": "op_missing"},
            ) from None
        except OSError:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI could not be started") from None
        except TimeoutError:
            raise OpsError(ErrorCode.LIMIT_REACHED, "1Password CLI exceeded its runtime limit") from None
        except Exception:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI could not be started") from None

        try:
            remaining = self._timeout_seconds - (asyncio.get_running_loop().time() - started)
            if remaining <= 0:
                raise TimeoutError
            stdout, stderr, returncode = await asyncio.wait_for(
                self._collect_and_wait(process), timeout=remaining
            )
        except TimeoutError:
            await self._terminate_and_reap(process)
            raise OpsError(ErrorCode.LIMIT_REACHED, "1Password CLI exceeded its runtime limit") from None
        except _OutputLimitExceeded:
            await self._terminate_and_reap(process)
            raise OpsError(ErrorCode.LIMIT_REACHED, "1Password CLI exceeded its output limit") from None
        except asyncio.CancelledError:
            await asyncio.shield(self._terminate_and_reap(process))
            raise
        except Exception:
            await self._terminate_and_reap(process)
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI output could not be collected") from None

        if returncode != 0:
            # stderr is used only to distinguish a login problem from an unavailable
            # provider.  It never crosses this private process boundary.
            if operation is _Operation.WHOAMI or _looks_like_auth_failure(stderr, self.sanitizer):
                raise OpsError(
                    ErrorCode.AUTH_REQUIRED,
                    f"1Password CLI session is not authenticated for account {self.account}; authenticate with op in the server environment and retry.",
                )
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI operation failed")
        try:
            return json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed JSON") from None

    async def _collect_and_wait(self, process: _Process) -> tuple[bytes, bytes, int]:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("1Password CLI pipes were not created")
        stdout_task = asyncio.create_task(_read_bounded(process.stdout, self._max_stdout_bytes))
        stderr_task = asyncio.create_task(_read_bounded(process.stderr, self._max_stderr_bytes))
        try:
            stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
            return stdout, stderr, await process.wait()
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    async def _terminate_and_reap(self, process: _Process) -> None:
        pid = process.pid
        if pid and os.name != "nt":
            with suppress(OSError, ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)
        with suppress(OSError, ProcessLookupError):
            process.kill()
        with suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=1.0)


class _Vaults:
    def __init__(self, client: CliClient) -> None:
        self._client = client

    async def list(self) -> list[dict[str, Any]]:
        raw = await self._client._invoke(_Operation.VAULTS)
        if not isinstance(raw, list):
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed vault data")
        return [_project_vault(entry, self._client.sanitizer) for entry in raw]


class _Items:
    def __init__(self, client: CliClient) -> None:
        self._client = client

    async def list(self, vault_id: str) -> list[dict[str, Any]]:
        raw = await self._client._invoke(_Operation.ITEMS, vault_id)
        if not isinstance(raw, list):
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed item data")
        return [_project_item(entry, vault_id, self._client.sanitizer) for entry in raw]


class _OutputLimitExceeded(Exception):
    pass


async def _read_bounded(reader: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := await reader.read(64 * 1024):
        size += len(chunk)
        if size > limit:
            raise _OutputLimitExceeded
        chunks.append(chunk)
    return b"".join(chunks)


def _looks_like_auth_failure(stderr: bytes, sanitizer: Sanitizer) -> bool:
    # Keep bounded diagnostic bytes local; sanitize before matching so registered
    # session values cannot accidentally be retained in an exception path.
    text, _ = sanitizer.scrub_text(stderr[:_DEFAULT_STDERR_LIMIT].decode("utf-8", "replace"))
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "not signed in", "sign in", "authentication", "authenticate", "unauthorized", "forbidden",
            "session", "expired", "token", "account not found", "unknown account",
        )
    )


def _required_string(value: Any, field: str, kind: str) -> str:
    if not isinstance(value, str) or not value:
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"1Password CLI returned malformed {kind} data")
    return value


def _optional_string(raw: dict[str, Any], field: str, out: dict[str, Any], output_field: str | None = None) -> None:
    if field not in raw or raw[field] is None:
        return
    if not isinstance(raw[field], str):
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed metadata")
    out[output_field or field] = raw[field]


def _optional_int(raw: dict[str, Any], field: str, out: dict[str, Any]) -> None:
    if field not in raw or raw[field] is None:
        return
    if not isinstance(raw[field], int) or isinstance(raw[field], bool):
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed metadata")
    out[field] = raw[field]


def _project_vault(raw: Any, sanitizer: Sanitizer) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed vault data")
    out: dict[str, Any] = {
        "id": _required_string(raw.get("id"), "id", "vault"),
        "title": _required_string(raw.get("name"), "name", "vault"),
    }
    _optional_string(raw, "description", out)
    _optional_string(raw, "type", out, "vault_type")
    for field in ("created_at", "updated_at"):
        _optional_string(raw, field, out)
    for field in ("item_count", "items_count", "active_item_count", "items"):
        if field in raw and raw[field] is not None:
            count: dict[str, Any] = {}
            _optional_int(raw, field, count)
            out["active_item_count"] = count[field]
            break
    scrubbed, _ = sanitizer.scrub(out)
    return scrubbed


def _project_item(raw: Any, listed_vault_id: str, sanitizer: Sanitizer) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed item data")
    vault = raw.get("vault")
    raw_vault_id = vault.get("id") if isinstance(vault, dict) else raw.get("vault_id", listed_vault_id)
    out: dict[str, Any] = {
        "id": _required_string(raw.get("id"), "id", "item"),
        "title": _required_string(raw.get("title"), "title", "item"),
        "category": _required_string(raw.get("category"), "category", "item"),
        "vault_id": _required_string(raw_vault_id, "vault_id", "item"),
    }
    if "tags" in raw and raw["tags"] is not None:
        if not isinstance(raw["tags"], list) or not all(isinstance(tag, str) for tag in raw["tags"]):
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed item data")
        out["tags"] = raw["tags"]
    else:
        out["tags"] = []
    urls = raw.get("urls", [])
    if not isinstance(urls, list):
        raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed item data")
    websites: list[dict[str, str]] = []
    for url in urls:
        if not isinstance(url, dict) or not isinstance(url.get("href"), str) or not url["href"]:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "1Password CLI returned malformed item data")
        websites.append({"url": url["href"]})
    out["websites"] = websites
    for field in ("created_at", "updated_at"):
        _optional_string(raw, field, out)
    scrubbed, _ = sanitizer.scrub(out)
    return scrubbed
