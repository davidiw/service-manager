"""Credential resolution. Resolved secrets stay in process memory, are registered with the sanitizer,
and are never serialized into results, logs, or configuration."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from local_ops.config import CredentialRef, ServerConfig
from local_ops.models import ErrorCode, OpsError
from local_ops.release import Sanitizer


@dataclass
class ResolvedCredential:
    """Opaque handle. `secret` may be None for profile/context style credentials that are consumed by a
    client library through environment or file configuration."""

    ref: CredentialRef
    secret: str | None = None
    env: dict[str, str] | None = None
    path: str | None = None
    context: str | None = None
    profile: str | None = None

    def __repr__(self) -> str:  # never print secrets
        return f"ResolvedCredential(id={self.ref.id!r}, kind={self.ref.kind!r})"


class CredentialResolver:
    def __init__(self, config: ServerConfig, sanitizer: Sanitizer):
        self.config = config
        self.sanitizer = sanitizer
        self._cache: dict[str, ResolvedCredential] = {}
        self._lock = asyncio.Lock()
        self._onepassword_resolver: Any = None  # set by the 1Password adapter when available

    def configured(self, credential_id: str | None) -> bool:
        if not credential_id:
            return False
        ref = self.config.credential(credential_id)
        if ref is None:
            return False
        if ref.kind == "env" or ref.kind == "onepassword_service_account":
            return bool(ref.env_var and os.environ.get(ref.env_var))
        if ref.kind == "file":
            return bool(ref.path and self.config.resolve_path(ref.path).exists())
        if ref.kind in ("aws_profile", "aws_sso"):
            return True  # presence is checked live via STS
        if ref.kind == "kubeconfig_context":
            kc = Path(ref.kubeconfig).expanduser() if ref.kubeconfig else Path(os.environ.get("KUBECONFIG", "~/.kube/config")).expanduser()
            return kc.exists()
        if ref.kind == "onepassword_item":
            return self.configured(ref.via)
        return ref.kind in ("none", "onepassword_desktop", "aws_static_env")

    async def resolve(self, credential_id: str) -> ResolvedCredential:
        ref = self.config.credential(credential_id)
        if ref is None:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential {credential_id!r} is not configured")
        if credential_id in self._cache:
            return self._cache[credential_id]
        # Resolve `via` dependencies before taking the lock so nested resolution cannot deadlock.
        if ref.via:
            await self.resolve(ref.via)
        async with self._lock:
            if credential_id in self._cache:
                return self._cache[credential_id]
            resolved = await self._resolve(ref)
            if resolved.secret:
                self.sanitizer.register_secret(resolved.secret)
            self._cache[credential_id] = resolved
            return resolved

    def invalidate(self, credential_id: str) -> None:
        self._cache.pop(credential_id, None)

    async def _resolve(self, ref: CredentialRef) -> ResolvedCredential:
        if ref.kind == "none":
            return ResolvedCredential(ref)
        if ref.kind in ("env", "onepassword_service_account"):
            val = os.environ.get(ref.env_var or "")
            if not val:
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"environment variable for credential {ref.id!r} is not set", private_detail=f"missing env {ref.env_var}")
            return ResolvedCredential(ref, secret=val)
        if ref.kind == "file":
            p = self.config.resolve_path(ref.path or "")
            if not p.exists():  # noqa: ASYNC240 - single local stat during credential resolution
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential file for {ref.id!r} is missing")
            mode = p.stat().st_mode & 0o777
            if mode & 0o077:
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential file for {ref.id!r} must not be group/world readable", private_detail=f"{p} mode {oct(mode)}")
            return ResolvedCredential(ref, secret=p.read_text(encoding="utf-8").strip(), path=str(p))
        if ref.kind in ("aws_profile", "aws_sso"):
            return ResolvedCredential(ref, profile=ref.profile)
        if ref.kind == "aws_static_env":
            if not os.environ.get("AWS_ACCESS_KEY_ID"):
                raise OpsError(ErrorCode.AUTH_REQUIRED, "AWS static credentials are not present in the environment")
            self.sanitizer.register_secret(os.environ.get("AWS_SECRET_ACCESS_KEY"))
            self.sanitizer.register_secret(os.environ.get("AWS_SESSION_TOKEN"))
            return ResolvedCredential(ref, env={k: v for k, v in os.environ.items() if k.startswith("AWS_")})
        if ref.kind == "kubeconfig_context":
            kc = ref.kubeconfig or os.environ.get("KUBECONFIG") or "~/.kube/config"
            return ResolvedCredential(ref, path=str(Path(kc).expanduser()), context=ref.context)  # noqa: ASYNC240
        if ref.kind == "onepassword_desktop":
            return ResolvedCredential(ref)
        if ref.kind == "onepassword_item":
            if self._onepassword_resolver is None:
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential {ref.id!r} needs a configured 1Password adapter")
            secret = await self._onepassword_resolver(ref)
            return ResolvedCredential(ref, secret=secret)
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"unsupported credential kind {ref.kind}")

    @staticmethod
    def minimal_subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
        """Never copy the agent environment wholesale into provider subprocesses."""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"), "LANG": "C.UTF-8"}
        for k in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG", "HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME", "SSL_CERT_FILE"):
            if k in os.environ:
                env[k] = os.environ[k]
        if extra:
            env.update(extra)
        return env
