"""The one read-only kubeconfig exec shape this server ever allows: `aws eks get-token`, matching
exactly what `aws eks update-kubeconfig` writes. One canonical validator, enforced twice:

- at propose time (`config_proposals.py`), on a static YAML parse of the candidate kubeconfig, and
- on every live connect (`providers/kube_client.py` `RealKubeClient._ensure`), on whatever the kubeconfig
  on disk holds *right now* -- a proposal is only ever a point-in-time check, so a kubeconfig swapped
  after acceptance (or any human-configured context with `allow_exec_plugins: true`) must still fail
  closed here.

Only `command: aws`, `args: [eks, get-token, ...]` with the exact options `aws eks update-kubeconfig`
writes, and `env` containing at most `AWS_PROFILE`, pass. Nothing else -- in particular no `--role-arn`,
no other option, no other environment variable (which would otherwise let a crafted kubeconfig override
`PATH`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_ENDPOINT_URL`, or smuggle a
`credential_process` override) -- is ever accepted.
"""

from __future__ import annotations

from typing import Any

from local_ops.config import ServerConfig
from local_ops.models import ErrorCode, OpsError

ALLOWED_EXEC_OPTIONS = frozenset({"--cluster-name", "--region", "--output", "--profile"})


def allowed_exec_profiles(config: ServerConfig, purpose: str = "read") -> frozenset[str]:
    """`aws_sso` credential profiles configured with the given `purpose`. Read connections accept only
    `purpose: read` profiles; an execution connection (D33) accepts only `purpose: execute` profiles, so an
    admin profile can never be reached through a read context and a read profile is never what mutates."""
    return frozenset(c.profile for c in config.credentials if c.kind == "aws_sso" and c.purpose == purpose and c.profile)


def _get(cfg: Any, key: str) -> Any:
    """Read one key from either a plain dict (propose-time YAML parse) or a kubernetes_asyncio
    `ConfigNode` (runtime; supports `in`/`__getitem__`, not `.get`), unwrapped to a plain value."""
    if isinstance(cfg, dict):
        return cfg.get(key)
    if key in cfg:
        v = cfg[key]
        return getattr(v, "value", v)
    return None


def validate_exec_plugin(exec_cfg: Any, allowed_profiles: frozenset[str], *, context_name: str, purpose: str = "read") -> None:
    """Raises `OpsError(AUTH_REQUIRED, ...)` with a clear message and never any file content on any
    deviation from the one allowed shape."""
    command = _get(exec_cfg, "command")
    if command != "aws":
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} uses exec command {command!r}; only the read-only `aws eks get-token` helper is allowed")
    raw_args = _get(exec_cfg, "args") or []
    args = [str(getattr(a, "value", a)) for a in raw_args]
    opts = {a for a in args if a.startswith("--")}
    if "--role-arn" in opts:
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec uses --role-arn, which is never allowed")
    unknown = opts - ALLOWED_EXEC_OPTIONS
    if unknown:
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec uses option(s) {sorted(unknown)}; only --cluster-name/--region/--output/--profile are allowed")
    positionals: list[str] = []
    profile: str | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            if i + 1 >= len(args):
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec option {a!r} is missing its value")
            if a == "--profile":
                profile = args[i + 1]
            i += 2
            continue
        positionals.append(a)
        i += 1
    if positionals != ["eks", "get-token"]:
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec args must be exactly `eks get-token` plus allowed options")
    raw_env = _get(exec_cfg, "env") or []
    seen_env: set[str] = set()
    for e in raw_env:
        name = e.get("name") if isinstance(e, dict) else _get(e, "name")
        # kubernetes_asyncio builds the child env with a dict update (last entry wins), so a repeated name
        # would let a later value replace the one validated here.
        if name in seen_env:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec sets environment variable {name!r} more than once")
        seen_env.add(str(name))
        if name != "AWS_PROFILE":
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec sets environment variable {name!r}; only AWS_PROFILE is allowed")
        if profile is None:
            profile = e.get("value") if isinstance(e, dict) else _get(e, "value")
    if not profile:
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec profile could not be determined from --profile or AWS_PROFILE")
    if profile not in allowed_profiles:
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"kubeconfig context {context_name!r} exec profile {profile!r} is not a configured aws_sso credential with purpose {purpose}")
