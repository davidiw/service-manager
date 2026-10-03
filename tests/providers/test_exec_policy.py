"""The one read-only kubeconfig exec shape ever allowed: `aws eks get-token`, matching exactly what
`aws eks update-kubeconfig` writes. Enforced identically at propose time and on every live connect."""

from __future__ import annotations

import pytest

from local_ops.models import ErrorCode, OpsError
from local_ops.providers.exec_policy import validate_exec_plugin

READ_PROFILES = frozenset({"mi-mainnet-ro"})

# Exactly what `aws eks update-kubeconfig --region us-east-1 --name foo --profile mi-mainnet-ro` writes.
REAL_SHAPE = {
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "command": "aws",
    "args": ["--region", "us-east-1", "eks", "get-token", "--cluster-name", "foo", "--output", "json"],
    "env": [{"name": "AWS_PROFILE", "value": "mi-mainnet-ro"}],
    "interactiveMode": "IfAvailable",
    "provideClusterInfo": False,
    "installHint": "install the AWS CLI",
}


def _err(fields: dict, **over: object) -> OpsError:
    cfg = {**fields, **over}
    with pytest.raises(OpsError) as e:
        validate_exec_plugin(cfg, READ_PROFILES, context_name="c")
    return e.value


def test_real_update_kubeconfig_shape_is_accepted() -> None:
    validate_exec_plugin(REAL_SHAPE, READ_PROFILES, context_name="c")  # does not raise


def test_profile_from_env_only_also_accepted() -> None:
    cfg = {**REAL_SHAPE, "args": ["eks", "get-token", "--cluster-name", "foo"]}
    validate_exec_plugin(cfg, READ_PROFILES, context_name="c")


def test_non_aws_command_refused() -> None:
    assert _err(REAL_SHAPE, command="kubectl-oidc-login").code is ErrorCode.AUTH_REQUIRED


def test_role_arn_refused() -> None:
    args = [*REAL_SHAPE["args"], "--role-arn", "arn:aws:iam::1:role/x"]
    e = _err(REAL_SHAPE, args=args)
    assert "role-arn" in e.message


def test_unknown_option_refused() -> None:
    e = _err(REAL_SHAPE, args=[*REAL_SHAPE["args"], "--endpoint-url", "https://evil.invalid"])
    assert "are allowed" in e.message


def test_path_env_override_refused() -> None:
    """The exact attack this check exists to stop: smuggling a PATH override through exec env so
    `aws` resolves to an attacker-controlled binary."""
    e = _err(REAL_SHAPE, env=[{"name": "AWS_PROFILE", "value": "mi-mainnet-ro"}, {"name": "PATH", "value": "/tmp/evil"}])
    assert "PATH" in e.message


def test_aws_config_file_env_override_refused() -> None:
    e = _err(REAL_SHAPE, env=[{"name": "AWS_PROFILE", "value": "mi-mainnet-ro"}, {"name": "AWS_CONFIG_FILE", "value": "/tmp/evil"}])
    assert "AWS_CONFIG_FILE" in e.message


def test_unknown_profile_refused() -> None:
    e = _err(REAL_SHAPE, env=[{"name": "AWS_PROFILE", "value": "ghost-profile"}])
    assert "not a configured aws_sso credential" in e.message


def test_args_other_than_eks_get_token_refused() -> None:
    e = _err(REAL_SHAPE, args=["token"])
    assert "eks get-token" in e.message
