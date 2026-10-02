from __future__ import annotations

from local_ops.executors.base import Executor
from local_ops.executors.github_actions import GitHubActionsWorkflowExecutor
from local_ops.executors.helm import HelmExecutor
from local_ops.executors.kubernetes_native import KubernetesNativeExecutor
from local_ops.models import ErrorCode, OpsError

_EXECUTORS: dict[str, Executor] = {
    "kubernetes_native": KubernetesNativeExecutor(),
    "helm": HelmExecutor(),
    "github_actions_workflow": GitHubActionsWorkflowExecutor(),
}


def get(name: str) -> Executor:
    ex = _EXECUTORS.get(name)
    if ex is None:
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"unknown executor {name!r}")
    return ex


def register(name: str, executor: Executor) -> None:
    _EXECUTORS[name] = executor
