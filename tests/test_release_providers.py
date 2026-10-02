"""Regression tests for the provider-construction-failure disclosure gap: a provider adapter that
fails to construct records its exception message as a `limitations` entry (`UnavailableAdapter`),
which `capabilities_get` discloses unreviewed. The message must be scrubbed before it reaches that
surface (`local_ops.app.build_providers`, `local_ops.providers.base.UnavailableAdapter`).
"""

from __future__ import annotations

import pytest

from local_ops.app import build_providers
from local_ops.config import ProviderConfig, ServerConfig
from local_ops.providers.base import UnavailableAdapter
from local_ops.providers.credentials import CredentialResolver
from local_ops.release import Sanitizer

PASSWORD = "hunter2hunter2"


def _config_with_one_provider() -> ServerConfig:
    return ServerConfig(providers=[ProviderConfig(id="broken", kind="demo")])


def test_build_providers_scrubs_pattern_shaped_secret_in_exception_message(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _config_with_one_provider()

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"connection string postgres://admin:{PASSWORD}@db.internal/app failed")

    monkeypatch.setattr("local_ops.app._make_adapter", _raise)
    sanitizer = Sanitizer()
    reg = build_providers(cfg, CredentialResolver(cfg, sanitizer), sanitizer=sanitizer)

    adapter = reg.get("broken")
    assert isinstance(adapter, UnavailableAdapter)
    desc = adapter.describe()
    assert PASSWORD not in adapter.reason
    assert all(PASSWORD not in lim for lim in desc.limitations)


def test_build_providers_scrubs_registered_credential_literal_in_exception_message(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _config_with_one_provider()
    secret_literal = "zzq9-registered-secret-literal-42"

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"auth failed using credential {secret_literal}")

    monkeypatch.setattr("local_ops.app._make_adapter", _raise)
    sanitizer = Sanitizer()
    sanitizer.register_secret(secret_literal)
    reg = build_providers(cfg, CredentialResolver(cfg, sanitizer), sanitizer=sanitizer)

    adapter = reg.get("broken")
    assert isinstance(adapter, UnavailableAdapter)
    assert secret_literal not in adapter.reason
    assert secret_literal not in adapter.describe().limitations[0]


def test_build_providers_without_sanitizer_still_registers_an_unavailable_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backward compatible call site (e.g. the CLI) that does not pass a sanitizer to
    `build_providers` still gets a working `UnavailableAdapter` — `UnavailableAdapter.__init__` itself
    scrubs pattern-shaped secrets, defense-in-depth."""
    cfg = _config_with_one_provider()

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"password={PASSWORD} rejected")

    monkeypatch.setattr("local_ops.app._make_adapter", _raise)
    reg = build_providers(cfg, CredentialResolver(cfg, Sanitizer()))

    adapter = reg.get("broken")
    assert isinstance(adapter, UnavailableAdapter)
    assert PASSWORD not in adapter.reason


def test_unavailable_adapter_scrubs_reason_even_when_constructed_directly() -> None:
    """Defense-in-depth: any caller constructing `UnavailableAdapter` directly (not only
    `build_providers`) gets a scrubbed `limitations` entry."""
    cfg = ProviderConfig(id="p", kind="demo")
    adapter = UnavailableAdapter(cfg, f"RuntimeError: password={PASSWORD} rejected")
    assert PASSWORD not in adapter.reason
    assert PASSWORD not in adapter.describe().limitations[0]
