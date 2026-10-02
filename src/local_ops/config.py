"""Server configuration: trusted YAML loading for server settings, provider connections and
credential *references*. Credential values never live here."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from local_ops.models import ReviewMode, StrictModel, sha256_hex

CredentialKind = Literal[
    "none",
    "env",
    "file",
    "aws_profile",
    "aws_sso",
    "aws_static_env",
    "kubeconfig_context",
    "onepassword_service_account",
    "onepassword_desktop",
    "onepassword_cli",
    "onepassword_item",
]


class CredentialRef(StrictModel):
    """A configured resolver entry. Agents reference these by id; they never supply secret paths."""

    id: str
    kind: CredentialKind
    description: str | None = None
    env_var: str | None = None
    path: str | None = None
    profile: str | None = None
    account: str | None = None
    sso_start_url: str | None = None
    kubeconfig: str | None = None
    context: str | None = None
    vault_id: str | None = None
    item_id: str | None = None
    field: str | None = None
    via: str | None = None  # another credential id used to resolve this one (e.g. 1Password item via service account)
    purpose: Literal["read", "execute", "events", "review"] = "read"

    @model_validator(mode="after")
    def _check(self) -> CredentialRef:
        need = {
            "env": ["env_var"],
            "file": ["path"],
            "aws_profile": ["profile"],
            "aws_sso": ["profile"],
            "kubeconfig_context": ["context"],
            "onepassword_service_account": ["env_var"],
            "onepassword_cli": ["account"],
            "onepassword_item": ["vault_id", "item_id", "via"],
        }
        for f in need.get(self.kind, []):
            if getattr(self, f) is None:
                raise ValueError(f"credential {self.id!r} of kind {self.kind} requires {f}")
        if self.kind == "onepassword_cli" and (
            not self.account or not self.account.strip() or self.account.startswith("-")
            or any(ord(ch) < 32 for ch in self.account)
        ):
            raise ValueError("onepassword_cli requires a non-empty account selector without control characters or leading options")
        return self


ProviderKind = Literal[
    "aws",
    "kubernetes",
    "onepassword",
    "onepassword_events",
    "github",
    "grafana",
    "prometheus",
    "loki",
    "pagerduty",
    "local_import",
    "registry",
    "demo",
]


class ProviderConfig(StrictModel):
    id: str
    kind: ProviderKind
    description: str | None = None
    enabled: bool = True
    credential: str | None = None
    execution_credential: str | None = None
    # aws
    account_alias: str | None = None
    expected_account_id: str | None = None
    regions: list[str] = Field(default_factory=list)
    families: list[str] = Field(default_factory=list)
    organizations_enumeration: bool = False
    cloudtrail_lake_event_data_store: str | None = None
    # kubernetes
    context: str | None = None
    cluster_identity_file: str | None = None
    cluster_identity: dict[str, str] | None = None
    namespaces: list[str] = Field(default_factory=list)
    allow_exec_plugins: bool = False
    audit_log_source: str | None = None
    # onepassword
    vaults: list[str] = Field(default_factory=list)
    # github
    org: str | None = None
    repositories: list[str] = Field(default_factory=list)
    audit_log: bool = False
    # http providers
    url: str | None = None
    # local import
    path: str | None = None
    # registry
    registries: list[str] = Field(default_factory=list)
    # free-form, non-executable
    notes: str | None = None

    @model_validator(mode="after")
    def _check(self) -> ProviderConfig:
        if self.kind == "kubernetes" and not self.context and self.enabled:
            raise ValueError(f"kubernetes provider {self.id!r} requires context")
        if self.kind in ("grafana", "prometheus", "loki", "pagerduty") and not self.url and self.kind != "pagerduty":
            raise ValueError(f"{self.kind} provider {self.id!r} requires url")
        if self.kind == "local_import" and not self.path:
            raise ValueError(f"local_import provider {self.id!r} requires path")
        if self.kind == "aws" and not self.regions and self.enabled:
            raise ValueError(f"aws provider {self.id!r} requires explicit regions")
        return self


class Limits(StrictModel):
    provider_concurrency_global: int = Field(default=8, ge=1, le=64)
    provider_concurrency_per_provider: int = Field(default=2, ge=1, le=16)
    http_timeout_seconds: float = Field(default=30, gt=0, le=600)
    interactive_query_budget_seconds: int = Field(default=120, ge=5, le=3600)
    discovery_budget_seconds: int = Field(default=900, ge=10, le=7200)
    deployment_budget_seconds: int = Field(default=900, ge=10, le=7200)
    max_result_bytes: int = Field(default=4_000_000, ge=10_000)
    max_log_lines: int = Field(default=2000, ge=10, le=100_000)


class Retention(StrictModel):
    collected_payload_days: int = 14
    released_evidence_days: int = 30
    audit_event_days: int = 90
    request_metadata_days: int = 90


class ReviewDefaults(StrictModel):
    default_mode: ReviewMode = ReviewMode.REVIEW_BOTH
    approval_ttl_minutes: int = Field(default=60, ge=1)
    plan_ttl_minutes: int = Field(default=30, ge=1)
    yolo_override_max_minutes: int = Field(default=240, ge=1)


class ServerSection(StrictModel):
    bind_host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    public_url: str | None = None
    state_dir: str = "./local-state"
    tls_cert: str | None = None
    tls_key: str | None = None
    log_level: str = "INFO"

    @field_validator("bind_host")
    @classmethod
    def _loopback(cls, v: str) -> str:
        if v in ("localhost",):
            return v
        try:
            if not ipaddress.ip_address(v).is_loopback:
                raise ValueError
        except ValueError as e:
            raise ValueError("v1 only supports loopback bind addresses (127.0.0.1, ::1)") from e
        return v

    @property
    def tls(self) -> bool:
        return bool(self.tls_cert and self.tls_key)

    @property
    def base_url(self) -> str:
        if self.public_url:
            return self.public_url.rstrip("/")
        host = self.bind_host
        if ":" in host:
            host = f"[{host}]"
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{host}:{self.port}"


class ServerConfig(StrictModel):
    schema_version: int = 1
    server: ServerSection = Field(default_factory=ServerSection)
    limits: Limits = Field(default_factory=Limits)
    retention: Retention = Field(default_factory=Retention)
    review: ReviewDefaults = Field(default_factory=ReviewDefaults)
    credentials: list[CredentialRef] = Field(default_factory=list)
    providers: list[ProviderConfig] = Field(default_factory=list)
    helm_binary: str = "helm"
    aws_binary: str = "aws"
    config_path: Path | None = Field(default=None, exclude=True)
    config_hash: str = Field(default="", exclude=True)

    @model_validator(mode="after")
    def _check(self) -> ServerConfig:
        cred_ids = [c.id for c in self.credentials]
        if len(cred_ids) != len(set(cred_ids)):
            raise ValueError("duplicate credential ids")
        prov_ids = [p.id for p in self.providers]
        if len(prov_ids) != len(set(prov_ids)):
            raise ValueError("duplicate provider ids")
        for p in self.providers:
            for c in (p.credential, p.execution_credential):
                if c and c not in cred_ids:
                    raise ValueError(f"provider {p.id!r} references unknown credential {c!r}")
        for cred in self.credentials:
            if cred.via and cred.via not in cred_ids:
                raise ValueError(f"credential {cred.id!r} references unknown via credential {cred.via!r}")
        for p in self.providers:
            if p.kind != "kubernetes" or not p.credential:
                continue
            p_cred = self.credential(p.credential)
            # Only kubeconfig_context credentials declare a context statically; other kinds (env, file,
            # aws_profile, ...) resolve no context of their own, so there is nothing to compare.
            if p_cred is not None and p_cred.kind == "kubeconfig_context" and p_cred.context and p.context and p_cred.context != p.context:
                raise ValueError(f"kubernetes provider {p.id!r} is configured with context {p.context!r} but its credential {p_cred.id!r} declares context {p_cred.context!r}; the executor would mutate through a different context than the one whose identity was verified")
        return self

    def provider(self, provider_id: str) -> ProviderConfig | None:
        return next((p for p in self.providers if p.id == provider_id), None)

    def credential(self, credential_id: str) -> CredentialRef | None:
        return next((c for c in self.credentials if c.id == credential_id), None)

    def resolve_path(self, p: str) -> Path:
        path = Path(p).expanduser()
        if path.is_absolute() or self.config_path is None:
            return path
        return (self.config_path.parent / path).resolve()

    @property
    def state_dir(self) -> Path:
        return self.resolve_path(self.server.state_dir)


def load_server_config(path: str | Path) -> ServerConfig:
    p = Path(path).expanduser().resolve()
    raw = p.read_text(encoding="utf-8")
    data: dict[str, Any] = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("server config must be a mapping")
    cfg = ServerConfig.model_validate(data)
    cfg.config_path = p
    cfg.config_hash = sha256_hex(raw)
    return cfg


def default_server_config_text(state_dir: str = "./local-state", catalog_hint: str = "./catalog/demo") -> str:
    return f"""# Local Operations MCP server configuration (non-secret).
# Credential entries are *references* resolved by the server; never put secret values here.
schema_version: 1
server:
  bind_host: 127.0.0.1
  port: 8765
  state_dir: {state_dir}
limits:
  provider_concurrency_global: 8
  provider_concurrency_per_provider: 2
  http_timeout_seconds: 30
  interactive_query_budget_seconds: 120
retention:
  collected_payload_days: 14
  released_evidence_days: 30
  audit_event_days: 90
review:
  default_mode: review_both
  approval_ttl_minutes: 60
  plan_ttl_minutes: 30
credentials:
  - id: kubeconfig-demo
    kind: kubeconfig_context
    context: kind-local-ops-demo
    purpose: execute
providers:
  - id: demo-fake
    kind: demo
    description: In-process fake provider used by tests and the first-run demo.
  - id: kube-demo
    kind: kubernetes
    description: Disposable local kind cluster created by scripts/demo-cluster.sh
    credential: kubeconfig-demo
    context: kind-local-ops-demo
    cluster_identity_file: {state_dir}/demo-cluster.json
    namespaces: [demo]
  - id: demo-registry
    kind: registry
    description: Local OCI registry beside the kind cluster (tag -> digest resolution)
    registries: ["localhost:5001"]
# catalog hint for `local-ops serve --catalog {catalog_hint}`
"""
