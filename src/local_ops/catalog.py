"""Approved service catalog: one Markdown file per service with typed YAML front matter.

The catalog is human-owned, Git-versioned data. Discovery never writes to it. Observed state lives in
the database (see storage.py) and is joined to catalog entries at read time.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from local_ops.gitops import (
    CatalogCommitError as CatalogCommitError,  # noqa: F401 - re-exported for proposals.py/config_proposals.py
)
from local_ops.gitops import (
    commit_catalog_path as commit_catalog_path,  # noqa: F401 - re-exported, same reason
)
from local_ops.gitops import git_revision_excluding_config
from local_ops.models import Confidence, StrictModel, sha256_hex
from local_ops.pagerduty_contracts import PagerDutyTarget

FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)

# Built-in checks an operation may name without declaring them; they inspect the deployment controller.
BUILTIN_HEALTH_CHECKS = {
    "ready_replicas": "All desired replicas of the controller are ready and the rollout has converged.",
    "helm_release_deployed": "Helm release status is deployed at the expected revision.",
    "pagerduty_configuration_matches": "PagerDuty configuration matches the reviewed exact target.",
}
# Kinds a service may declare in `health_checks`. They are application-neutral: what a healthy response
# looks like is data in the service file, never code.
HEALTH_CHECK_KINDS = {
    "http_status": "GET url returns expected_status.",
    "http_json": "GET url returns JSON; json_field equals `equals`, equals the artifact version label "
    "(equals_artifact_version), and/or increases between two reads interval_seconds apart (increases).",
}
KNOWN_EXECUTORS = {"kubernetes_native", "helm", "github_actions_workflow", "pagerduty_configuration"}
EXECUTOR_KINDS = {
    "kubernetes_native": {"rollout_restart", "image_update", "rollback"},
    "helm": {"rollout_restart", "helm_upgrade", "helm_rollback"},
    "github_actions_workflow": {"workflow_dispatch"},
    "pagerduty_configuration": {"configure"},
}


class Evidence(StrictModel):
    source: str  # URL, file path, or source id
    note: str | None = None
    observed_at: str | None = None


class Fact(StrictModel):
    topic: str
    statement: str
    confidence: Confidence = Confidence.CLAIMED
    evidence: list[Evidence] = Field(default_factory=list)


class Claim(StrictModel):
    statement: str
    source: str
    dated: str | None = None


class Contradiction(StrictModel):
    topic: str
    claims: list[Claim]
    status: Literal["unresolved", "resolved"] = "unresolved"
    resolution_hint: str | None = None


class KnowledgeHolder(StrictModel):
    name: str
    role: str | None = None
    status: Literal["current", "departed", "unknown"] = "unknown"
    contact: str | None = None
    note: str | None = None


class SourceRepository(StrictModel):
    url: str
    path: str | None = None
    deployment_mechanism: str | None = None
    workflow: str | None = None
    note: str | None = None
    access: Literal["verified", "claimed", "unavailable"] = "claimed"
    # D30 provenance fields -- observed through providers (GitHub commits/runs, registry manifests, IaC
    # backend config), never inferred. `evidence_class` is "direct" only when the proposal that set it
    # cited a released evidence/observation id with an exact identifier match (enforced in proposals.py);
    # "strong"/"weak" and None (unclaimed) carry no such guarantee.
    commit: str | None = None
    artifact: str | None = None
    tag: str | None = None
    digest: str | None = None
    build_workflow: str | None = None
    iac_backend: str | None = None
    evidence_class: Literal["direct", "strong", "weak"] | None = None


class CredentialReference(StrictModel):
    id: str
    kind: str  # e.g. aws_iam_role, kms_key, k8s_secret, onepassword_item, vault_path, signing_identity
    held_in: str  # where it is held, e.g. "1Password vault X", "AWS Secrets Manager", "Vault (legacy)"
    resolver_id: str | None = None  # server credential id if the server can resolve it
    note: str | None = None
    status: Literal["verified", "claimed", "unknown", "legacy"] = "claimed"


class Observability(StrictModel):
    kind: Literal["logs", "metrics", "dashboard", "alerts", "events", "traces", "oncall"]
    provider_id: str | None = None
    query: str | None = None
    url: str | None = None
    note: str | None = None


class HealthCheckConfig(StrictModel):
    id: str
    kind: str
    url: str | None = None
    expected_status: int = 200
    json_field: str | None = None  # dotted path into the JSON body, e.g. "version" or "status.height"
    equals: str | None = None  # compared as a string
    equals_artifact_version: bool = False  # compare json_field with the deployed artifact's version label
    increases: bool = False  # json_field must be numeric and strictly increase between two reads
    interval_seconds: int = Field(default=5, ge=1, le=60)
    timeout_seconds: int = 10

    @model_validator(mode="after")
    def _check(self) -> HealthCheckConfig:
        if self.kind == "http_json":
            if not self.json_field:
                raise ValueError(f"health check {self.id}: http_json requires json_field")
            if self.equals is None and not self.equals_artifact_version and not self.increases:
                raise ValueError(f"health check {self.id}: http_json needs equals, equals_artifact_version or increases")
        elif self.json_field or self.equals is not None or self.equals_artifact_version or self.increases:
            raise ValueError(f"health check {self.id}: json assertions require kind http_json")
        return self


class SavedQuery(StrictModel):
    """A reviewed `evidence_query` template. Expanded and validated against the live query schema at use
    (`operations.diagnosis.expand_saved_query`); it never grants authority and always runs as an ordinary
    evidence_query request through the review gate."""

    id: str
    description: str
    source_id: str
    query_type: str
    scope: dict[str, Any] = Field(default_factory=dict)
    filters: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, int] = Field(default_factory=dict)
    lookback_minutes: int | None = Field(default=None, ge=1, le=10080)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", v):
            raise ValueError("saved query id must be lowercase [a-z0-9_-]")
        return v


class SignatureMatch(StrictModel):
    source: str = "any"  # a query_type, or "any"
    contains: str = Field(min_length=3, max_length=500)  # literal substring; never a regex


class FailureSignature(StrictModel):
    id: str
    match: SignatureMatch
    meaning: str
    first_steps: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class ServiceKnowledge(StrictModel):
    """Durable, application-neutral investigation knowledge an assistant can reuse across sessions."""

    queries: list[SavedQuery] = Field(default_factory=list)
    failure_signatures: list[FailureSignature] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> ServiceKnowledge:
        for kind, items in (("saved query", self.queries), ("failure signature", self.failure_signatures)):
            ids = [i.id for i in items]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {kind} ids")
        return self


class OperationConfig(StrictModel):
    executor: str
    kind: str
    binding_id: str
    container: str | None = None
    allowed_image_repositories: list[str] = Field(default_factory=list)
    require_digest: bool = True
    readiness_timeout_seconds: int = 180
    health_checks: list[str] = Field(default_factory=list)
    rollback_policy: Literal["explicit_only", "unsupported", "automatic_in_plan"] = "explicit_only"
    # helm
    release: str | None = None
    chart_path: str | None = None
    values_files: list[str] = Field(default_factory=list)
    image_value_path: str | None = None
    # github actions
    repository: str | None = None
    workflow_file: str | None = None
    ref: str | None = None
    inputs_contract: dict[str, str] = Field(default_factory=dict)
    pagerduty_actor_user_id: str | None = None

    @field_validator("pagerduty_actor_user_id")
    @classmethod
    def _pagerduty_actor_user_id(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9]{7,32}", value):
            raise ValueError("pagerduty_actor_user_id must be an alphanumeric PagerDuty provider ID")
        return value

    @model_validator(mode="after")
    def _check(self) -> OperationConfig:
        if self.executor not in KNOWN_EXECUTORS:
            raise ValueError(f"unknown executor {self.executor!r}")
        if self.kind not in EXECUTOR_KINDS[self.executor]:
            raise ValueError(f"executor {self.executor} does not support kind {self.kind!r}")
        if self.executor == "helm" and not self.release:
            raise ValueError("helm operations require release")
        return self


class BindingSelector(StrictModel):
    """Exact, provider-native selection of observed resources for one binding (D25). Every listed tag must
    be present with exactly this value, and the resource type must be listed; nothing is matched by name
    similarity. The binding's provider (one verified account) and optional region bound it further."""

    resource_types: list[str] = Field(min_length=1, max_length=20)
    tags: dict[str, str] = Field(min_length=1, max_length=10)


class Binding(StrictModel):
    id: str
    environment: str
    provider_id: str
    region: str | None = None
    cluster_name: str | None = None
    account_id: str | None = None
    cluster_identity: str | None = None  # provider identity (EKS ARN) or approved local-cluster identity ref
    namespace: str | None = None
    workload_kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ECSService", "EC2", "Lambda", "External"] | None = None
    workload_name: str | None = None
    workload_uid: str | None = None
    container_name: str | None = None
    execution_enabled: bool = False
    source_state: Literal["documentary", "observed", "verified"] = "documentary"
    reported_pod_names: list[str] = Field(default_factory=list)
    # Exact observed resource keys (e.g. instance ARNs) and/or an exact-tag selector (D25). These name
    # where a logical service runs; they never enable execution.
    resource_keys: list[str] = Field(default_factory=list, max_length=500)
    selector: BindingSelector | None = None
    endpoints: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    note: str | None = None
    pagerduty_target: PagerDutyTarget | None = None

    def execution_missing_fields(self) -> list[str]:
        required = ["namespace", "workload_kind", "workload_name", "cluster_identity"]
        return [f for f in required if not getattr(self, f)]


class ServiceSpec(StrictModel):
    schema_version: int = 1
    id: str
    name: str
    purpose: str | None = None
    why_it_matters: str | None = None
    owner: str | None = None
    backup: str | None = None
    disposition: Literal["keep", "retire", "migrate", "undecided"] = "undecided"
    approved_by: str | None = None
    knowledge_holders: list[KnowledgeHolder] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    used_by: list[str] = Field(default_factory=list)
    next_expiry: str | None = None
    expiry_note: str | None = None
    bindings: list[Binding] = Field(default_factory=list)
    source_repositories: list[SourceRepository] = Field(default_factory=list)
    credential_refs: list[CredentialReference] = Field(default_factory=list)
    observability: list[Observability] = Field(default_factory=list)
    audit_sources: list[str] = Field(default_factory=list)
    health_checks: list[HealthCheckConfig] = Field(default_factory=list)
    operations: dict[str, OperationConfig] = Field(default_factory=dict)
    restart_procedure: str | None = None
    knowledge: ServiceKnowledge = Field(default_factory=ServiceKnowledge)
    facts: list[Fact] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    costs: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", v):
            raise ValueError("service id must be lowercase kebab-case")
        return v

    @model_validator(mode="after")
    def _check(self) -> ServiceSpec:
        bids = [b.id for b in self.bindings]
        if len(bids) != len(set(bids)):
            raise ValueError(f"service {self.id}: duplicate binding ids")
        if self.environments:
            for b in self.bindings:
                if b.environment not in self.environments:
                    raise ValueError(f"service {self.id}: binding {b.id} environment {b.environment!r} not in environments")
        for op_name, op in self.operations.items():
            if op_name not in ("restart", "update", "rollback", "redeploy", "configure"):
                raise ValueError(f"service {self.id}: unsupported operation name {op_name!r}")
            ob = self.binding(op.binding_id)
            if ob is None:
                raise ValueError(f"service {self.id}: operation {op_name} references unknown binding {op.binding_id!r}")
            if ob.pagerduty_target is not None and op.executor != "pagerduty_configuration":
                raise ValueError(f"service {self.id}: PagerDuty target on binding {ob.id} requires pagerduty_configuration executor")
            if op.kind == "configure":
                if op.executor != "pagerduty_configuration":
                    raise ValueError(f"service {self.id}: configure requires pagerduty_configuration executor")
                if ob.pagerduty_target is None:
                    raise ValueError(f"service {self.id}: configure binding {ob.id} requires pagerduty_target")
                if op.health_checks != ["pagerduty_configuration_matches"]:
                    raise ValueError(f"service {self.id}: configure requires exactly pagerduty_configuration_matches health check")
                if ob.pagerduty_target.resource_type == "incident" and not op.pagerduty_actor_user_id:
                    raise ValueError(f"service {self.id}: incident configure requires pagerduty_actor_user_id")
            if ob.execution_enabled and op.kind != "configure":
                missing = ob.execution_missing_fields()
                if missing:
                    raise ValueError(f"service {self.id}: binding {ob.id} has execution_enabled but is missing {missing}")
                if not op.health_checks:
                    raise ValueError(f"service {self.id}: executable operation {op_name} declares no health checks")
            if op.kind == "image_update" and not op.container:
                raise ValueError(f"service {self.id}: image_update requires container")
            if op.kind == "image_update" and not op.allowed_image_repositories:
                raise ValueError(f"service {self.id}: image_update requires allowed_image_repositories")
        hc_ids = {h.id for h in self.health_checks}
        if len(hc_ids) != len(self.health_checks):
            raise ValueError(f"service {self.id}: duplicate health check ids")
        for op_name, op in self.operations.items():
            for hc in op.health_checks:
                if hc not in BUILTIN_HEALTH_CHECKS and hc not in hc_ids:
                    raise ValueError(f"service {self.id}: operation {op_name} names health check {hc!r}, which is neither built in ({sorted(BUILTIN_HEALTH_CHECKS)}) nor declared in health_checks")
        for h in self.health_checks:
            if h.id in BUILTIN_HEALTH_CHECKS:
                raise ValueError(f"service {self.id}: health check id {h.id!r} is reserved for a built-in check")
            if h.kind not in HEALTH_CHECK_KINDS:
                raise ValueError(f"service {self.id}: health check {h.id} has unknown kind {h.kind!r} (supported: {sorted(HEALTH_CHECK_KINDS)})")
        return self

    def binding(self, binding_id: str) -> Binding | None:
        return next((b for b in self.bindings if b.id == binding_id), None)

    def health_check(self, hc_id: str) -> HealthCheckConfig | None:
        return next((h for h in self.health_checks if h.id == hc_id), None)


class ServiceDoc(StrictModel):
    spec: ServiceSpec
    body: str
    path: str
    file_hash: str


class IdentityRecord(StrictModel):
    """Known human/service identities and their status; used by departed-identity rules."""

    id: str
    display_name: str | None = None
    kind: Literal["human", "service", "shared_role", "unknown"] = "human"
    status: Literal["current", "departed", "revoked", "unknown"] = "unknown"
    departed_at: str | None = None
    revoked_at: str | None = None
    aliases: list[str] = Field(default_factory=list)  # IAM user names, ARNs, GitHub logins, emails, 1Password user ids
    note: str | None = None


class CatalogMeta(StrictModel):
    name: str
    description: str | None = None
    execution_allowed: bool = False
    seed: bool = False
    expected_identities: list[str] = Field(default_factory=list)
    deployment_mechanisms: dict[str, str] = Field(default_factory=dict)


class CatalogIssue(StrictModel):
    level: Literal["error", "warning"]
    path: str
    message: str


class Catalog:
    def __init__(self, root: Path, meta: CatalogMeta, services: dict[str, ServiceDoc], identities: list[IdentityRecord], revision: str, issues: list[CatalogIssue]):
        self.root = root
        self.meta = meta
        self.services = services
        self.identities = identities
        self.revision = revision
        self.issues = issues

    @property
    def errors(self) -> list[CatalogIssue]:
        return [i for i in self.issues if i.level == "error"]

    def service(self, service_id: str) -> ServiceDoc | None:
        return self.services.get(service_id)

    def dependents_of(self, service_id: str) -> list[str]:
        out = set()
        for sid, doc in self.services.items():
            if service_id in doc.spec.depends_on:
                out.add(sid)
        if service_id in self.services:
            out.update(self.services[service_id].spec.used_by)
        return sorted(out)

    def executable_operations(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if not self.meta.execution_allowed:
            return out
        for sid, doc in self.services.items():
            for op_name, op in doc.spec.operations.items():
                b = doc.spec.binding(op.binding_id)
                if b and b.execution_enabled:
                    out.append((sid, op_name))
        return out

    def gaps(self) -> list[dict[str, Any]]:
        """Static gaps derived from the approved configuration alone."""
        gaps: list[dict[str, Any]] = []
        for sid, doc in sorted(self.services.items()):
            s = doc.spec

            def gap(kind: str, detail: str, severity: str = "medium", *, _sid: str = sid) -> None:
                gaps.append({"service_id": _sid, "kind": kind, "detail": detail, "severity": severity, "basis": "catalog"})

            if not s.owner:
                gap("unknown_owner", "No approved owner recorded.")
            if not s.bindings:
                gap("unbound_service", "No runtime binding recorded; where it runs is unknown.", "high")
            for b in s.bindings:
                # Resource keys can only be proposed once observed and released (D25), so a binding that names
                # exact resources is backed by observation even while its source_state is documentary.
                if b.source_state == "documentary" and not b.resource_keys:
                    gap("documentary_binding", f"Binding {b.id} is documentary only (not observed at runtime).")
                if not b.account_id and b.provider_id.startswith("aws") and not b.resource_keys and b.selector is None:
                    gap("account_unknown", f"Binding {b.id}: AWS account id not recorded.")
                if b.execution_enabled is False and s.operations:
                    gap("execution_disabled", f"Binding {b.id}: operations declared but execution disabled.", "low")
            if not s.source_repositories:
                gap("undocumented_deployment_mechanism", "No source repository / deployment mechanism recorded.")
            elif any(r.deployment_mechanism is None for r in s.source_repositories):
                gap("undocumented_deployment_mechanism", "Source repository recorded without deployment mechanism.")
            if not any(o.kind == "alerts" or o.kind == "oncall" for o in s.observability):
                gap("missing_alert_source", "No alert/on-call source recorded.")
            if not any(o.kind == "logs" for o in s.observability):
                gap("missing_log_source", "No log source recorded.", "low")
            if not s.audit_sources:
                gap("unsupported_audit_coverage", "No audit source recorded for this service.", "low")
            if s.next_expiry is None:
                gap("expiry_unknown", "Expiry/renewal date unknown (not 'none').", "low")
            if not s.credential_refs:
                gap("no_credential_access_proof", "No credential references recorded; access path unknown.", "low")
            for c in s.contradictions:
                if c.status == "unresolved":
                    gap("contradiction", f"{c.topic}: " + " | ".join(f"{cl.statement} [{cl.source}]" for cl in c.claims), "high")
            for u in s.unknowns:
                gap("unknown", u, "low")
            for h in s.knowledge_holders:
                if h.status == "departed":
                    gap("knowledge_holder_departed", f"{h.name} ({h.role or 'role unknown'}) has departed.", "high")
            if not s.knowledge_holders:
                gap("no_knowledge_holder", "No one is recorded as understanding this service.", "medium")
            for dep in s.depends_on:
                if not dep.startswith("external:") and dep not in self.services:
                    gap("dangling_dependency", f"depends_on {dep!r} is not a catalog service.", "medium")
        return gaps


def parse_service_markdown(text: str, path: str) -> ServiceDoc:
    m = FRONT_MATTER_RE.match(text)
    if not m:
        raise ValueError(f"{path}: missing YAML front matter")
    data = yaml.safe_load(m.group(1)) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: front matter must be a mapping")
    spec = ServiceSpec.model_validate(data)
    return ServiceDoc(spec=spec, body=m.group(2), path=path, file_hash=sha256_hex(text))


def committed_change(cat: Catalog) -> str | None:
    """The catalog repository's HEAD commit when it differs from the one `cat` was loaded at, else None.
    Only commits count: uncommitted edits in the working tree never trigger a reload."""
    head = git_revision_excluding_config(cat.root)
    if not head or cat.revision.endswith(f"+git.{head[:12]}"):
        return None
    return head


def load_catalog(root: str | Path) -> Catalog:
    """Load a catalog directory. Runs at startup/reload; the loader is synchronous on purpose
    (local file reads during trusted configuration load, not in a request path)."""
    rootp = Path(root).expanduser().resolve()
    issues: list[CatalogIssue] = []
    meta_path = rootp / "catalog.yaml"
    if meta_path.exists():
        meta = CatalogMeta.model_validate(yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {})
    else:
        meta = CatalogMeta(name=rootp.name)
        issues.append(CatalogIssue(level="warning", path=str(meta_path), message="catalog.yaml missing; execution_allowed defaults to false"))
    services: dict[str, ServiceDoc] = {}
    hasher_parts: list[str] = []
    for p in sorted((rootp / "services").glob("*.md")) if (rootp / "services").exists() else []:
        text = p.read_text(encoding="utf-8")
        hasher_parts.append(f"{p.relative_to(rootp)}:{sha256_hex(text)}")
        try:
            doc = parse_service_markdown(text, str(p.relative_to(rootp)))
        except Exception as e:  # noqa: BLE001 - surface every parse failure as an issue
            issues.append(CatalogIssue(level="error", path=str(p), message=str(e)))
            continue
        if doc.spec.id in services:
            issues.append(CatalogIssue(level="error", path=str(p), message=f"duplicate service id {doc.spec.id}"))
            continue
        services[doc.spec.id] = doc
    identities: list[IdentityRecord] = []
    ipath = rootp / "identities.yaml"
    if ipath.exists():
        text = ipath.read_text(encoding="utf-8")
        hasher_parts.append(f"identities.yaml:{sha256_hex(text)}")
        try:
            raw = yaml.safe_load(text) or {}
            identities = [IdentityRecord.model_validate(i) for i in raw.get("identities", [])]
        except Exception as e:  # noqa: BLE001
            issues.append(CatalogIssue(level="error", path=str(ipath), message=str(e)))
    if meta_path.exists():
        hasher_parts.append(f"catalog.yaml:{sha256_hex(meta_path.read_text(encoding='utf-8'))}")
    # cross references
    for sid, doc in services.items():
        for dep in doc.spec.depends_on:
            if not dep.startswith("external:") and dep not in services:
                issues.append(CatalogIssue(level="warning", path=doc.path, message=f"{sid}: depends_on {dep!r} not in catalog"))
        for ub in doc.spec.used_by:
            if not ub.startswith("external:") and ub not in services:
                issues.append(CatalogIssue(level="warning", path=doc.path, message=f"{sid}: used_by {ub!r} not in catalog"))
        if not meta.execution_allowed:
            for b in doc.spec.bindings:
                if b.execution_enabled:
                    issues.append(CatalogIssue(level="error", path=doc.path, message=f"{sid}: binding {b.id} enables execution but catalog.execution_allowed is false"))
    git_rev = git_revision_excluding_config(rootp)
    revision = sha256_hex("\n".join(hasher_parts))[:24] + (f"+git.{git_rev[:12]}" if git_rev else "")
    return Catalog(rootp, meta, services, identities, revision, issues)


def service_to_markdown(doc: ServiceDoc, observed: dict[str, Any] | None = None, gaps: list[dict[str, Any]] | None = None) -> str:
    """Render a readable service page (export). Observed data must already be disclosure-filtered."""
    s = doc.spec
    lines = [f"# {s.name} (`{s.id}`)", ""]
    lines.append(f"**Disposition:** {s.disposition} · **Owner:** {s.owner or 'unknown'} · **Backup:** {s.backup or 'unknown'} · **Approved by:** {s.approved_by or 'nobody yet'}")
    lines.append("")
    if s.purpose:
        lines += ["## What it is", s.purpose, ""]
    if s.why_it_matters:
        lines += ["## Why it matters", s.why_it_matters, ""]
    lines += ["## Relationships", f"- Depends on: {', '.join(s.depends_on) or 'none recorded'}", f"- Used by: {', '.join(s.used_by) or 'none recorded'}", ""]
    lines.append("## Where it runs (approved bindings)")
    if not s.bindings:
        lines.append("_No bindings recorded._")
    for b in s.bindings:
        lines.append(
            f"- `{b.id}` · env={b.environment} · provider={b.provider_id} · region={b.region or '?'} · cluster={b.cluster_name or '?'} · account={b.account_id or 'unknown'} · "
            f"{b.workload_kind or '?'}/{b.workload_name or '?'} ns={b.namespace or '?'} · state={b.source_state} · execution={'enabled' if b.execution_enabled else 'disabled'}"
        )
        if b.selector is not None:
            lines.append(f"  - selects {', '.join(b.selector.resource_types)} with tags " + ", ".join(f"{k}={v}" for k, v in sorted(b.selector.tags.items())))
        if b.resource_keys:
            lines.append(f"  - names {len(b.resource_keys)} exact resource keys")
        for src in b.sources:
            lines.append(f"  - source: {src}")
    lines.append("")
    if observed:
        lines.append("## Observed runtime state (released observations)")
        for key, val in observed.items():
            lines.append(f"- {key}: {val}")
        lines.append("")
    lines.append("## Artifact, repository and deployment mechanism")
    for r in s.source_repositories:
        lines.append(f"- {r.url}{(' / ' + r.path) if r.path else ''} · mechanism={r.deployment_mechanism or 'unknown'} · access={r.access}{(' · ' + r.note) if r.note else ''}")
    if not s.source_repositories:
        lines.append("_Unknown._")
    lines.append("")
    lines.append("## Credentials and signing identities referenced (never values)")
    for c in s.credential_refs:
        lines.append(f"- `{c.id}` ({c.kind}) held in: {c.held_in} · status={c.status}{(' · ' + c.note) if c.note else ''}")
    if not s.credential_refs:
        lines.append("_None recorded._")
    lines.append("")
    lines.append("## Health, logs, metrics, alerts")
    for h in s.health_checks:
        lines.append(f"- health check `{h.id}` ({h.kind}) {h.url or ''}")
    for o in s.observability:
        lines.append(f"- {o.kind}: provider={o.provider_id or '-'} {o.url or ''} {o.query or ''} {o.note or ''}".rstrip())
    lines.append(f"- audit sources: {', '.join(s.audit_sources) or 'none recorded'}")
    lines.append("")
    lines.append("## Restart / update")
    if s.restart_procedure:
        lines.append(s.restart_procedure)
    for name, op in s.operations.items():
        ob = s.binding(op.binding_id)
        lines.append(f"- {name}: executor={op.executor} kind={op.kind} binding={op.binding_id} enabled={bool(ob and ob.execution_enabled)} checks={op.health_checks}")
    if not s.operations and not s.restart_procedure:
        lines.append("_No validated restart/update path recorded._")
    lines.append("")
    lines.append("## Who understands it")
    for k in s.knowledge_holders:
        lines.append(f"- {k.name} ({k.role or 'role unknown'}) — {k.status}{(' · ' + k.note) if k.note else ''}")
    if not s.knowledge_holders:
        lines.append("_Nobody recorded._")
    lines.append("")
    lines.append("## Facts and confidence")
    for f in s.facts:
        ev = "; ".join(e.source for e in f.evidence) or "no evidence recorded"
        lines.append(f"- [{f.confidence}] {f.topic}: {f.statement} (evidence: {ev})")
    lines.append("")
    if s.contradictions:
        lines.append("## Contradictions requiring verification")
        for contra in s.contradictions:
            lines.append(f"- **{contra.topic}** ({contra.status})")
            for cl in contra.claims:
                lines.append(f"  - {cl.statement} — {cl.source}{(' (' + cl.dated + ')') if cl.dated else ''}")
            if contra.resolution_hint:
                lines.append(f"  - how to resolve: {contra.resolution_hint}")
        lines.append("")
    if s.knowledge.queries or s.knowledge.failure_signatures:
        lines.append("## Investigation knowledge")
        for q in s.knowledge.queries:
            lines.append(f"- saved query `{q.id}` ({q.query_type} via {q.source_id}): {q.description}")
        for sig in s.knowledge.failure_signatures:
            lines.append(f"- signature `{sig.id}` ({sig.match.source} contains {sig.match.contains!r}): {sig.meaning}")
            for step in sig.first_steps:
                lines.append(f"  - first step: {step}")
        lines.append("")
    lines.append("## Unknowns")
    for u in s.unknowns:
        lines.append(f"- {u}")
    if not s.unknowns:
        lines.append("_None recorded (this is itself a claim; verify)._")
    lines.append("")
    lines.append(f"**Expiry:** {s.next_expiry or 'unknown'}{(' — ' + s.expiry_note) if s.expiry_note else ''}")
    lines.append("")
    if gaps:
        lines.append("## Open gaps")
        for g in gaps:
            lines.append(f"- [{g['severity']}] {g['kind']}: {g['detail']}")
        lines.append("")
    if doc.body.strip():
        lines += ["## Operational notes", doc.body.strip(), ""]
    return "\n".join(lines)


def catalog_index_markdown(catalog: Catalog, gaps: list[dict[str, Any]] | None = None) -> str:
    lines = [f"# Service map: {catalog.meta.name}", ""]
    if catalog.meta.description:
        lines += [catalog.meta.description, ""]
    lines.append(f"Catalog revision `{catalog.revision}` · execution_allowed={catalog.meta.execution_allowed} · {len(catalog.services)} services")
    lines.append("")
    lines.append("| Service | Disposition | Owner | Environments | Bindings | Executable ops | Contradictions |")
    lines.append("|---|---|---|---|---|---|---|")
    for sid, doc in sorted(catalog.services.items()):
        s = doc.spec
        ex = [n for n, op in s.operations.items() if (b := s.binding(op.binding_id)) and b.execution_enabled and catalog.meta.execution_allowed]
        contra = sum(1 for c in s.contradictions if c.status == "unresolved")
        lines.append(f"| [{s.name}]({sid}.md) | {s.disposition} | {s.owner or 'unknown'} | {', '.join(s.environments) or '-'} | {len(s.bindings)} | {', '.join(ex) or 'none'} | {contra} |")
    lines.append("")
    if gaps:
        by_kind: dict[str, int] = {}
        for g in gaps:
            by_kind[g["kind"]] = by_kind.get(g["kind"], 0) + 1
        lines.append("## Gap summary")
        for k, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {k}: {n}")
        lines.append("")
    return "\n".join(lines)
