"""Assistants propose provider connections; the server verifies, a human approves, the server applies
(DECISIONS D29).

Two narrow proposal kinds only: `kubernetes_connection` (add one kubernetes provider plus its read-only
kubeconfig_context credential) and `cluster_pin` (set `cluster_identity` on an existing kubernetes
provider the server itself verifies against a released AWS observation). Nothing else is proposable.
Accepting writes `config/overlay.yaml` inside the catalog's own Git repository and commits only that
path; the server then rebuilds the provider registry from the merged config and swaps it in atomically.
"""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from local_ops.auth import Principal
from local_ops.catalog import CatalogCommitError, commit_catalog_path
from local_ops.config import (
    ProviderConfig,
    ServerConfig,
    load_server_config,
    merge_config_overlay,
    overlay_path_for,
)
from local_ops.models import Capability, ErrorCode, OpsError, StrictModel, canonical_json, sha256_hex
from local_ops.providers.base import ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.providers.exec_policy import allowed_exec_profiles, validate_exec_plugin
from local_ops.release import Sanitizer
from local_ops.storage import Database


class ConnectionFields(StrictModel):
    provider_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    credential_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    description: str | None = None
    kubeconfig: str
    context: str
    allow_exec_plugins: bool = False


class PinFields(StrictModel):
    provider_id: str
    observation_id: str


def _dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)


def _normalize_server_url(url: str) -> str:
    """Scheme/trailing-slash/host-case-insensitive normalization for comparing a live API server URL
    against an observed EKS `endpoint`."""
    u = url.strip()
    if "://" in u:
        scheme, rest = u.split("://", 1)
    else:
        scheme, rest = "https", u
    rest = rest.rstrip("/")
    host, _, tail = rest.partition("/")
    host = host.lower()
    return f"{scheme.lower()}://{host}" + (f"/{tail}" if tail else "")


def _parse_kubeconfig_context(kubeconfig_path: Path, context_name: str) -> tuple[bool, dict[str, Any] | None]:
    """Returns (context_exists, exec_config_or_None). Static parse only; never loads credentials."""
    try:
        data = yaml.safe_load(kubeconfig_path.read_text(encoding="utf-8")) or {}
    except OSError as e:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"could not read kubeconfig {kubeconfig_path}: {e}") from None
    if not isinstance(data, dict):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"{kubeconfig_path} is not a valid kubeconfig mapping")
    contexts = data.get("contexts") or []
    ctx = next((c for c in contexts if isinstance(c, dict) and c.get("name") == context_name), None)
    if ctx is None:
        return False, None
    user_name = (ctx.get("context") or {}).get("user")
    users = data.get("users") or []
    u = next((x for x in users if isinstance(x, dict) and x.get("name") == user_name), None)
    exec_cfg = ((u or {}).get("user") or {}).get("exec")
    return True, exec_cfg if isinstance(exec_cfg, dict) else None


def _validate_kubeconfig_path(raw: str) -> Path:
    """The proposed kubeconfig must resolve (expanduser + symlinks) to a regular file under the server
    user's own `~/.kube/`, owned by that same user, and not group/world-writable. This stops a proposal
    from pointing the server at an arbitrary host path (probing, or a file an attacker can still edit
    after acceptance); it is deliberately independent of the exec-plugin shape check, which is what
    actually makes a swapped file safe to run. Error messages never include OSError text or file content."""
    p = Path(raw).expanduser()
    try:
        resolved = p.resolve(strict=True)
    except OSError:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubeconfig path does not exist") from None
    kube_home = (Path.home() / ".kube").resolve()
    try:
        resolved.relative_to(kube_home)
    except ValueError:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"kubeconfig must resolve under {kube_home}") from None
    try:
        st = resolved.stat()
    except OSError:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubeconfig path is not accessible") from None
    if not stat.S_ISREG(st.st_mode):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubeconfig must be a regular file")
    if st.st_uid != os.getuid():
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubeconfig must be owned by the server user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubeconfig must not be group- or world-writable")
    return resolved


def _check_connection_fields(current: ServerConfig, f: ConnectionFields) -> tuple[ConnectionFields, dict[str, Any] | None]:
    """Run identically at propose time and re-run, unchanged, at accept time (so a kubeconfig swapped
    on disk, or the merged config drifting between the two, cannot slip through). Returns `f` with
    `kubeconfig` replaced by the fully resolved path actually checked (which is what gets stored and
    committed -- never the raw string the proposer supplied, since that could be unexpanded, relative, or
    a symlink), plus the parsed exec block (for the reviewer to see exactly what will run), if any."""
    if current.provider(f.provider_id) is not None:
        raise OpsError(ErrorCode.CONFLICT, f"provider id {f.provider_id!r} already exists")
    if current.credential(f.credential_id) is not None:
        raise OpsError(ErrorCode.CONFLICT, f"credential id {f.credential_id!r} already exists")
    kubeconfig_path = _validate_kubeconfig_path(f.kubeconfig)
    exists, exec_cfg = _parse_kubeconfig_context(kubeconfig_path, f.context)
    if not exists:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"kubeconfig has no context {f.context!r}")
    if exec_cfg is not None:
        if not f.allow_exec_plugins:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"kubeconfig context {f.context!r} uses an exec credential plugin; propose allow_exec_plugins to evaluate it")
        validate_exec_plugin(exec_cfg, allowed_exec_profiles(current), context_name=f.context)
    elif f.allow_exec_plugins:
        raise OpsError(ErrorCode.INVALID_ARGUMENT, f"kubeconfig context {f.context!r} has no exec plugin; allow_exec_plugins has nothing to allow")
    return f.model_copy(update={"kubeconfig": str(kubeconfig_path)}), exec_cfg


class ConfigProposalService:
    def __init__(self, db: Database, config_ref: dict[str, ServerConfig], providers_ref: dict[str, ProviderRegistry], resolver: CredentialResolver, sanitizer: Sanitizer, catalog_path: Path, auth: Any, provider_overrides: dict[str, Any] | None = None):
        self.db = db
        self.config_ref = config_ref
        self.providers_ref = providers_ref
        self.resolver = resolver
        self.sanitizer = sanitizer
        self._catalog_root = Path(catalog_path)
        self.auth = auth
        self.provider_overrides = provider_overrides or {}
        # Serializes the whole read-modify-write-commit of overlay.yaml: two concurrent accepts must
        # never race on the same file (lost update) or interleave their Git commits.
        self._accept_lock = asyncio.Lock()

    @property
    def config(self) -> ServerConfig:
        return self.config_ref["config"]

    @property
    def providers(self) -> ProviderRegistry:
        return self.providers_ref["providers"]

    def _current_merged(self) -> ServerConfig:
        assert self.config.config_path is not None
        return load_server_config(self.config.config_path, self._catalog_root)

    def _overlay_file(self) -> Path:
        return overlay_path_for(self._catalog_root)

    def _read_overlay(self) -> dict[str, Any]:
        p = self._overlay_file()
        if not p.exists():
            return {}
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ agent side
    async def propose_connection(self, principal: Principal, capability: Capability, fields: dict[str, Any], reason: str | None) -> dict[str, Any]:
        try:
            f = ConnectionFields.model_validate(fields)
        except ValueError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"invalid connection fields: {str(e)[:500]}") from None
        # `credential_id` is excluded from this scan on purpose: `ConnectionFields` already constrains it
        # to a plain identifier slug (like `provider_id`), so it is structurally never a secret value, and
        # its *name* legitimately contains "credential" the way `secretName`/`secretRef` legitimately
        # contain "secret" elsewhere in this codebase's own disclosure conventions.
        _, removed = self.sanitizer.scrub({"provider_id": f.provider_id, "kubeconfig": f.kubeconfig, "context": f.context, "description": f.description, "reason": reason})
        if removed:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"proposal contains credential-shaped content ({sorted(removed)}); only credential references are proposable")
        current = self._current_merged()
        f, exec_cfg = _check_connection_fields(current, f)

        credential = {"id": f.credential_id, "kind": "kubeconfig_context", "context": f.context, "kubeconfig": f.kubeconfig, "purpose": "read"}
        provider: dict[str, Any] = {"id": f.provider_id, "kind": "kubernetes", "description": f.description, "credential": f.credential_id, "context": f.context, "namespaces": [], "allow_exec_plugins": f.allow_exec_plugins}
        # The exact exec command/args/env as parsed, so the reviewer sees precisely what will run
        # (DECISIONS D29); re-validated unchanged at accept time.
        payload = {"kind": "kubernetes_connection", "fields": f.model_dump(), "exec": exec_cfg}
        overlay = self._read_overlay()
        new_overlay = dict(overlay)
        new_overlay["credentials"] = [*overlay.get("credentials", []), credential]
        new_overlay.setdefault("providers", list(overlay.get("providers", [])))
        new_overlay["providers"] = [*overlay.get("providers", []), provider]
        return await self._propose(principal, capability, "kubernetes_connection", payload, reason, new_overlay, f"add kubernetes provider {f.provider_id!r} (credential {f.credential_id!r})")

    async def propose_pin(self, principal: Principal, capability: Capability, fields: dict[str, Any], reason: str | None) -> dict[str, Any]:
        try:
            f = PinFields.model_validate(fields)
        except ValueError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"invalid pin fields: {str(e)[:500]}") from None
        current = self._current_merged()
        prov = current.provider(f.provider_id)
        if prov is None or prov.kind != "kubernetes":
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"{f.provider_id!r} is not a configured kubernetes provider")
        if prov.cluster_identity or prov.cluster_identity_file:
            raise OpsError(ErrorCode.CONFLICT, f"provider {f.provider_id!r} already has a cluster identity")
        pin = await self._verify_pin(principal, current, prov, f.observation_id)
        payload = {"kind": "cluster_pin", "fields": f.model_dump(), "pin": pin}
        overlay = self._read_overlay()
        new_overlay = dict(overlay)
        pins = dict(overlay.get("cluster_identity_pins", {}))
        pins[f.provider_id] = pin
        new_overlay["cluster_identity_pins"] = pins
        return await self._propose(principal, capability, "cluster_pin", payload, reason, new_overlay, f"pin cluster_identity on provider {f.provider_id!r}")

    async def _verify_pin(self, principal: Principal, current: ServerConfig, prov: ProviderConfig, observation_id: str) -> dict[str, str]:
        obs = await self.db.observation(observation_id)
        if obs is None or principal.id not in (obs.get("released_to") or []):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"observation {observation_id!r} is unknown or not released to you")
        if obs["resource_type"] != "aws/eks_cluster":
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"observation {observation_id!r} is a {obs['resource_type']!r}, not aws/eks_cluster")
        account = (obs.get("identity") or {}).get("account")
        aws_prov = next((p for p in current.providers if p.kind == "aws" and p.expected_account_id and p.expected_account_id == account), None)
        if aws_prov is None:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"observation {observation_id!r} account {account!r} does not match any configured AWS provider's verified expected_account_id")
        endpoint = (obs.get("attributes") or {}).get("endpoint")
        if not endpoint:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"observation {observation_id!r} has no endpoint to verify against")
        adapter = self.providers.get(prov.id)
        verify = getattr(adapter, "verified_identity", None)
        if adapter is None or verify is None:
            raise OpsError(ErrorCode.CONFLICT, f"provider {prov.id!r} has no live adapter to verify against")
        try:
            live = await verify()
        except OpsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"could not reach provider {prov.id!r} to verify its identity: {type(e).__name__}") from None
        if _normalize_server_url(str(live.get("server") or "")) != _normalize_server_url(str(endpoint)):
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"live API server for {prov.id!r} does not match observation {observation_id!r}'s endpoint", private_detail=f"live={live.get('server')} observed={endpoint}")
        arn = (obs.get("identity") or {}).get("arn")
        if not arn:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"observation {observation_id!r} has no arn")
        return {"kube_system_uid": str(live.get("kube_system_uid")), "eks_arn": str(arn)}

    async def _propose(self, principal: Principal, capability: Capability, kind: str, payload: dict[str, Any], reason: str | None, new_overlay: dict[str, Any], summary: str) -> dict[str, Any]:
        if principal.revoked or not principal.has(capability):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "credential revoked or not granted this capability")
        config_path = self.config.config_path
        assert config_path is not None
        base_raw = config_path.read_text(encoding="utf-8")
        base_data = yaml.safe_load(base_raw) or {}
        try:
            merged = merge_config_overlay(base_data, new_overlay)
            ServerConfig.model_validate(merged)
        except ValueError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"proposal would not produce a valid configuration: {str(e)[:500]}") from None
        old_text = _dump_yaml(self._read_overlay())
        new_text = _dump_yaml(new_overlay)
        content_hash = sha256_hex(canonical_json({"kind": kind, "payload": payload}))
        prior = await self.db.config_proposal_by_content(principal.id, content_hash)
        if prior is not None:
            return {**self.public(prior), "existing": True}
        pid, existing = await self.db.insert_config_proposal({"principal_id": principal.id, "kind": kind, "payload": payload, "overlay_diff": f"--- overlay (current)\n+++ overlay (proposed)\n{summary}\n", "content_hash": content_hash})
        if existing:
            row = await self.db.config_proposal(pid)
            assert row is not None
            return {**self.public(row), "existing": True}
        await self.db.app_audit(principal.name, "agent", "config.propose", detail=f"{pid} {kind}: {summary}")
        return {"proposal_id": pid, "existing": False, "status": "pending_review", "kind": kind, "summary": summary, "diff_preview": f"{old_text}\n->\n{new_text}" if old_text != new_text else new_text}

    async def list_for(self, principal: Principal, *, status: str | None = None) -> dict[str, Any]:
        rows = await self.db.config_proposals(principal_id=principal.id, status=status)
        return {"proposals": [self.public(r) for r in rows]}

    def effective_status(self, row: dict[str, Any]) -> str:
        return str(row["status"])

    def public(self, row: dict[str, Any]) -> dict[str, Any]:
        return {"proposal_id": row["id"], "kind": row["kind"], "status": self.effective_status(row), "payload": row["payload"], "created_at": row["created_at"], "decided_at": row["decided_at"], "decision_note": row["decision_note"], "overlay_commit": row.get("overlay_commit")}

    # ------------------------------------------------------------------ reviewer side
    async def accept(self, proposal_id: str, reviewer: str, note: str | None) -> dict[str, Any]:
        async with self._accept_lock:
            return await self._accept_locked(proposal_id, reviewer, note)

    async def _accept_locked(self, proposal_id: str, reviewer: str, note: str | None) -> dict[str, Any]:
        row = await self.db.config_proposal(proposal_id)
        if row is None:
            raise OpsError(ErrorCode.NOT_FOUND, "no such proposal")
        if self.effective_status(row) != "pending_review":
            raise OpsError(ErrorCode.CONFLICT, f"proposal is {row['status']}; only a pending proposal can be accepted")
        kind, payload = row["kind"], row["payload"]
        current = self._current_merged()
        overlay = self._read_overlay()
        new_overlay = dict(overlay)
        if kind == "kubernetes_connection":
            f = ConnectionFields.model_validate(payload["fields"])
            try:
                f, _exec_cfg = _check_connection_fields(current, f)
            except OpsError as e:
                if not await self.db.decide_config_proposal(proposal_id, "stale", reviewer, f"re-verification failed: {e.message}"):
                    raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently") from None
                raise OpsError(ErrorCode.CONFLICT, f"proposal no longer applies cleanly; marked stale: {e.message}") from None
            credential = {"id": f.credential_id, "kind": "kubeconfig_context", "context": f.context, "kubeconfig": f.kubeconfig, "purpose": "read"}
            provider: dict[str, Any] = {"id": f.provider_id, "kind": "kubernetes", "description": f.description, "credential": f.credential_id, "context": f.context, "namespaces": [], "allow_exec_plugins": f.allow_exec_plugins}
            new_overlay["credentials"] = [*overlay.get("credentials", []), credential]
            new_overlay["providers"] = [*overlay.get("providers", []), provider]
            summary = f"add kubernetes provider {f.provider_id!r}"
        elif kind == "cluster_pin":
            f2 = PinFields.model_validate(payload["fields"])
            prov = current.provider(f2.provider_id)
            if prov is None or prov.kind != "kubernetes" or prov.cluster_identity or prov.cluster_identity_file:
                if not await self.db.decide_config_proposal(proposal_id, "stale", reviewer, "provider no longer eligible for a pin"):
                    raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently")
                raise OpsError(ErrorCode.CONFLICT, f"provider {f2.provider_id!r} is no longer eligible for a cluster_identity pin; proposal marked stale")
            proposer = await self.auth.principal(row["principal_id"])
            if proposer is None:
                raise OpsError(ErrorCode.NOT_FOUND, "proposing credential no longer exists")
            try:
                pin = await self._verify_pin(proposer, current, prov, f2.observation_id)
            except OpsError as e:
                if not await self.db.decide_config_proposal(proposal_id, "stale", reviewer, f"re-verification failed: {e.message}"):
                    raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently") from None
                raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"cluster identity could no longer be verified; proposal marked stale: {e.message}") from None
            pins = dict(overlay.get("cluster_identity_pins", {}))
            pins[f2.provider_id] = pin
            new_overlay["cluster_identity_pins"] = pins
            summary = f"pin cluster_identity on {f2.provider_id!r}"
        else:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"unknown proposal kind {kind!r}")

        config_path = current.config_path
        assert config_path is not None
        base_raw = config_path.read_text(encoding="utf-8")
        base_data = yaml.safe_load(base_raw) or {}
        try:
            merge_config_overlay(base_data, new_overlay)
        except ValueError as e:
            if not await self.db.decide_config_proposal(proposal_id, "stale", reviewer, str(e)):
                raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently") from None
            raise OpsError(ErrorCode.CONFLICT, f"proposal no longer applies cleanly; marked stale: {e}") from None

        overlay_file = self._overlay_file()
        overlay_file.parent.mkdir(parents=True, exist_ok=True)
        previous_text = overlay_file.read_text(encoding="utf-8") if overlay_file.exists() else None
        overlay_file.write_text(_dump_yaml(new_overlay), encoding="utf-8")
        rel = str(overlay_file.relative_to(self._catalog_root))
        try:
            commit = await asyncio.to_thread(commit_catalog_path, self._catalog_root, rel, f"config proposal {proposal_id} accepted by {reviewer}: {summary}")
        except CatalogCommitError as e:
            if previous_text is None:
                overlay_file.unlink(missing_ok=True)
            else:
                overlay_file.write_text(previous_text, encoding="utf-8")
            raise OpsError(ErrorCode.CONFLICT, f"could not commit the accepted proposal: {e}") from None
        if not await self.db.decide_config_proposal(proposal_id, "accepted", reviewer, note, commit):
            raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently")
        await self.db.app_audit(reviewer, "reviewer", "config.proposal.accept", detail=f"{proposal_id} {kind} commit={commit[:12]}")
        self._hot_reload()
        return {"proposal_id": proposal_id, "commit": commit, "summary": summary}

    async def reject(self, proposal_id: str, reviewer: str, note: str | None) -> None:
        if not await self.db.decide_config_proposal(proposal_id, "rejected", reviewer, note):
            raise OpsError(ErrorCode.CONFLICT, "proposal is not pending")
        await self.db.app_audit(reviewer, "reviewer", "config.proposal.reject", detail=f"{proposal_id}: {note or ''}"[:500])

    def _hot_reload(self) -> None:
        from local_ops.app import rebuild_providers

        old_config = self.config
        new_config = self._current_merged()
        unchanged_ids = {p.id for p in new_config.providers if (op := old_config.provider(p.id)) is not None and op.model_dump() == p.model_dump()}
        new_registry = rebuild_providers(self.providers, new_config, self.resolver, self.provider_overrides, self.sanitizer, unchanged_ids)
        self.config_ref["config"] = new_config
        self.providers_ref["providers"] = new_registry
