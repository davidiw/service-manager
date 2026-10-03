"""Agent-authored catalog proposals (DECISIONS D24).

An assistant that learns something durable about a service proposes a bounded JSON-Patch-style change to
that service's file. The server validates it against the current approved catalog and stores it as a
proposal. A reviewer accepts or rejects it in the browser; accepting writes a patch under the state
directory for a human to apply and commit. The server never writes the catalog, and a proposal never
grants authority: only descriptive and knowledge fields may be changed, and a new binding must have
execution disabled.
"""

from __future__ import annotations

import asyncio
import copy
import difflib
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from local_ops.auth import Principal
from local_ops.catalog import (
    FRONT_MATTER_RE,
    Catalog,
    CatalogCommitError,
    ServiceSpec,
    commit_catalog_path,
    parse_service_markdown,
)
from local_ops.config import ServerConfig
from local_ops.models import Capability, ErrorCode, OpsError, StrictModel, canonical_json, sha256_hex
from local_ops.operations.diagnosis import validate_saved_query_template
from local_ops.release import Sanitizer
from local_ops.storage import Database

# Descriptive and knowledge fields an assistant may change. Everything else (identity, approval,
# disposition, operations, credential references, health checks, existing bindings) stays human-edited.
PROPOSABLE_FIELDS = frozenset({
    "name", "purpose", "why_it_matters", "owner", "backup", "knowledge_holders", "environments", "depends_on", "used_by",
    "next_expiry", "expiry_note", "source_repositories", "observability", "audit_sources", "restart_procedure",
    "knowledge", "facts", "contradictions", "unknowns", "tags", "costs",
})
MAX_CHANGES = 50
MAX_PROPOSAL_BYTES = 64_000
MAX_PENDING_PER_PRINCIPAL = 20
SERVICE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")


class ProposedChange(StrictModel):
    op: Literal["add", "replace", "remove"]
    path: str = Field(pattern=r"^/[^\s]*$", max_length=300)
    value: Any = None
    evidence: list[str] = Field(default_factory=list, max_length=20, description="Released evidence/observation/finding ids supporting this change")


def _pointer(path: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in path.lstrip("/").split("/")]


def _apply(doc: dict[str, Any], change: ProposedChange) -> None:
    parts = _pointer(change.path)
    parent: Any = doc
    for i, key in enumerate(parts[:-1]):
        if isinstance(parent, list):
            if not key.isdigit() or int(key) >= len(parent):
                raise ValueError(f"{change.path}: no list index {key!r}")
            parent = parent[int(key)]
        elif isinstance(parent, dict):
            if key not in parent:
                if change.op != "add":
                    raise ValueError(f"{change.path}: {'/'.join(parts[: i + 1])} does not exist")
                parent[key] = [] if parts[i + 1] == "-" or parts[i + 1].isdigit() else {}
            parent = parent[key]
        else:
            raise ValueError(f"{change.path}: cannot descend into a scalar")
    last = parts[-1]
    if isinstance(parent, list):
        if change.op == "add":
            if last == "-":
                parent.append(change.value)
            elif last.isdigit() and int(last) <= len(parent):
                parent.insert(int(last), change.value)
            else:
                raise ValueError(f"{change.path}: bad list index {last!r}")
            return
        if not last.isdigit() or int(last) >= len(parent):
            raise ValueError(f"{change.path}: no list index {last!r}")
        if change.op == "replace":
            parent[int(last)] = change.value
        else:
            parent.pop(int(last))
        return
    if not isinstance(parent, dict):
        raise ValueError(f"{change.path}: cannot index a scalar")
    if change.op in ("replace", "remove") and last not in parent:
        raise ValueError(f"{change.path}: does not exist")
    if change.op == "remove":
        parent.pop(last)
    else:
        parent[last] = change.value


def _check_allowed(change: ProposedChange) -> None:
    parts = _pointer(change.path)
    top = parts[0]
    if top == "bindings":
        # Mapping a service means recording where it runs; only a brand-new, non-executable binding.
        if change.op != "add" or parts != ["bindings", "-"] or not isinstance(change.value, dict):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"{change.path}: existing bindings are human-edited; only `add /bindings/-` of a new binding may be proposed")
        if change.value.get("execution_enabled"):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"{change.path}: a proposed binding cannot enable execution")
        # Identity and verification are what a human checks before enabling execution; never take them from an assistant.
        claimed = sorted(k for k in ("cluster_identity", "workload_uid", "account_id") if change.value.get(k))
        if claimed or change.value.get("source_state") == "verified":
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"{change.path}: a proposed binding cannot claim {claimed or ['source_state: verified']}; a human records verified identity")
        return
    if top not in PROPOSABLE_FIELDS:
        raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"{change.path}: {top!r} is not proposable (allowed: {sorted(PROPOSABLE_FIELDS | {'bindings (add only)'})})")
    if top == "name" and change.op == "remove":
        raise OpsError(ErrorCode.INVALID_ARGUMENT, "name cannot be removed")


def _git_root(start: Path) -> Path | None:
    d = start
    for _ in range(12):
        if (d / ".git").exists():
            return d
        if d.parent == d:
            return None
        d = d.parent
    return None


def _lines(text: str) -> list[str]:
    # git splits lines on "\n" only; str.splitlines() also splits on U+2028, U+0085 etc. and would corrupt hunks.
    parts = text.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _unified_diff(old: str, new: str, fromfile: str, tofile: str) -> str:
    out = []
    for line in difflib.unified_diff(_lines(old), _lines(new), fromfile=fromfile, tofile=tofile):
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def _render(front: dict[str, Any], body: str) -> str:
    text = yaml.safe_dump(front, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)
    return f"---\n{text}---\n{body}"


class ProposalService:
    def __init__(self, db: Database, config_ref: dict[str, ServerConfig], sanitizer: Sanitizer, catalog_ref: dict[str, Catalog]):
        self.db = db
        self.config_ref = config_ref
        self.sanitizer = sanitizer
        self.catalog_ref = catalog_ref
        # Serializes accept(): two concurrent accepts (even for different service files) must never
        # interleave their working-tree write and Git commit against the one catalog repository.
        self._accept_lock = asyncio.Lock()

    @property
    def config(self) -> ServerConfig:
        # Backed by the same swappable reference Core/Worker use (D29 hot reload): a provider a config
        # proposal just added is citable by a catalog proposal (`knowledge.queries`, a binding) without
        # a restart.
        return self.config_ref["config"]

    @property
    def catalog(self) -> Catalog:
        return self.catalog_ref["catalog"]

    # ------------------------------------------------------------------ agent side
    async def propose(self, principal: Principal, capability: Capability, *, service_id: str, base_revision: str, changes: list[dict[str, Any]], reason: str | None) -> dict[str, Any]:
        if principal.revoked or not principal.has(capability):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, "credential revoked or not granted this capability")
        if not SERVICE_ID_RE.fullmatch(service_id):
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "service_id must be lowercase kebab-case")
        try:
            parsed = [ProposedChange.model_validate(c) for c in changes]
        except ValueError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"invalid change: {str(e)[:400]}") from None
        if not parsed or len(parsed) > MAX_CHANGES:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"propose between 1 and {MAX_CHANGES} changes")
        payload = canonical_json([c.model_dump() for c in parsed])
        if len(payload.encode()) > MAX_PROPOSAL_BYTES or len(reason or "") > 2000:
            raise OpsError(ErrorCode.LIMIT_REACHED, f"proposal exceeds {MAX_PROPOSAL_BYTES} bytes or reason exceeds 2000 characters")
        _, removed = self.sanitizer.scrub({"changes": [c.model_dump() for c in parsed], "reason": reason})
        if removed:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"proposal contains credential-shaped content ({sorted(removed)}); the catalog holds credential references only")
        for c in parsed:
            _check_allowed(c)

        cat = self.catalog
        if base_revision != cat.revision:
            raise OpsError(ErrorCode.PLAN_STALE, f"catalog revision is {cat.revision}, not {base_revision}; re-read with catalog_read and propose against the current revision", data={"current_revision": cat.revision})
        content_hash = sha256_hex(canonical_json({"service_id": service_id, "base_revision": base_revision, "changes": payload}))

        doc = cat.service(service_id)
        if doc is None:
            front: dict[str, Any] = {"schema_version": 1, "id": service_id, "name": service_id}
            body = ""  # FRONT_MATTER_RE drops blank lines after the closing ---, so any would not round-trip
            current_text = ""
            target = cat.root / "services" / f"{service_id}.md"
            if target.exists():
                raise OpsError(ErrorCode.CONFLICT, f"{target.name} exists but did not load into the catalog; fix the file first")
        else:
            target = cat.root / doc.path
            current_text = target.read_text(encoding="utf-8")
            if sha256_hex(current_text) != doc.file_hash:
                raise OpsError(ErrorCode.CONFLICT, "the service file changed on disk since the catalog was loaded; ask the reviewer to reload the catalog")
            m = FRONT_MATTER_RE.match(current_text)
            assert m is not None  # it parsed at load time
            front = yaml.safe_load(m.group(1)) or {}
            body = m.group(2)

        new_front = copy.deepcopy(front)
        for c in parsed:
            try:
                _apply(new_front, c)
            except ValueError as e:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, str(e)) from None
        try:
            spec = ServiceSpec.model_validate(new_front)
        except ValueError as e:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"the proposed service file would not validate: {str(e)[:600]}") from None
        if spec.id != service_id:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "a proposal cannot change the service id")
        for q in spec.knowledge.queries:
            if self.config.provider(q.source_id) is None:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, f"saved query {q.id}: source_id {q.source_id!r} is not a configured provider")
            try:
                validate_saved_query_template(q.model_dump())
            except ValueError as e:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, f"saved query {q.id} does not fit the evidence_query schema: {str(e)[:300]}") from None

        prior = await self.db.proposal_by_content(principal.id, content_hash)
        if prior is not None:
            return {**self.public(prior), "existing": True, "changes": len(parsed), "warnings": []}
        citations = sorted({e for c in parsed for e in c.evidence})
        unreleased = await self.db.unreleased_citations(principal.id, citations)
        if unreleased:
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"cited ids are unknown or not released to you: {unreleased[:10]}")
        # A proposed binding may name exact observed resources (D25); each must be an observation of that
        # provider already released to the proposer, so a proposal cannot point at unseen or withheld rows.
        for c in parsed:
            if _pointer(c.path)[0] != "bindings":
                continue
            proposed = next((b for b in spec.bindings if b.id == c.value.get("id")), None)
            if proposed is None:
                continue
            if self.config.provider(proposed.provider_id) is None:
                raise OpsError(ErrorCode.INVALID_ARGUMENT, f"binding {proposed.id}: provider_id {proposed.provider_id!r} is not a configured provider")
            unseen = await self.db.unreleased_resource_keys(principal.id, proposed.provider_id, proposed.resource_keys)
            if unseen:
                raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"binding {proposed.id}: resource keys never observed on {proposed.provider_id} or not released to you: {unseen[:10]}")
        pending = [r for r in await self.db.proposals(principal_id=principal.id, status="pending_review") if self.effective_status(r) == "pending_review"]
        if len(pending) >= MAX_PENDING_PER_PRINCIPAL:
            raise OpsError(ErrorCode.LIMIT_REACHED, f"{MAX_PENDING_PER_PRINCIPAL} proposals already await review; wait for decisions before proposing more")

        proposed_text = _render(new_front, body)
        # What gets committed is the rendered file, so it must load back to exactly what was validated
        # (YAML folds some characters, e.g. U+0085, on reload).
        if parse_service_markdown(proposed_text, rel_hint := f"services/{service_id}.md").spec != spec:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, f"the proposed {rel_hint} would not round-trip through YAML unchanged; avoid control and line-separator characters")
        notes: list[str] = []
        if doc is not None and _render(front, body) != current_text:
            notes.append("The file is not in canonical YAML form: this patch also reformats the front matter (comments are dropped). Review the listed changes, not only the diff.")
        root = _git_root(cat.root) or cat.root
        rel = str(target.resolve().relative_to(root.resolve()))
        diff = _unified_diff(current_text, proposed_text, "/dev/null" if doc is None else f"a/{rel}", f"b/{rel}")
        if not diff:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "the proposal changes nothing")
        pid, existing = await self.db.insert_proposal({
            "principal_id": principal.id, "capability": capability.value, "service_id": service_id, "is_new_service": doc is None,
            "base_revision": base_revision, "base_file_hash": doc.file_hash if doc else None, "target_path": rel, "reason": reason,
            "changes": [c.model_dump() for c in parsed], "citations": citations, "proposed_text": proposed_text,
            "proposed_file_hash": sha256_hex(proposed_text), "diff": diff, "content_hash": content_hash, "notes": notes,
        })
        if not existing:
            await self.db.app_audit(principal.name, "agent", "catalog.propose", detail=f"{pid} {service_id} ({len(parsed)} changes)")
        warnings = [f"depends_on {d!r} is not a catalog service yet" for d in spec.depends_on if not d.startswith("external:") and d not in cat.services and d != service_id]
        if existing:  # a concurrent identical proposal won the insert
            row = await self.db.proposal(pid)
            assert row is not None
            return {**self.public(row), "existing": True, "changes": len(parsed), "warnings": []}
        return {"proposal_id": pid, "existing": False, "status": "pending_review", "service_id": service_id, "new_service": doc is None, "base_revision": base_revision, "changes": len(parsed), "warnings": warnings + notes}

    async def list_for(self, principal: Principal, *, service_id: str | None = None, status: str | None = None) -> dict[str, Any]:
        rows = await self.db.proposals(principal_id=principal.id, service_id=service_id)
        items = [self.public(r) for r in rows]
        if status:
            items = [i for i in items if i["status"] == status]
        return {"proposals": items, "catalog_revision": self.catalog.revision}

    def effective_status(self, row: dict[str, Any]) -> str:
        """Stored status plus what the current catalog says: applied once the service file matches the
        proposal, stale once the file it was made against has changed. Bound to the one file rather than
        the catalog revision, which also moves with git HEAD and unrelated services."""
        doc = self.catalog.service(row["service_id"])
        if doc is not None and doc.file_hash == row["proposed_file_hash"]:
            return "applied"
        if row["status"] == "pending_review" and (doc.file_hash if doc else None) != row["base_file_hash"]:
            return "stale"
        return str(row["status"])

    def public(self, row: dict[str, Any]) -> dict[str, Any]:
        return {"proposal_id": row["id"], "service_id": row["service_id"], "new_service": row["is_new_service"], "status": self.effective_status(row), "base_revision": row["base_revision"], "reason": row["reason"], "changes": row["changes"], "created_at": row["created_at"], "decided_at": row["decided_at"], "decision_note": row["decision_note"]}

    # ------------------------------------------------------------------ reviewer side
    async def accept(self, proposal_id: str, reviewer: str, note: str | None) -> dict[str, Any]:
        async with self._accept_lock:
            return await self._accept_locked(proposal_id, reviewer, note)

    async def _accept_locked(self, proposal_id: str, reviewer: str, note: str | None) -> dict[str, Any]:
        row = await self.db.proposal(proposal_id)
        if row is None:
            raise OpsError(ErrorCode.NOT_FOUND, "no such proposal")
        status = self.effective_status(row)
        if status != "pending_review":
            raise OpsError(ErrorCode.CONFLICT, f"proposal is {status}; only a pending proposal against the current service file can be accepted")
        target = self.catalog.root / row["target_path"]
        base_hash = row["base_file_hash"]
        if base_hash is None:
            if target.exists():
                raise OpsError(ErrorCode.CONFLICT, "the service file now exists though the proposal was for a new service; it is stale")
            current_text = ""
        else:
            if not target.exists() or sha256_hex(current_text := target.read_text(encoding="utf-8")) != base_hash:
                raise OpsError(ErrorCode.CONFLICT, "the service file changed on disk since the proposal; it is stale")
        out_dir = self.config.state_dir / "proposals"
        out_dir.mkdir(parents=True, exist_ok=True)
        patch = out_dir / f"{proposal_id}.patch"
        patch.write_text(row["diff"], encoding="utf-8")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(row["proposed_text"], encoding="utf-8")
        try:
            commit = await asyncio.to_thread(commit_catalog_path, self.catalog.root, row["target_path"], f"catalog proposal {proposal_id} accepted by {reviewer}: {row['service_id']}")
        except CatalogCommitError as e:
            # Undo the working-tree write so a failed commit never leaves an uncommitted edit behind.
            if current_text:
                target.write_text(current_text, encoding="utf-8")
            elif target.exists():
                target.unlink()
            raise OpsError(ErrorCode.CONFLICT, f"could not commit the accepted proposal: {e}") from None
        if not await self.db.decide_proposal(proposal_id, "accepted", reviewer, note, str(patch)):
            raise OpsError(ErrorCode.CONFLICT, "proposal was decided concurrently")
        await self.db.app_audit(reviewer, "reviewer", "catalog.proposal.accept", detail=f"{proposal_id} {row['service_id']} commit={commit[:12]}")
        return {"proposal_id": proposal_id, "patch_path": str(patch), "commit": commit, "target_path": row["target_path"]}

    async def reject(self, proposal_id: str, reviewer: str, note: str | None) -> None:
        if not await self.db.decide_proposal(proposal_id, "rejected", reviewer, note):
            raise OpsError(ErrorCode.CONFLICT, "proposal is not pending")
        await self.db.app_audit(reviewer, "reviewer", "catalog.proposal.reject", detail=f"{proposal_id}: {note or ''}"[:500])
