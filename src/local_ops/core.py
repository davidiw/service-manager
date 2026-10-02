"""Shared application core assembled once by the composition root (app.py) and used by both the MCP
surfaces and the browser routes. There is no second, less-restricted execution path."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from local_ops.auth import AuthService, Principal
from local_ops.catalog import Catalog, catalog_index_markdown, load_catalog, service_to_markdown
from local_ops.config import ServerConfig
from local_ops.discovery import service_runtime_view
from local_ops.models import Capability, DataClass, ErrorCode, OpsError, utcnow
from local_ops.operations.base import OperationRegistry
from local_ops.proposals import ProposalService
from local_ops.providers.base import ProviderRegistry
from local_ops.providers.credentials import CredentialResolver
from local_ops.release import Sanitizer, derived_disclosable
from local_ops.requests import RequestService
from local_ops.storage import Database
from local_ops.worker import Worker


@dataclass
class Core:
    config_ref: dict[str, ServerConfig]
    catalog_path: Path
    db: Database
    auth: AuthService
    sanitizer: Sanitizer
    resolver: CredentialResolver
    providers_ref: dict[str, ProviderRegistry]
    registry: OperationRegistry
    requests: RequestService
    worker: Worker
    catalog_ref: dict[str, Catalog]
    proposals: ProposalService
    config_proposals: Any = None
    started_at: Any = field(default_factory=utcnow)

    @property
    def config(self) -> ServerConfig:
        return self.config_ref["config"]

    @property
    def providers(self) -> ProviderRegistry:
        return self.providers_ref["providers"]

    @property
    def catalog(self) -> Catalog:
        return self.catalog_ref["catalog"]

    def reload_catalog(self) -> Catalog:
        self.catalog_ref["catalog"] = load_catalog(self.catalog_path)
        return self.catalog

    # ------------------------------------------------------------ control-only catalog reads (no provider I/O)
    async def catalog_read(self, principal: Principal | None, *, service_id: str | None = None, include_observed: bool = True, include_body: bool = False) -> dict[str, Any]:
        """Approved configuration plus observations released to the principal (reviewer: everything)."""
        audience = principal.id if principal else None
        cat = self.catalog
        if service_id:
            doc = cat.service(service_id)
            if doc is None:
                raise OpsError(ErrorCode.NOT_FOUND, f"service {service_id!r} not in catalog")
            docs = {service_id: doc}
        else:
            docs = cat.services
        obs = await self.db.observations(audience=audience, include_missing=True) if include_observed else []
        gaps = [g for g in cat.gaps() if not service_id or g.get("service_id") == service_id]
        services = []
        for sid, doc in sorted(docs.items()):
            entry: dict[str, Any] = {"spec": doc.spec.model_dump(mode="json"), "path": doc.path, "dependents": cat.dependents_of(sid)}
            if include_body:
                entry["notes"] = doc.body
            if include_observed:
                entry["observed"] = service_runtime_view(sid, obs)
            entry["gaps"] = [g for g in gaps if g.get("service_id") == sid]
            services.append(entry)
        return {"catalog": {"name": cat.meta.name, "revision": cat.revision, "execution_allowed": cat.meta.execution_allowed, "seed": cat.meta.seed, "description": cat.meta.description}, "services": services, "unresolved_observations": [o for o in obs if not o.get("match_service_id")] if include_observed and not service_id else [], "issues": [i.model_dump() for i in cat.issues]}

    async def catalog_gaps(self, principal: Principal | None, *, service_id: str | None = None, kinds: list[str] | None = None) -> dict[str, Any]:
        audience = principal.id if principal else None
        gaps = list(self.catalog.gaps())
        obs = await self.db.observations(audience=audience)
        from local_ops.discovery import observed_gaps

        rows = [{"resource_type": o["resource_type"], "resource_key": o["resource_key"], "identity": o["identity"], "attributes": o["attributes"], "provider_id": o["provider_id"], "match_service_id": o.get("match_service_id"), "match_binding_id": o.get("match_binding_id"), "match_basis": o.get("match_basis"), "match_confidence": o.get("match_confidence")} for o in obs]
        gaps += observed_gaps(rows, self.catalog) if rows else []
        if service_id:
            gaps = [g for g in gaps if g.get("service_id") == service_id]
        if kinds:
            gaps = [g for g in gaps if g["kind"] in kinds]
        by_kind: dict[str, int] = {}
        for g in gaps:
            by_kind[g["kind"]] = by_kind.get(g["kind"], 0) + 1
        scans = []
        for s in await self.db.scans(20):
            req = await self.db.request(s["request_id"])
            if principal is None or (req and req["response_status"] == "released" and (req["principal_id"] == principal.id or principal.id in req["audience"])):
                scans.append({"request_id": s["request_id"], "finished_at": s["finished_at"], "denominators": s["denominators"], "unavailable": s["unavailable"]})
            if len(scans) >= 5:
                break
        return {"gaps": gaps, "by_kind": by_kind, "recent_scans": scans, "note": "Gaps derive from approved configuration plus observations released to you; absence in an incomplete scan is not deletion."}

    async def catalog_export(self, principal: Principal | None, *, fmt: str = "markdown", service_id: str | None = None, write: bool = False) -> dict[str, Any]:
        audience = principal.id if principal else None
        cat = self.catalog
        obs = await self.db.observations(audience=audience)
        gaps = cat.gaps()
        files: dict[str, str] = {}
        if fmt == "json":
            data = await self.catalog_read(principal, service_id=service_id, include_observed=True, include_body=True)
            import json

            files["catalog.json"] = json.dumps(data, indent=2, default=str)
        else:
            if not service_id:
                files["README.md"] = catalog_index_markdown(cat, gaps)
            for sid, doc in sorted(cat.services.items()):
                if service_id and sid != service_id:
                    continue
                view = service_runtime_view(sid, obs)
                observed = {"workloads": [f"{w['kind']}/{w['name']} ns={w['namespace']} images={[d['image'] for d in (w.get('desired_images') or [])]} rollout={w.get('rollout')} match={w.get('match_basis')} ({w.get('match_confidence')}) last_seen={w.get('last_seen_at')}" for w in view["workloads"]], "other_resources": len(view["other_resources"])} if view["observation_count"] else None
                files[f"{sid}.md"] = service_to_markdown(doc, observed=observed, gaps=[g for g in gaps if g.get("service_id") == sid])
        out_dir = None
        if write:
            out_dir = self.config.state_dir / "exports" / utcnow().strftime("%Y%m%dT%H%M%SZ")
            out_dir.mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                (out_dir / name).write_text(content, encoding="utf-8")
        total = sum(len(v) for v in files.values())
        max_inline = self.config.limits.max_result_bytes
        truncated = total > max_inline
        if truncated:
            budget = max_inline
            inline: dict[str, str] = {}
            for name, content in files.items():
                if budget <= 0:
                    break
                inline[name] = content[:budget]
                budget -= len(inline[name])
            files = inline
        return {"format": fmt, "files": files, "written_to": str(out_dir) if out_dir else None, "truncated": truncated, "note": "Exports contain approved configuration and observations released to the requesting principal only."}

    async def ops_snapshot(self, principal: Principal | None) -> Any:
        """Operational-view snapshot over released observations (D26): those released to `principal`, or for
        the local operator (principal None) those released to anyone. Pending/withheld rows never appear."""
        from local_ops.opsview import load_snapshot

        return await load_snapshot(self.db, self.catalog, {p.id: p.kind for p in self.config.providers}, audience=principal.id if principal else None)

    async def observations_query(self, principal: Principal, *, provider_id: str | None = None, resource_type: str | None = None, account: str | None = None, region: str | None = None, tag_key: str | None = None, tag_value: str | None = None, text: str | None = None, unbound_only: bool = False, include_related: bool = False, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """Released observations for correlation work (D26). Filters are exact except `text`, a literal
        case-insensitive substring over the resource key and display label, which only narrows what the
        caller reads; it never creates a relationship or a binding."""
        from local_ops.opsview import account_of, label, resolve_binding, summary

        if not 1 <= limit <= 500 or offset < 0:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "limit must be 1..500 and offset >= 0")
        snap = await self.ops_snapshot(principal)
        bound: set[tuple[str, str]] = set()
        if unbound_only:
            for doc in self.catalog.services.values():
                for b in doc.spec.bindings:
                    bound |= {(r["provider_id"], r["resource_key"]) for r, _ in resolve_binding(b, snap.index)}
        needle = (text or "").lower()
        rows = []
        for r in snap.index.rows:
            tags = (r.get("attributes") or {}).get("tags")
            tags = tags if isinstance(tags, dict) else {}
            if provider_id and r["provider_id"] != provider_id:
                continue
            if resource_type and r["resource_type"] != resource_type:
                continue
            if account and account_of(r) != account:
                continue
            if region and (r.get("identity") or {}).get("region") != region:
                continue
            if tag_key and (tag_key not in tags or (tag_value is not None and tags.get(tag_key) != tag_value)):
                continue
            if needle and needle not in r["resource_key"].lower() and needle not in label(r).lower():
                continue
            if unbound_only and (r["provider_id"], r["resource_key"]) in bound:
                continue
            rows.append(r)
        page = rows[offset : offset + limit]
        items = []
        for r in page:
            item = {"observation_id": r["id"], "provider_id": r["provider_id"], "resource_key": r["resource_key"], "resource_type": r["resource_type"], "label": label(r), "identity": r.get("identity"), "summary": dict(summary(r)), "evidence_id": r.get("evidence_id"), "scope_key": r.get("scope_key"), "last_seen_at": r.get("last_seen_at"), "missing_since": r.get("missing_since"), "coverage": snap.coverage.status(r["provider_id"], r.get("scope_key"))}
            if include_related:
                item["relationships"] = [{"kind": e["kind"], "direction": e["direction"], "basis": e["basis"], "target": e["target"], "resolved_key": e["row"]["resource_key"] if e["row"] else None, "resolved_type": e["row"]["resource_type"] if e["row"] else None, "resolved_label": label(e["row"]) if e["row"] else None} for e in snap.index.neighbours(r)]
            items.append(item)
        return {"items": items, "total": len(rows), "offset": offset, "limit": limit, "has_more": offset + limit < len(rows), "catalog_revision": self.catalog.revision, "note": "Released observations only. Relationships are exact provider identifiers; grouping resources into services is a hypothesis to propose with catalog_propose, citing observation ids."}

    async def access_report(self, principal: Principal | None, *, person: str | None = None) -> dict[str, Any]:
        """Onboarding path, coverage, and an exact-match person's access/offboarding checklist (D27)."""
        from local_ops.access import AccessGraph

        snap = await self.ops_snapshot(principal)
        graph = AccessGraph.build(snap)
        found = None
        if person:
            aliases = [a for i in self.catalog.identities for a in [i.id, i.display_name or "", *i.aliases] if person.strip().lower() in {x.strip().lower() for x in [i.id, i.display_name or "", *i.aliases] if x}]
            found = graph.find_person(person, aliases)
        refs = [c.model_dump(mode="json") for doc in self.catalog.services.values() for c in doc.spec.credential_refs if c.kind.startswith("onepassword")]
        vaults = sorted({str((r.get("identity") or {}).get("title")) for r in snap.index.rows if r["resource_type"] == "onepassword/vault"})
        return {"onboarding": graph.onboarding(), "offboarding": graph.offboarding(found, refs, vaults), "person": found, "machine_identities": graph.machine_identities(), "note": "Derived from observations released to you and their scan coverage; nothing here is inferred from names."}

    async def findings_read(self, principal: Principal, request_id: str | None, limit: int) -> dict[str, Any]:
        items = await self.requests.findings_for(principal, request_id, limit)
        return {"items": items, "count": len(items), "note": "Only findings whose contributing evidence has been released to you are listed."}

    async def capabilities(self, principal: Principal | None, capability: Capability | None = None) -> dict[str, Any]:
        caps = [capability] if capability else list(Capability)
        out: dict[str, Any] = {"server": "local-ops-mcp", "version": __import__("local_ops").__version__, "capabilities": {}}
        for cap in caps:
            tools = [{"name": s.name, "data_class": s.data_class.value, "effect": s.effect.value, "summary": s.summary, "args_schema": s.args_model.model_json_schema(), "requires_idempotency_key": s.is_mutation} for s in self.registry.for_capability(cap)]
            modes: dict[str, Any] = {}
            if principal:
                for dc in DataClass.for_capability(cap):
                    m, source, exp = await self.auth.effective_mode(principal.id, dc)
                    modes[dc.value] = {"mode": m.value, "source": source, "expires_at": exp.isoformat() if exp else None}
            out["capabilities"][cap.value] = {"granted": bool(principal and principal.has(cap)), "review_modes": modes, "operations": tools}
        out["providers"] = [d.model_dump(mode="json") for d in self.providers.describe_all()]
        out["catalog"] = {"name": self.catalog.meta.name, "revision": self.catalog.revision, "execution_allowed": self.catalog.meta.execution_allowed, "services": len(self.catalog.services)}
        out["limits"] = self.config.limits.model_dump()
        return out


def disclosable(*audiences: list[str], requester: str) -> bool:
    return derived_disclosable(audiences, requester)
