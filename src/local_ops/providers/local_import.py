"""Local import adapter: reviewed files that stand in for sources without an adapter.

Billing exports, registrar/DNS records, identity/departure lists, service claims and documentary
notes are read from files under the configured path. Every observation carries provenance
(`source_file`, `imported_at`, `imported: True`) and is a *claim* from a file, never live collection.
Content is parsed with csv/json only; nothing is executed or templated. Symlinks that escape the
import directory are refused and oversized files are skipped with a note.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, UnavailableScope, canonical_json, iso, sha256_hex, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    SupportedOperation,
)

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext

KINDS = ("billing", "registrar", "identities", "services", "dns", "events", "notes")
EXTENSIONS = (".json", ".jsonl", ".csv", ".md")
MAX_FILE_BYTES = 20 * 1024 * 1024
RESOURCE_TYPES = {"billing": "import/billing_line", "registrar": "import/domain", "dns": "import/dns_record", "services": "import/service_claim", "identities": "import/identity", "notes": "import/note"}
EVENT_REQUIRED = ("event_key", "provider", "source_id", "occurred_at", "action")
EVENTS_NOTE = "imported events are claims from a reviewed file, not live collection"


def classify(path: Path) -> tuple[str | None, str, str]:
    """`<kind>.<name>.<ext>` or `<kind>.<ext>` -> (kind, name, ext). Unknown kinds yield None."""
    parts = path.name.split(".")
    if len(parts) < 2:
        return None, path.name, ""
    kind, ext = parts[0].lower(), "." + parts[-1].lower()
    name = ".".join(parts[1:-1]) or parts[0]
    return (kind if kind in KINDS else None), name, ext


def _rows_from_json(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = json.loads(text)
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        data = data["records"]
    if not isinstance(data, list):
        return [], ["expected a JSON list or {\"records\": [...]}"]
    notes = []
    rows = []
    for i, row in enumerate(data):
        if isinstance(row, dict):
            rows.append(row)
        else:
            notes.append(f"record {i} is not an object; skipped")
    return rows, notes


def _rows_from_jsonl(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    notes: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            notes.append(f"line {n}: invalid JSON ({e.msg}); skipped")
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            notes.append(f"line {n}: not an object; skipped")
    return rows, notes


def _rows_from_csv(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    reader = csv.DictReader(io.StringIO(text))
    rows = [{str(k).strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k is not None} for row in reader]
    return rows, []


def load_rows(text: str, ext: str) -> tuple[list[dict[str, Any]], list[str]]:
    if ext == ".json":
        return _rows_from_json(text)
    if ext == ".jsonl":
        return _rows_from_jsonl(text)
    if ext == ".csv":
        return _rows_from_csv(text)
    return [], [f"unsupported extension {ext}"]


def markdown_note(text: str) -> dict[str, Any]:
    title = next((ln.lstrip("#").strip() for ln in text.splitlines() if ln.startswith("#")), None)
    return {"title": title, "body": text, "line_count": text.count("\n") + 1}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    lowered = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        v = lowered.get(k.lower())
        if v not in (None, ""):
            return v
    return None


def _as_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [s.strip() for s in str(v).replace(";", ",").split(",") if s.strip()]


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if v is None or v == "":
        return None
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


class LocalImportAdapter:
    kind = "local_import"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: Any = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.root = server.resolve_path(config.path or ".")

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=[
            SupportedOperation(name="discover", effect=Effect.READ, description="Read reviewed import files (<kind>.<name>.{json,jsonl,csv,md}) for billing, registrar, dns, services, identities and notes.", limitations=["observations are claims from files, not live observations", f"files over {MAX_FILE_BYTES // (1024 * 1024)}MB are skipped"]),
            SupportedOperation(name="local_import", effect=Effect.READ, description="filters.kind=events: load events.*.json/jsonl rows already in normalized-event shape.", local_filters=["kind"], limitations=[EVENTS_NOTE]),
        ], required_credentials=[], credential_configured=True, scope_constraints={"path": str(self.root)}, limitations=["Never executes imported content; parsed with csv/json only.", "Symlinks escaping the import directory are refused.", "Kind is declared by the filename prefix; files without a known kind prefix are listed as skipped."])

    async def check_availability(self, *, live: bool = False) -> Availability:
        if not self.root.is_dir():
            return Availability(available=False, reason="path_missing", detail=f"{self.root} is not a directory", checked_live=True)
        return Availability(available=True, checked_live=True, identity={"path": str(self.root)})

    # ---- file enumeration -------------------------------------------------------------------

    def _files(self) -> tuple[list[Path], list[Path], list[str]]:
        """Candidate files, skipped files (refused/unreadable/oversized) and their notes. Symlink escapes
        and oversized files never make it into the returned `files` list, but they are still returned in
        `skipped` so the caller can mark their declared kind partial rather than silently complete."""
        notes: list[str] = []
        if not self.root.is_dir():
            return [], [], [f"import path {self.root} is not a directory"]
        root_real = self.root.resolve()
        files: list[Path] = []
        skipped: list[Path] = []
        for p in sorted(self.root.rglob("*")):
            rel = str(p.relative_to(self.root))
            try:
                real = p.resolve(strict=True)
            except OSError:
                notes.append(f"{rel}: unresolvable path (dangling symlink?); skipped")
                skipped.append(p)
                continue
            if not real.is_relative_to(root_real):
                notes.append(f"{rel}: symlink escapes the import directory; refused")
                skipped.append(p)
                continue
            if not real.is_file():
                continue
            if p.suffix.lower() not in EXTENSIONS:
                continue
            try:
                size = real.stat().st_size
            except OSError:
                notes.append(f"{rel}: unreadable; skipped")
                skipped.append(p)
                continue
            if size > MAX_FILE_BYTES:
                notes.append(f"{rel}: {size} bytes exceeds the {MAX_FILE_BYTES} byte bound; skipped")
                skipped.append(p)
                continue
            files.append(p)
        return files, skipped, notes

    def _read(self, p: Path) -> str:
        return p.read_text(encoding="utf-8", errors="replace")

    # ---- discovery --------------------------------------------------------------------------

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, identity={"path": str(self.root), "imported": True})
        files, skipped, notes = self._files()
        report.notes.extend(notes)
        if not self.root.is_dir():
            report.unavailable.append({"source": self.provider_id, "reason": "path_missing", "detail": str(self.root)})
            return report
        imported_at = iso(utcnow())
        seen_kinds: set[str] = set()
        # A kind is complete only if every file declared under it was actually read. A skipped file
        # (oversized, unreadable, symlink-refused) or a file whose content was entirely unparseable
        # (e.g. a .json file that is not a list) means that kind's observation set is incomplete, even
        # though other files for the same kind parsed fine.
        partial_kinds: set[str] = set()
        for p in skipped:
            skipped_kind, _, _ = classify(p)
            if skipped_kind is not None and skipped_kind != "events":
                partial_kinds.add(skipped_kind)
        for p in files:
            budget.check()
            kind, name, ext = classify(p)
            rel = str(p.relative_to(self.root))
            if kind is None:
                report.notes.append(f"{rel}: no recognised kind prefix ({', '.join(KINDS)}); skipped")
                continue
            if kind == "events":
                report.notes.append(f"{rel}: event files are loaded by evidence_query(local_import, kind=events), not discovery")
                continue
            seen_kinds.add(kind)
            text = self._read(p)
            prov = {"source_file": rel, "imported_at": imported_at, "imported": True, "fixture": False, "sha256": sha256_hex(text)}
            if ext == ".md":
                note = markdown_note(text)
                eid = await ctx.store_evidence(self.provider_id, "local_import_file", {"file": rel, "kind": kind, "content": text}, summary=f"imported {kind} note {rel}", provenance=prov)
                report.observations.append(Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:{kind}:{rel}", resource_type=RESOURCE_TYPES.get(kind, "import/note"), identity={"file": rel, "title": note["title"] or name}, attributes={**note, **prov, "declared_kind": kind}, scope_key=f"{self.provider_id}/{kind}", evidence_id=eid))
                continue
            rows, row_notes = load_rows(text, ext)
            report.notes.extend(f"{rel}: {n}" for n in row_notes)
            if row_notes and not rows:
                # the file was read but its content was entirely unparseable (e.g. a .json file that is
                # not a list/{"records": [...]}), so this kind's observation set from this file is empty,
                # not confirmed-empty.
                partial_kinds.add(kind)
                report.notes.append(f"{rel}: content unparseable as {kind} rows; {kind} is reported partial for this scan")
            eid = await ctx.store_evidence(self.provider_id, "local_import_file", {"file": rel, "kind": kind, "rows": rows}, summary=f"imported {len(rows)} {kind} rows from {rel}", provenance=prov)
            for idx, row in enumerate(rows):
                obs = self._observation(kind, name, rel, idx, row, prov, eid)
                report.observations.append(obs)
                if kind == "registrar":
                    expires = _first(row, "expires_at", "expiry", "expires", "expiration_date")
                    if expires:
                        report.expiries.append({"resource_key": obs.resource_key, "kind": "domain", "expires_at": str(expires), "source_file": rel, "imported": True})
        for k in sorted(seen_kinds | partial_kinds):
            (report.partial_scopes if k in partial_kinds else report.completed_scopes).append(f"{self.provider_id}/{k}")
        if not files:
            report.notes.append(f"no importable files under {self.root}")
        return report

    def _observation(self, kind: str, name: str, rel: str, idx: int, row: dict[str, Any], prov: dict[str, Any], eid: str) -> Observation:
        rtype = RESOURCE_TYPES[kind]
        scope_key = f"{self.provider_id}/{kind}"
        row_hash = sha256_hex(canonical_json(row))[:16]
        if kind == "billing":
            attrs = {"vendor": _first(row, "vendor", "provider", "supplier"), "amount": _first(row, "amount", "total", "cost"), "currency": _first(row, "currency"), "period": _first(row, "period", "month", "billing_period"), "description": _first(row, "description", "item", "line_item"), "service_hint": _first(row, "service_hint", "service", "service_id")}
            return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:billing_line:{row_hash}", resource_type=rtype, identity={"file": rel, "row": idx, "vendor": attrs["vendor"], "period": attrs["period"]}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)
        if kind == "registrar":
            domain = str(_first(row, "domain", "name") or f"row-{idx}").lower()
            attrs = {"domain": domain, "registrar": _first(row, "registrar", "vendor"), "expires_at": _first(row, "expires_at", "expiry", "expires", "expiration_date"), "auto_renew": _as_bool(_first(row, "auto_renew", "autorenew")), "nameservers": _as_list(_first(row, "nameservers", "name_servers", "ns")), "owner_account": _first(row, "owner_account", "account", "owner")}
            return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:domain:{domain}", resource_type=rtype, identity={"domain": domain, "file": rel}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)
        if kind == "dns":
            rname = str(_first(row, "name", "record", "host") or f"row-{idx}").lower()
            rtype_dns = str(_first(row, "type", "record_type") or "?").upper()
            attrs = {"name": rname, "type": rtype_dns, "value": _first(row, "value", "target", "data", "content"), "ttl": _first(row, "ttl"), "zone": _first(row, "zone", "domain")}
            return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:dns:{rname}:{rtype_dns}:{row_hash}", resource_type=rtype, identity={"name": rname, "type": rtype_dns, "file": rel}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)
        if kind == "services":
            sid = str(_first(row, "id", "service_id", "name") or f"row-{idx}")
            attrs = {"service_id": sid, "name": _first(row, "name", "title"), "owner": _first(row, "owner", "team"), "environment": _first(row, "environment", "env"), "location": _first(row, "location", "provider", "where"), "url": _first(row, "url", "endpoint"), "description": _first(row, "description", "notes")}
            return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:service_claim:{sid}", resource_type=rtype, identity={"service_id": sid, "file": rel}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)
        if kind == "identities":
            iid = str(_first(row, "id", "identity", "username", "email", "principal") or f"row-{idx}")
            attrs = {"id": iid, "name": _first(row, "name", "display_name"), "status": _first(row, "status", "state"), "departed_at": _first(row, "departed_at", "departure_date", "revoked_at", "left_at"), "role": _first(row, "role", "title"), "providers": _as_list(_first(row, "providers", "systems", "accounts"))}
            return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:identity:{iid}", resource_type=rtype, identity={"id": iid, "file": rel}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)
        title = _first(row, "title", "subject", "name")
        attrs = {"title": title, "body": _first(row, "body", "text", "note", "content"), "author": _first(row, "author"), "date": _first(row, "date", "written_at")}
        return Observation(provider_id=self.provider_id, resource_key=f"import:{self.provider_id}:note:{rel}:{row_hash}", resource_type=rtype, identity={"file": rel, "row": idx, "title": title}, attributes={**attrs, "raw": row, **prov}, scope_key=scope_key, evidence_id=eid)

    # ---- events -----------------------------------------------------------------------------

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        filters = query.get("filters") or {}
        cov = Coverage(requested_sources=[self.provider_id], event_categories=["imported"], source_retention_known=False, source_retention_note=EVENTS_NOTE, filters_local=["kind"], time_range_requested={"start": (query.get("time_range") or {}).get("start"), "end": (query.get("time_range") or {}).get("end")})
        if query.get("query_type") != "local_import" or filters.get("kind", "events") != "events":
            cov.unavailable_scopes.append(UnavailableScope(source=self.provider_id, reason="unsupported_query_type", detail=f"{query.get('query_type')!r} kind={filters.get('kind')!r}; supported: local_import with filters.kind=events"))
            cov.conclusion_scope = "Unsupported query; no evidence collected."
            return EvidenceResult(coverage=cov)
        files, skipped, notes = self._files()
        event_files = [p for p in files if classify(p)[0] == "events" and classify(p)[2] in (".json", ".jsonl")]
        skipped_events = [p for p in skipped if classify(p)[0] == "events"]
        limits = query.get("limits") or {}
        max_events = max(1, min(int(limits.get("max_events", 500) or 500), budget.max_events))
        imported_at = iso(utcnow())
        events: list[dict[str, Any]] = []
        eids: list[str] = []
        result_notes = [EVENTS_NOTE, *notes]
        truncated = False
        for p in event_files:
            budget.check()
            rel = str(p.relative_to(self.root))
            rows, row_notes = load_rows(self._read(p), classify(p)[2])
            result_notes.extend(f"{rel}: {n}" for n in row_notes)
            valid: list[dict[str, Any]] = []
            for idx, row in enumerate(rows):
                missing = [k for k in EVENT_REQUIRED if not row.get(k)]
                if missing:
                    result_notes.append(f"{rel}: record {idx} missing required keys {missing}; skipped")
                    continue
                ev = dict(row)
                ev.setdefault("collected_at", imported_at)
                ev.setdefault("category", "imported")
                fields: dict[str, Any] = ev["fields"] if isinstance(ev.get("fields"), dict) else {}
                ev["fields"] = {**fields, "source_file": rel, "imported": True, "imported_at": imported_at}
                valid.append(ev)
            eid = await ctx.store_evidence(self.provider_id, "local_import_events", {"file": rel, "events": valid[: max(0, max_events - len(events))]}, summary=f"{len(valid)} imported events from {rel}", provenance={"source_file": rel, "imported_at": imported_at, "imported": True})
            eids.append(eid)
            for ev in valid:
                if len(events) >= max_events:
                    truncated = True
                    break
                ev["evidence_ref"] = eid
                events.append(ev)
            if truncated:
                break
        cov.truncated = truncated
        cov.completed_scopes = [f"{self.provider_id}/events"] if not truncated and not skipped_events else []
        if truncated:
            cov.collection_gaps.append(f"imported events bounded to {max_events}")
        if skipped_events:
            cov.collection_gaps.append(f"{len(skipped_events)} events file(s) were skipped (oversized/unreadable/symlink-refused); event listing is partial")
        if not event_files:
            result_notes.append(f"no events.*.json/jsonl files under {self.root}")
        if events:
            times = sorted(str(e["occurred_at"]) for e in events)
            cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        cov.conclusion_scope = "Imported events are claims from files; absence of an event here says nothing about the live source."
        return EvidenceResult(items=[{"imported": True, **e} for e in events], events=events, coverage=cov, raw_evidence_ids=eids, notes=result_notes, query_description={"path": str(self.root), "files": [str(p.relative_to(self.root)) for p in event_files], "kind": "events", "imported": True})
