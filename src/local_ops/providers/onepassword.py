"""1Password metadata adapter over SDK authentication or an inherited human CLI session.

Discovery enumerates vault and item *metadata only* (ids, titles, categories, tags, timestamps). It never
retrieves item fields to build an inventory. Secret resolution is a separate, internal path used only by
the credential resolver for approved `onepassword_item` credential references; the resolved string is
returned to the resolver (which registers it with the sanitizer) and is never logged or stored.

Access scope is the vaults visible to the configured credential, not organization-wide visibility.
Service accounts exclude personal/private/employee vaults; human sessions may see additional vaults.
"""

from __future__ import annotations

import shutil
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from local_ops.config import CredentialRef, ProviderConfig, ServerConfig
from local_ops.models import Effect, ErrorCode, OpsError, iso
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
    from local_ops.providers.credentials import CredentialResolver

INTEGRATION_NAME = "local-ops-mcp"
INTEGRATION_VERSION = "0.1.0"

SCOPED_VIEW_LIMITATION = (
    "Access is a scoped view limited to vaults visible to the configured credential, not organization-wide visibility. "
    "Service accounts exclude personal/private/employee vaults; human sessions may see additional vaults."
)
FIELDS_NOT_AVAILABLE_NOTE = "The Items list API returns item overviews only; field names/values are not exposed and are deliberately not retrieved for inventory."
CUSTODIAN_NOTE = "Do not infer the current custodian from the historical creator or last editor; 1Password metadata does not identify a current owner."

ClientFactory = Callable[[Any], Awaitable[Any]]
"""Given an auth value (service-account token string or `onepassword.DesktopAuth`), returns an
authenticated SDK-shaped client exposing `.vaults.list()`, `.items.list(vault_id)` and
`.secrets.resolve(ref)`."""


async def _default_client_factory(auth: Any) -> Any:
    from onepassword import Client  # imported lazily: loads the native SDK core

    return await Client.authenticate(auth, INTEGRATION_NAME, INTEGRATION_VERSION)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read a field from an SDK pydantic model, a plain object or a dict; enums become their values."""
    if isinstance(obj, dict):
        val = obj.get(name, default)
    else:
        val = getattr(obj, name, default)
    if hasattr(val, "value") and not isinstance(val, str | int | float | bool):
        val = val.value
    return val


def _ts(val: Any) -> str | None:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        try:
            return iso(val)
        except (TypeError, ValueError):
            return val.isoformat()
    return str(val)


class OnePasswordAdapter:
    kind = "onepassword"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, client_factory: ClientFactory | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._client_factory = client_factory
        self._client: Any = None
        if resolver is not None and self._auth_mode() != "onepassword_cli":
            # Hook so other credentials of kind `onepassword_item` can be resolved through this adapter.
            resolver._onepassword_resolver = self.resolve_item_secret

    # ---------------------------------------------------------------- plumbing
    def _credential_ref(self) -> CredentialRef | None:
        if not self.config.credential:
            return None
        return self.server.credential(self.config.credential)

    def _auth_mode(self) -> str:
        ref = self._credential_ref()
        return ref.kind if ref else "unconfigured"

    async def _auth_value(self) -> Any:
        """Service-account token (string) or a DesktopAuth object. Never logged."""
        ref = self._credential_ref()
        if ref is None or self.resolver is None or not self.config.credential:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"1Password provider {self.provider_id} has no credential configured")
        if ref.kind == "onepassword_desktop":
            try:
                from onepassword import DesktopAuth
            except ImportError as e:
                raise OpsError(ErrorCode.AUTH_REQUIRED, "desktop_auth_not_supported_in_this_sdk", private_detail=str(e)) from e
            account = ref.profile or ref.context or ""
            if not account:
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential {ref.id!r} (onepassword_desktop) needs the 1Password account name in `profile`")
            return DesktopAuth(account)
        if ref.kind == "onepassword_service_account":
            # Lock-free path on purpose: resolver.resolve() holds its (non-reentrant) lock while it delegates an
            # `onepassword_item` credential to this adapter, so calling resolve() here again would deadlock.
            cred = await self.resolver._resolve(ref)
            if not cred.secret:
                raise OpsError(ErrorCode.AUTH_REQUIRED, f"service-account token for {ref.id!r} is empty")
            self.resolver.sanitizer.register_secret(cred.secret)
            return cred.secret
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential kind {ref.kind!r} cannot authenticate the 1Password SDK (need onepassword_service_account or onepassword_desktop)")

    async def client(self) -> Any:
        if self._client is None:
            if self._auth_mode() == "onepassword_cli":
                from local_ops.providers.onepassword_cli import CliClient

                ref = self._credential_ref()
                if ref is None or not ref.account or self.resolver is None:
                    raise OpsError(ErrorCode.AUTH_REQUIRED, "1Password CLI account reference is not configured")
                self._client = CliClient(ref.account, self.resolver.sanitizer)
                return self._client
            auth = await self._auth_value()
            factory = self._client_factory or _default_client_factory
            try:
                self._client = await factory(auth)
            except OpsError:
                raise
            except Exception as e:  # noqa: BLE001 - SDK raises untyped exceptions; never include the token
                raise OpsError(_classify(e), f"1Password authentication failed for {self.provider_id}", private_detail=f"{type(e).__name__}: {_safe_message(e)}") from e
        return self._client

    async def resolve_item_secret(self, ref: CredentialRef) -> str:
        """Internal credential resolution for approved `onepassword_item` references. The returned string
        is handed to the credential resolver only; it is never logged, stored or placed in a result."""
        if self._auth_mode() == "onepassword_cli":
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "onepassword_cli supports metadata census only, not secret resolution")
        if not ref.vault_id or not ref.item_id:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential {ref.id!r} needs vault_id and item_id")
        client = await self.client()
        reference = f"op://{ref.vault_id}/{ref.item_id}/{ref.field or 'password'}"
        try:
            value = await client.secrets.resolve(reference)
        except OpsError:
            raise
        except Exception as e:  # noqa: BLE001
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"1Password could not resolve credential {ref.id!r}", private_detail=f"{type(e).__name__} for {reference}") from e
        if not isinstance(value, str):
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"1Password returned a non-string secret for credential {ref.id!r}")
        return value

    async def _visible_vaults(self, client: Any) -> list[Any]:
        if self._auth_mode() == "onepassword_cli":
            await client.check_auth()
        return list(await client.vaults.list())

    def _identity(self, count: int) -> dict[str, Any]:
        if self._auth_mode() == "onepassword_cli":
            ref = self._credential_ref()
            return {"auth": "onepassword_cli", "account": ref.account if ref else None,
                    "visible_vault_count": count, "scope": "vaults visible to authenticated CLI user for configured account"}
        return {"auth": self._auth_mode(), "visible_vault_count": count, "scope": "granted vaults only (not organization-wide)"}

    # ---------------------------------------------------------------- description / availability
    def describe(self) -> AdapterDescription:
        configured = self._client_factory is not None or bool(self.resolver and self.resolver.configured(self.config.credential))
        return AdapterDescription(
            provider_id=self.provider_id, kind=self.kind, description=self.config.description,
            operations=[
                SupportedOperation(name="discover", effect=Effect.READ, description="Vault and item metadata (ids, titles, categories, tags, timestamps) within granted vaults.", provider_side_filters=["vaults"], limitations=[FIELDS_NOT_AVAILABLE_NOTE, "No whole-vault secret export; no item field values in results."]),
                *([] if self._auth_mode() == "onepassword_cli" else [SupportedOperation(name="resolve_item_secret", effect=Effect.READ, description="Internal resolution of an approved onepassword_item credential reference (never returned to callers).", limitations=["Only credentials declared in server configuration; values go to the sanitizer-registered resolver cache only."])]),
            ],
            required_credentials=[c for c in [self.config.credential] if c],
            credential_configured=configured,
            scope_constraints={"vaults": self.config.vaults or "all vaults visible to the credential", "auth": self._auth_mode()},
            limitations=[SCOPED_VIEW_LIMITATION, FIELDS_NOT_AVAILABLE_NOTE, CUSTODIAN_NOTE, "Events (sign-ins, item usage, audit) are a separate source: configure an onepassword_events provider."],
        )

    async def check_availability(self, *, live: bool = False) -> Availability:
        if self._auth_mode() == "onepassword_cli" and not shutil.which("op"):
            return Availability(available=False, reason="op_missing", detail="1Password CLI binary op was not found", checked_live=live)
        configured = self._client_factory is not None or bool(self.resolver and self.resolver.configured(self.config.credential))
        if not configured:
            return Availability(available=False, reason="credential_not_configured", detail=f"credential for {self.provider_id} is not resolvable")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        try:
            client = await self.client()
            vaults = await self._visible_vaults(client)
        except OpsError as e:
            return Availability(available=False, reason=e.code.value, detail=e.message, checked_live=True)
        except Exception as e:  # noqa: BLE001
            return Availability(available=False, reason=_classify(e).value, detail=type(e).__name__, checked_live=True)
        return Availability(available=True, checked_live=True, identity=self._identity(len(vaults)))

    # ---------------------------------------------------------------- discovery
    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        report = DiscoveryReport(provider_id=self.provider_id, notes=[SCOPED_VIEW_LIMITATION, FIELDS_NOT_AVAILABLE_NOTE, CUSTODIAN_NOTE])
        try:
            client = await self.client()
            visible = await self._visible_vaults(client)
        except OpsError as e:
            report.unavailable.append({"source": self.provider_id, "reason": e.code.value, "detail": e.message})
            return report
        except Exception as e:  # noqa: BLE001
            report.unavailable.append({"source": self.provider_id, "reason": _classify(e).value, "detail": type(e).__name__})
            return report
        report.identity = self._identity(len(visible))
        by_id = {str(_attr(v, "id")): v for v in visible}
        by_title = {str(_attr(v, "title")): v for v in visible}
        requested = list(scope.vaults)
        configured = list(self.config.vaults)
        if requested and configured:
            # Configured vaults are the allowed set; a request naming a vault outside it is refused
            # rather than silently honored (same precedent as AWS region scoping).
            wanted = [w for w in requested if w in configured]
            for w in requested:
                if w not in configured:
                    report.unavailable.append({"source": f"{self.provider_id}/{w}", "reason": "vault_outside_configured_scope", "detail": f"vault {w} is not in the provider's configured vaults"})
        else:
            wanted = requested or configured
        if wanted or requested or configured:
            selected = []
            for w in wanted:
                v = by_id.get(w) or by_title.get(w)
                if v is None:
                    report.unavailable.append({"source": f"{self.provider_id}/{w}", "reason": "vault_not_visible_to_credential", "detail": "configured vault is not among the vaults granted to this credential; it may exist but is outside this scoped view"})
                    continue
                selected.append(v)
        else:
            selected = list(visible)
        for v in selected:
            budget.check()
            ctx.check_cancel()
            vid = str(_attr(v, "id"))
            scope_key = f"{self.provider_id}/{vid}"
            vault_meta = {"id": vid, "title": _attr(v, "title"), "description": _attr(v, "description"), "vault_type": _attr(v, "vault_type"), "active_item_count": _attr(v, "active_item_count"), "content_version": _attr(v, "content_version"), "attribute_version": _attr(v, "attribute_version"), "created_at": _ts(_attr(v, "created_at")), "updated_at": _ts(_attr(v, "updated_at"))}
            try:
                items = await client.items.list(vid)
            except Exception as e:  # noqa: BLE001
                report.unavailable.append({"source": scope_key, "reason": _classify(e).value, "detail": type(e).__name__})
                report.partial_scopes.append(scope_key)
                continue
            item_meta = [self._item_metadata(it, vid) for it in items]
            eid = await ctx.store_evidence(self.provider_id, "onepassword_vault_metadata", {"vault": vault_meta, "items": item_meta, "fields_available": False}, summary=f"vault {vault_meta['title']}: {len(item_meta)} items (metadata only)")
            report.observations.append(Observation(
                provider_id=self.provider_id, resource_key=f"op:{vid}", resource_type="onepassword/vault",
                identity={"vault_id": vid, "title": vault_meta["title"]},
                attributes={**{k: val for k, val in vault_meta.items() if k not in ("id", "title")}, "item_count_listed": len(item_meta), "scoped_view": True},
                scope_key=scope_key, evidence_id=eid,
            ))
            for m in item_meta:
                report.observations.append(Observation(
                    provider_id=self.provider_id, resource_key=f"op:{vid}:{m['id']}", resource_type="onepassword/item",
                    identity={"vault_id": vid, "item_id": m["id"], "title": m["title"]},
                    attributes={**{k: val for k, val in m.items() if k not in ("id", "title", "vault_id")}, "fields_available": False, "fields_available_note": FIELDS_NOT_AVAILABLE_NOTE, "custodian_unknown": True, "custodian_note": CUSTODIAN_NOTE},
                    scope_key=scope_key, evidence_id=eid, relationships=[{"kind": "member_of", "target": f"op:{vid}"}],
                ))
            report.completed_scopes.append(scope_key)
        return report

    @staticmethod
    def _item_metadata(it: Any, vault_id: str) -> dict[str, Any]:
        """Overview metadata only. Field values are never read here."""
        websites = _attr(it, "websites") or []
        return {
            "id": str(_attr(it, "id")), "title": _attr(it, "title"), "category": _attr(it, "category"), "vault_id": str(_attr(it, "vault_id") or vault_id),
            "tags": list(_attr(it, "tags") or []), "websites": [str(_attr(w, "url")) for w in websites if _attr(w, "url")],
            "created_at": _ts(_attr(it, "created_at")), "updated_at": _ts(_attr(it, "updated_at")),
        }

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"1Password adapter {self.provider_id} supports discovery only; events come from an onepassword_events provider")


def _classify(e: Exception) -> ErrorCode:
    if isinstance(e, OpsError):
        return e.code
    name = type(e).__name__.lower()
    msg = _safe_message(e).lower()
    if "auth" in name or "token" in msg or "authenticat" in msg or "unauthorized" in msg or "expired" in name:
        return ErrorCode.AUTH_REQUIRED
    return ErrorCode.PROVIDER_UNAVAILABLE


def _safe_message(e: Exception) -> str:
    """Exception text bounded and with any service-account-token-shaped substring removed."""
    import re

    text = str(e)[:300]
    return re.sub(r"\bops_[A-Za-z0-9_\-]{20,}\b", "[REDACTED:onepassword_token]", text)
