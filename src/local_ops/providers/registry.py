"""OCI registry adapter: resolve mutable tags to immutable digests and read image config labels.

Supports anonymous/basic/bearer-token registries (including a local registry) and, when an aws
provider is configured for the account, ECR via aiobotocore. Reads only."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import httpx

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import ArtifactRef, Coverage, Effect, ErrorCode, OpsError
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    SupportedOperation,
)

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

MANIFEST_TYPES = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"


def split_repository(repository: str) -> tuple[str, str]:
    """`localhost:5001/team/app` -> ("localhost:5001", "team/app"); docker.io defaults."""
    parts = repository.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        return parts[0], parts[1]
    return "registry-1.docker.io", repository if "/" in repository else f"library/{repository}"


class RegistryAdapter:
    kind = "registry"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, http: httpx.AsyncClient | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self._http = http
        self._owned_http = http is None

    async def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.server.limits.http_timeout_seconds)
        return self._http

    async def close(self) -> None:
        if self._http is not None and self._owned_http:
            await self._http.aclose()

    def describe(self) -> AdapterDescription:
        return AdapterDescription(provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=[
            SupportedOperation(name="resolve_digest", effect=Effect.READ, description="Resolve repo:tag to an immutable manifest/index digest and read OCI version labels."),
        ], required_credentials=[c for c in [self.config.credential] if c], credential_configured=True, scope_constraints={"registries": self.config.registries}, limitations=["Multi-platform index digests differ from per-platform manifest digests; both are reported."])

    async def check_availability(self, *, live: bool = False) -> Availability:
        if not live:
            return Availability(available=True, reason="configured_not_live_checked")
        for reg in self.config.registries:
            try:
                r = await (await self.http()).get(f"{self._scheme(reg)}://{reg}/v2/", headers=await self._auth_headers(reg, None))
                if r.status_code in (200, 401):
                    return Availability(available=True, checked_live=True, identity={"registry": reg})
            except httpx.HTTPError as e:
                return Availability(available=False, reason="provider_unavailable", detail=type(e).__name__, checked_live=True)
        return Availability(available=False, reason="no_registry_reachable", checked_live=True)

    def _scheme(self, registry: str) -> str:
        return "http" if registry.startswith("localhost") or registry.startswith("127.0.0.1") else "https"

    def allowed(self, repository: str) -> bool:
        reg, _ = split_repository(repository)
        return not self.config.registries or reg in self.config.registries

    async def _auth_headers(self, registry: str, www_auth: str | None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.resolver and self.config.credential and self.resolver.configured(self.config.credential):
            cred = await self.resolver.resolve(self.config.credential)
            if cred.secret and ":" in cred.secret:
                headers["Authorization"] = "Basic " + base64.b64encode(cred.secret.encode()).decode()
            elif cred.secret:
                headers["Authorization"] = f"Bearer {cred.secret}"
        return headers

    async def _bearer_challenge(self, www_auth: str, repo: str) -> str | None:
        if not www_auth.lower().startswith("bearer"):
            return None
        params = dict(kv.split("=", 1) for kv in www_auth[7:].replace('"', "").split(",") if "=" in kv)
        realm = params.get("realm")
        if not realm:
            return None
        r = await (await self.http()).get(realm, params={"service": params.get("service", ""), "scope": f"repository:{repo}:pull"})
        if r.status_code != 200:
            return None
        return r.json().get("token") or r.json().get("access_token")

    async def resolve(self, image: str) -> ArtifactRef:
        """Resolve `repo:tag` or `repo@sha256:...` into an ArtifactRef with digest kind and version label."""
        if "@sha256:" in image:
            repository, digest = image.split("@", 1)
            tag = None
        else:
            repository, tag = (image.rsplit(":", 1) if image.count(":") > (1 if ":" in image.split("/")[0] else 0) or ("/" in image and image.rfind(":") > image.rfind("/")) else (image, "latest"))
            digest = None
        if not self.allowed(repository):
            raise OpsError(ErrorCode.AUTHORIZATION_DENIED, f"registry for {repository} is not in the configured allow list for {self.provider_id}")
        registry, repo = split_repository(repository)
        client = await self.http()
        base = f"{self._scheme(registry)}://{registry}/v2/{repo}"
        ref = digest or tag
        headers = {"Accept": MANIFEST_TYPES, **(await self._auth_headers(registry, None))}
        r = await client.get(f"{base}/manifests/{ref}", headers=headers)
        if r.status_code == 401 and "www-authenticate" in r.headers:
            token = await self._bearer_challenge(r.headers["www-authenticate"], repo)
            if token:
                headers["Authorization"] = f"Bearer {token}"
                r = await client.get(f"{base}/manifests/{ref}", headers=headers)
        if r.status_code == 404:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"image {image} not found in registry {registry}")
        if r.status_code != 200:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, f"registry {registry} returned {r.status_code} for {repo}", private_detail=r.text[:500])
        resolved_digest = r.headers.get("docker-content-digest") or digest
        if not resolved_digest:
            raise OpsError(ErrorCode.PROVIDER_UNAVAILABLE, "registry did not return a content digest")
        manifest = r.json()
        media = manifest.get("mediaType") or r.headers.get("content-type", "")
        digest_kind: str = "index" if "index" in media or "manifest.list" in media else "manifest"
        version_label = None
        config_digest = None
        if digest_kind == "manifest":
            config_digest = (manifest.get("config") or {}).get("digest")
        else:
            manifests = manifest.get("manifests") or []
            pick = next((m for m in manifests if (m.get("platform") or {}).get("architecture") == "amd64"), manifests[0] if manifests else None)
            if pick:
                r2 = await client.get(f"{base}/manifests/{pick['digest']}", headers=headers)
                if r2.status_code == 200:
                    config_digest = (r2.json().get("config") or {}).get("digest")
        if config_digest:
            r3 = await client.get(f"{base}/blobs/{config_digest}", headers=headers)
            if r3.status_code == 200:
                try:
                    labels = (r3.json().get("config") or {}).get("Labels") or {}
                    version_label = labels.get("org.opencontainers.image.version") or labels.get("version")
                except (json.JSONDecodeError, AttributeError):
                    version_label = None
        return ArtifactRef(reference=f"{repository}@{resolved_digest}", repository=repository, tag=tag, digest=resolved_digest, digest_kind=digest_kind, version_label=version_label)  # type: ignore[arg-type]

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        return DiscoveryReport(provider_id=self.provider_id, notes=["registry adapter resolves artifacts on demand; it does not enumerate repositories"])

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        if query.get("query_type") == "resolve_digest":
            ref = await self.resolve(query["scope"]["image"])
            return EvidenceResult(items=[ref.model_dump()], coverage=Coverage(requested_sources=[self.provider_id], completed_scopes=[self.provider_id]))
        raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, "registry adapter supports resolve_digest only")
