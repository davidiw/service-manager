"""ASGI composition root and lifespan.

One Uvicorn worker, one application instance per state directory (process lock). The lifespan opens the
database, builds providers, starts the three MCP session managers and the durable worker."""

from __future__ import annotations

import fcntl
import logging
import os
import stat
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send

from local_ops.auth import AuthService
from local_ops.catalog import Catalog, load_catalog
from local_ops.config import ServerConfig, load_server_config
from local_ops.core import Core
from local_ops.mcp_surfaces import build_all
from local_ops.models import Capability
from local_ops.operations import diagnosis as op_diagnosis
from local_ops.operations import discovery as op_discovery
from local_ops.operations import execution as op_execution
from local_ops.operations.base import OperationRegistry
from local_ops.proposals import ProposalService
from local_ops.providers.base import ProviderRegistry, UnavailableAdapter
from local_ops.providers.credentials import CredentialResolver
from local_ops.release import Sanitizer
from local_ops.requests import RequestService
from local_ops.storage import Database
from local_ops.worker import Worker

log = logging.getLogger("local_ops.app")


class ProcessLock:
    def __init__(self, path: Path):
        self.path = path
        self._fh: Any = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+")  # noqa: SIM115
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise RuntimeError(f"another local-ops instance already uses state directory {self.path.parent}") from e
        self._fh.seek(0)
        self._fh.truncate()
        self._fh.write(str(os.getpid()))
        self._fh.flush()

    def release(self) -> None:
        if self._fh:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None


def build_providers(config: ServerConfig, resolver: CredentialResolver, overrides: dict[str, Any] | None = None, sanitizer: Sanitizer | None = None) -> ProviderRegistry:
    """Instantiate adapters from config. `overrides` lets tests inject adapters (e.g. a fake kube client).

    A provider construction failure's exception message reaches `capabilities_get` as a limitation,
    unreviewed (`UnavailableAdapter.describe`); it is scrubbed here with the server's own sanitizer
    (so a registered credential literal echoed back by a bad config is also caught, not only
    pattern-shaped secrets) before the message is kept at all.
    """
    reg = ProviderRegistry(concurrency_per_provider=config.limits.provider_concurrency_per_provider)
    overrides = overrides or {}
    for p in config.providers:
        if not p.enabled:
            continue
        if p.id in overrides:
            reg.register(overrides[p.id])
            continue
        try:
            reg.register(_make_adapter(p, config, resolver))
        except Exception as e:  # noqa: BLE001
            log.warning("provider %s unavailable: %s", p.id, e)
            detail = f"{type(e).__name__}: {e}"
            if sanitizer is not None:
                detail, _ = sanitizer.scrub_text(detail)
            reg.register(UnavailableAdapter(p, detail))  # type: ignore[arg-type]
    return reg


def rebuild_providers(old: ProviderRegistry, config: ServerConfig, resolver: CredentialResolver, overrides: dict[str, Any] | None, sanitizer: Sanitizer | None, unchanged_ids: set[str]) -> ProviderRegistry:
    """Rebuild the registry from a merged config after a config proposal is accepted (D29 hot reload).
    Adapters (and their semaphores) are reused for provider ids in `unchanged_ids`; everything else
    (new providers, and any provider whose configuration changed, e.g. a newly pinned cluster_identity)
    is constructed fresh, exactly like the startup path."""
    reg = ProviderRegistry(concurrency_per_provider=config.limits.provider_concurrency_per_provider)
    overrides = overrides or {}
    for p in config.providers:
        if not p.enabled:
            continue
        if p.id in unchanged_ids and p.id in old.adapters:
            reg.adapters[p.id] = old.adapters[p.id]
            reg.per_provider_semaphores[p.id] = old.per_provider_semaphores.get(p.id) or reg.semaphore(p.id)
            continue
        if p.id in overrides:
            reg.register(overrides[p.id])
            continue
        try:
            reg.register(_make_adapter(p, config, resolver))
        except Exception as e:  # noqa: BLE001
            log.warning("provider %s unavailable: %s", p.id, e)
            detail = f"{type(e).__name__}: {e}"
            if sanitizer is not None:
                detail, _ = sanitizer.scrub_text(detail)
            reg.register(UnavailableAdapter(p, detail))  # type: ignore[arg-type]
    return reg


def _make_adapter(p: Any, config: ServerConfig, resolver: CredentialResolver) -> Any:
    kind = p.kind
    if kind == "demo":
        from local_ops.providers.demo import DemoProvider

        return DemoProvider(p, config)
    if kind == "kubernetes":
        from local_ops.providers.kubernetes import KubernetesAdapter

        return KubernetesAdapter(p, config, resolver)
    if kind == "registry":
        from local_ops.providers.registry import RegistryAdapter

        return RegistryAdapter(p, config, resolver)
    if kind == "aws":
        from local_ops.providers.aws import AwsAdapter

        return AwsAdapter(p, config, resolver)
    if kind == "onepassword":
        from local_ops.providers.onepassword import OnePasswordAdapter

        return OnePasswordAdapter(p, config, resolver)
    if kind == "onepassword_events":
        from local_ops.providers.onepassword_events import OnePasswordEventsAdapter

        return OnePasswordEventsAdapter(p, config, resolver)
    if kind == "github":
        from local_ops.providers.github import GitHubAdapter

        return GitHubAdapter(p, config, resolver)
    if kind in ("grafana", "prometheus", "loki"):
        from local_ops.providers import grafana as g

        cls = {"grafana": g.GrafanaAdapter, "prometheus": g.PrometheusAdapter, "loki": g.LokiAdapter}[kind]
        return cls(p, config, resolver)
    if kind == "pagerduty":
        from local_ops.providers.pagerduty import PagerDutyAdapter

        return PagerDutyAdapter(p, config, resolver)
    if kind == "local_import":
        from local_ops.providers.local_import import LocalImportAdapter

        return LocalImportAdapter(p, config, resolver)
    raise ValueError(f"unknown provider kind {kind}")


def build_registry() -> OperationRegistry:
    reg = OperationRegistry()
    op_discovery.register(reg)
    op_diagnosis.register(reg)
    op_execution.register(reg)
    return reg


async def build_core(config: ServerConfig, catalog_path: Path, *, provider_overrides: dict[str, Any] | None = None) -> Core:
    # Re-resolve with the catalog's provider-connection overlay (D29) merged in, so a prior accepted
    # config proposal is picked up on every (re)start regardless of how the caller originally loaded
    # `config`. This is the one canonical loader (`load_server_config`); re-reading here is cheap and
    # keeps every caller correct without threading `catalog_path` through each of them.
    if config.config_path is not None:
        config = load_server_config(config.config_path, catalog_path)
    state = config.state_dir
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, stat.S_IRWXU)
    db = Database(state / "local-ops.sqlite", state / "evidence")
    await db.open()
    sanitizer = Sanitizer()
    resolver = CredentialResolver(config, sanitizer)
    providers = build_providers(config, resolver, provider_overrides, sanitizer)
    auth = AuthService(db, config)
    registry = build_registry()
    catalog_ref: dict[str, Catalog] = {"catalog": load_catalog(catalog_path)}
    # Shared, swappable references (mirrors catalog_ref): accepting a config proposal (D29) rebuilds the
    # provider registry from the merged config and swaps both atomically so new operations see the
    # update while operations already running keep what they captured at start.
    config_ref: dict[str, ServerConfig] = {"config": config}
    providers_ref: dict[str, ProviderRegistry] = {"providers": providers}
    requests = RequestService(db, config, auth, registry, catalog_ref)
    worker = Worker(db, config_ref, auth, registry, providers_ref, sanitizer, requests, catalog_ref)
    proposals = ProposalService(db, config, sanitizer, catalog_ref)
    from local_ops.config_proposals import ConfigProposalService

    config_proposals = ConfigProposalService(db, config_ref, providers_ref, resolver, sanitizer, catalog_path, auth, provider_overrides)
    return Core(config_ref=config_ref, catalog_path=catalog_path, db=db, auth=auth, sanitizer=sanitizer, resolver=resolver, providers_ref=providers_ref, registry=registry, requests=requests, worker=worker, catalog_ref=catalog_ref, proposals=proposals, config_proposals=config_proposals)


class BearerKeyMiddleware:
    """Authenticates every MCP HTTP request (init, POST, GET stream, DELETE) with a bearer API key and
    populates the SDK's `scope["user"]` so sessions are bound to the credential. Keys are never read
    from query strings. An invalid supplied Origin is rejected before authentication."""

    def __init__(self, app: ASGIApp, core: Core, capability: Capability, allowed_origins: set[str]):
        self.app = app
        self.core = core
        self.capability = capability
        self.allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin and origin not in self.allowed_origins:
            await JSONResponse({"error": "forbidden", "message": "invalid Origin"}, status_code=403)(scope, receive, send)
            return  # MCP clients are not browsers: a null Origin is never accepted here
        auth = headers.get("authorization", "")
        secret = auth[7:] if auth.lower().startswith("bearer ") else None
        principal = await self.core.auth.authenticate_key(secret)
        if principal is None or principal.revoked:
            await JSONResponse({"error": "auth_required", "message": "valid bearer credential required"}, status_code=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})(scope, receive, send)
            return
        if not principal.has(self.capability):
            await JSONResponse({"error": "authorization_denied", "message": f"credential not granted {self.capability.value}"}, status_code=403)(scope, receive, send)
            return
        token = AccessToken(token="", client_id=principal.id, scopes=sorted(g.value for g in principal.grants), subject=principal.name)
        scope["user"] = AuthenticatedUser(token)
        scope["auth"] = type("Creds", (), {"scopes": token.scopes})()
        await self.app(scope, receive, send)


class HostOriginMiddleware(BaseHTTPMiddleware):
    """Validate Host and Origin on every browser/API request; add a restrictive CSP and no-sniff headers."""

    def __init__(self, app: ASGIApp, allowed_hosts: set[str], allowed_origins: set[str]):
        super().__init__(app)
        self.allowed_hosts = allowed_hosts
        self.allowed_origins = allowed_origins

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        host = request.headers.get("host", "")
        if host not in self.allowed_hosts:
            return JSONResponse({"error": "forbidden", "message": "invalid Host"}, status_code=421)
        origin = request.headers.get("origin")
        if origin and origin not in self.allowed_origins:
            same_site = request.headers.get("sec-fetch-site") == "same-origin"
            if not (origin == "null" and same_site):
                return JSONResponse({"error": "forbidden", "message": "invalid Origin"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


def allowed_hosts_for(config: ServerConfig) -> set[str]:
    port = config.server.port
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if config.server.public_url:
        from urllib.parse import urlparse

        u = urlparse(config.server.public_url)
        if u.netloc:
            hosts.add(u.netloc)
    return hosts


def create_app(config: ServerConfig, catalog_path: Path, *, provider_overrides: dict[str, Any] | None = None, core_holder: dict[str, Core] | None = None) -> FastAPI:
    from local_ops.web.routes import build_router

    hosts = allowed_hosts_for(config)
    origins = {f"{'https' if config.server.tls else 'http'}://{h}" for h in hosts}
    holder: dict[str, Core] = core_holder if core_holder is not None else {}
    lock = ProcessLock(config.state_dir / "server.lock")
    mcp_servers: dict[Capability, Any] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        lock.acquire()
        core = await build_core(config, catalog_path, provider_overrides=provider_overrides)
        holder["core"] = core
        app.state.core = core
        async with AsyncExitStack() as stack:
            for server in mcp_servers.values():
                await stack.enter_async_context(server.session_manager.run())
            await core.worker.start()
            try:
                yield
            finally:
                await core.worker.stop()
                for adapter in core.providers.adapters.values():
                    close = getattr(adapter, "close", None)
                    if close:
                        try:
                            await close()
                        except Exception:  # noqa: BLE001
                            pass
                await core.db.close()
                lock.release()

    app = FastAPI(title="Local Operations MCP", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(HostOriginMiddleware, allowed_hosts=hosts, allowed_origins=origins)

    # A placeholder core proxy so MCP tool closures resolve the live core after lifespan.
    class CoreProxy:
        def __getattr__(self, item: str) -> Any:
            return getattr(holder["core"], item)

    proxy: Any = CoreProxy()
    mcp_servers.update(build_all(proxy))
    ts = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=sorted(hosts), allowed_origins=sorted(origins))
    for cap, server in mcp_servers.items():
        mcp_app = server.streamable_http_app(streamable_http_path="/", transport_security=ts, json_response=False)
        wrapped = BearerKeyMiddleware(AuthContextMiddleware(mcp_app), proxy, cap, origins)
        app.router.routes.append(Mount(f"/mcp/{cap.value}", app=wrapped))

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}  # reveals nothing about catalog/providers/requests

    app.include_router(build_router(lambda: holder["core"]))
    static_dir = Path(__file__).parent / "web" / "static"
    from starlette.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    return app


def app_from_env() -> FastAPI:
    catalog_path = Path(os.environ["LOCAL_OPS_CATALOG"])
    cfg = load_server_config(os.environ["LOCAL_OPS_CONFIG"], catalog_path)
    return create_app(cfg, catalog_path)
