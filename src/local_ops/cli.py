"""local-ops command line: init, serve, doctor, keys, reviewer, catalog."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import typer

from local_ops import __version__
from local_ops.config import ServerConfig, default_server_config_text, load_server_config
from local_ops.models import Capability

app = typer.Typer(add_completion=False, help="Local Operations MCP server.", no_args_is_help=True)
keys_app = typer.Typer(help="Manage client API keys.")
reviewer_app = typer.Typer(help="Manage the browser reviewer login.")
catalog_app = typer.Typer(help="Validate and export catalogs.")
app.add_typer(keys_app, name="keys")
app.add_typer(reviewer_app, name="reviewer")
app.add_typer(catalog_app, name="catalog")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _core(config: ServerConfig, catalog: Path | None = None) -> Any:
    from local_ops.app import build_core

    return await build_core(config, catalog or Path(os.environ.get("LOCAL_OPS_CATALOG", "./catalog/demo")))


@app.command()
def version() -> None:
    typer.echo(__version__)


@app.command()
def init(config_dir: Path = typer.Option(Path("./local-config"), help="Directory for server.yaml and keys.env"), state_dir: Path = typer.Option(Path("./local-state"), help="Private state directory"), reviewer_user: str = typer.Option("reviewer"), reviewer_password_env: str = typer.Option("", help="Env var holding the reviewer password (otherwise prompts)"), show_keys: bool = typer.Option(False, help="Print the generated secrets to stdout (otherwise only keys.env)"), force: bool = typer.Option(False)) -> None:
    """Create a non-secret server config, the private state dir, two capability keys (read, write) and a reviewer login.
    Prints no secrets unless --show-keys; never creates production access."""
    config_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = config_dir / "server.yaml"
    if cfg_path.exists() and not force:
        typer.echo(f"{cfg_path} exists; use --force to overwrite", err=True)
        raise typer.Exit(1)
    rel_state = os.path.relpath(state_dir.resolve(), config_dir.resolve())
    cfg_path.write_text(default_server_config_text(state_dir=rel_state), encoding="utf-8")
    config = load_server_config(cfg_path)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, stat.S_IRWXU)
    password = os.environ.get(reviewer_password_env) if reviewer_password_env else None
    if not password:
        if not sys.stdin.isatty():
            typer.echo("no TTY: supply --reviewer-password-env", err=True)
            raise typer.Exit(2)
        password = getpass.getpass("Reviewer password (min 12 chars): ")

    async def go() -> dict[str, str]:
        core = await _core(config)
        try:
            await core.auth.set_reviewer_password(reviewer_user, password or "")
            secrets: dict[str, str] = {}
            for cap in Capability:
                name = f"{cap.value}-default"
                if await core.db.principal_by_name(name):
                    continue
                _, secret = await core.auth.create_key(name, [cap], note="created by local-ops init")
                secrets[name] = secret
            return secrets
        finally:
            await core.db.close()

    secrets = _run(go())
    keys_path = config_dir / "keys.env"
    lines = [f"LOCAL_OPS_KEY_{n.upper().replace('-', '_')}={s}" for n, s in secrets.items()]
    if lines:
        keys_path.write_text("# Local Ops client keys. Private; mode 0600. Shown once.\n" + "\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(keys_path, stat.S_IRUSR | stat.S_IWUSR)
    typer.echo(f"config: {cfg_path}\nstate:  {state_dir}\nreviewer login: {reviewer_user}\nkeys written (0600): {keys_path} -> {', '.join(secrets) or 'none (already existed)'}")
    if show_keys:
        for n, s in secrets.items():
            typer.echo(f"{n}: {s}")
    typer.echo("next: uv run local-ops serve --config ./local-config/server.yaml --catalog ./catalog/demo")


@app.command()
def serve(config: Path = typer.Option(..., "--config"), catalog: Path = typer.Option(..., "--catalog"), reload: bool = typer.Option(False)) -> None:
    """Run the server (one worker, loopback only)."""
    import uvicorn

    cfg = load_server_config(config)
    os.environ["LOCAL_OPS_CONFIG"] = str(config.resolve())
    os.environ["LOCAL_OPS_CATALOG"] = str(catalog.resolve())
    kwargs: dict[str, Any] = {"host": cfg.server.bind_host, "port": cfg.server.port, "workers": 1, "log_level": cfg.server.log_level.lower(), "access_log": False, "proxy_headers": False, "server_header": False, "date_header": False}
    if cfg.server.tls:
        kwargs["ssl_certfile"] = str(cfg.resolve_path(cfg.server.tls_cert or ""))
        kwargs["ssl_keyfile"] = str(cfg.resolve_path(cfg.server.tls_key or ""))
    typer.echo(f"local-ops {__version__} listening on {cfg.server.base_url} (MCP: /mcp/read /mcp/write; review UI: /review)")
    uvicorn.run("local_ops.app:app_from_env", factory=True, reload=reload, **kwargs)


@app.command()
def doctor(config: Path = typer.Option(..., "--config"), catalog: Path | None = typer.Option(None, "--catalog"), live: bool = typer.Option(False, help="Perform live provider connection checks (explicit opt-in)")) -> None:
    """Report dependency versions, configuration validation and provider setup. Local checks only unless --live."""
    import importlib.metadata as md

    report: dict[str, Any] = {"local_ops": __version__, "python": sys.version.split()[0], "packages": {}, "binaries": {}, "config": {}, "catalog": {}, "providers": []}
    for pkg in ("mcp", "fastapi", "uvicorn", "pydantic", "aiobotocore", "kubernetes_asyncio", "onepassword-sdk", "aiosqlite", "httpx", "jinja2"):
        try:
            report["packages"][pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            report["packages"][pkg] = "missing"
    for b in ("helm", "aws", "kubectl", "kind", "docker", "op"):
        report["binaries"][b] = shutil.which(b) or "not found"
    try:
        # With --catalog, merge the D29 provider-connection overlay too, so doctor reports providers an
        # accepted config_propose added, not only what server.yaml itself names.
        cfg = load_server_config(config, catalog) if catalog else load_server_config(config)
        report["config"] = {"path": str(cfg.config_path), "valid": True, "bind": f"{cfg.server.bind_host}:{cfg.server.port}", "state_dir": str(cfg.state_dir), "providers": len(cfg.providers), "credentials": len(cfg.credentials)}
    except Exception as e:  # noqa: BLE001
        report["config"] = {"valid": False, "error": str(e)}
        typer.echo(json.dumps(report, indent=2))
        raise typer.Exit(1) from None
    if catalog:
        from local_ops.catalog import load_catalog

        cat = load_catalog(catalog)
        report["catalog"] = {"path": str(cat.root), "revision": cat.revision, "services": len(cat.services), "execution_allowed": cat.meta.execution_allowed, "errors": [i.model_dump() for i in cat.errors], "warnings": len([i for i in cat.issues if i.level == "warning"])}

    async def providers() -> None:
        from local_ops.app import build_providers
        from local_ops.providers.credentials import CredentialResolver
        from local_ops.release import Sanitizer

        reg = build_providers(cfg, CredentialResolver(cfg, Sanitizer()))
        for a in reg.adapters.values():
            d = a.describe()
            try:
                av = await a.check_availability(live=live)
                avd = av.model_dump()
            except Exception as e:  # noqa: BLE001
                avd = {"available": False, "reason": type(e).__name__}
            report["providers"].append({"id": d.provider_id, "kind": d.kind, "credential_configured": d.credential_configured, "required_credentials": d.required_credentials, "availability": avd, "limitations": d.limitations})
            close = getattr(a, "close", None)
            if close:
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass

    _run(providers())
    report["mode"] = "live checks performed" if live else "local checks only (pass --live for connection checks)"
    typer.echo(json.dumps(report, indent=2, default=str))
    if report["catalog"].get("errors"):
        raise typer.Exit(1)


@keys_app.command("create")
def keys_create(name: str, grants: list[str] = typer.Option(..., "--grant", help="read|write (repeatable; explicit, not cumulative)"), config: Path = typer.Option(..., "--config"), note: str = typer.Option("")) -> None:
    cfg = load_server_config(config)

    async def go() -> str:
        core = await _core(cfg)
        try:
            _, secret = await core.auth.create_key(name, [Capability(g) for g in grants], note=note or None)
            return secret
        finally:
            await core.db.close()

    secret = _run(go())
    typer.echo(f"created key {name!r} with grants {grants}. Secret (shown once):\n{secret}")


@keys_app.command("list")
def keys_list(config: Path = typer.Option(..., "--config")) -> None:
    cfg = load_server_config(config)

    async def go() -> list[Any]:
        core = await _core(cfg)
        try:
            return await core.auth.list_principals()
        finally:
            await core.db.close()

    for p in _run(go()):
        typer.echo(f"{p.name:32} {p.extra.get('key_prefix', ''):24} grants={','.join(sorted(g.value for g in p.grants)):32} {'REVOKED' if p.revoked else 'active':8} last_used={p.extra.get('last_used_at')}")


@keys_app.command("revoke")
def keys_revoke(name: str, config: Path = typer.Option(..., "--config")) -> None:
    cfg = load_server_config(config)

    async def go() -> None:
        core = await _core(cfg)
        try:
            await core.auth.revoke_key(name)
        finally:
            await core.db.close()

    _run(go())
    typer.echo(f"revoked {name}")


@keys_app.command("rotate")
def keys_rotate(name: str, config: Path = typer.Option(..., "--config")) -> None:
    cfg = load_server_config(config)

    async def go() -> str:
        core = await _core(cfg)
        try:
            _, secret = await core.auth.rotate_key(name)
            return secret
        finally:
            await core.db.close()

    typer.echo(f"rotated {name}. New secret (shown once):\n{_run(go())}")


@reviewer_app.command("set-password")
def reviewer_set_password(config: Path = typer.Option(..., "--config"), username: str = typer.Option("reviewer"), password_env: str = typer.Option("")) -> None:
    cfg = load_server_config(config)
    password = os.environ.get(password_env) if password_env else None
    if not password:
        password = getpass.getpass("New reviewer password (min 12 chars): ")

    async def go() -> None:
        core = await _core(cfg)
        try:
            await core.auth.set_reviewer_password(username, password or "")
        finally:
            await core.db.close()

    _run(go())
    typer.echo(f"reviewer {username!r} password set")


@catalog_app.command("validate")
def catalog_validate(path: Path) -> None:
    from local_ops.catalog import load_catalog

    cat = load_catalog(path)
    for i in cat.issues:
        typer.echo(f"[{i.level}] {i.path}: {i.message}")
    typer.echo(f"{len(cat.services)} services, revision {cat.revision}, execution_allowed={cat.meta.execution_allowed}, executable_operations={cat.executable_operations()}")
    if cat.errors:
        raise typer.Exit(1)


@catalog_app.command("export")
def catalog_export(path: Path, out: Path = typer.Option(Path("./exports/catalog")), fmt: str = typer.Option("markdown")) -> None:
    """Export approved configuration only (no observed state) as readable Markdown or JSON."""
    from local_ops.catalog import catalog_index_markdown, load_catalog, service_to_markdown

    cat = load_catalog(path)
    out.mkdir(parents=True, exist_ok=True)
    gaps = cat.gaps()
    if fmt == "json":
        (out / "catalog.json").write_text(json.dumps({"catalog": cat.meta.model_dump(), "revision": cat.revision, "services": {sid: d.spec.model_dump(mode="json") for sid, d in cat.services.items()}, "gaps": gaps}, indent=2), encoding="utf-8")
    else:
        (out / "README.md").write_text(catalog_index_markdown(cat, gaps), encoding="utf-8")
        for sid, d in cat.services.items():
            (out / f"{sid}.md").write_text(service_to_markdown(d, gaps=[g for g in gaps if g.get("service_id") == sid]), encoding="utf-8")
    typer.echo(f"exported {len(cat.services)} services to {out}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
