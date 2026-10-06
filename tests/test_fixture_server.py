"""Regression coverage for loopback fixture socket ownership."""

from __future__ import annotations

import socket

import httpx
import pytest

import tests.conftest as fixtures


@pytest.mark.asyncio
async def test_make_env_keeps_reserved_health_port_through_catalog_setup(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    original = fixtures.write_catalog

    def catalog_with_port_contention(*args, health_port: int, **kwargs):  # type: ignore[no-untyped-def]
        contender = socket.socket()
        try:
            contender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with pytest.raises(OSError):
                contender.bind(("127.0.0.1", health_port))
        finally:
            contender.close()
        return original(*args, health_port=health_port, **kwargs)

    monkeypatch.setattr(fixtures, "write_catalog", catalog_with_port_contention)
    async with fixtures.make_env(tmp_path) as env:
        async with httpx.AsyncClient() as client:
            assert (await client.get(f"http://127.0.0.1:{env.health_port}/health")).status_code == 200
            assert (await client.get(f"{env.base_url}/review")).status_code == 303
