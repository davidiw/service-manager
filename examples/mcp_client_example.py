#!/usr/bin/env python3
"""Generic official-SDK client example (mcp>=2): connect to one capability surface with a bearer key,
submit an operation, poll status and retrieve the released result.

Usage:
    export LOCAL_OPS_KEY_READ_DEFAULT=...   # from local-config/keys.env
    uv run python examples/mcp_client_example.py read discovery_scan '{"providers": ["demo-fake"]}'
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

BASE = os.environ.get("LOCAL_OPS_URL", "http://127.0.0.1:8765")


def _result(res):  # type: ignore[no-untyped-def]
    if res.is_error:
        text = res.content[0].text if res.content else ""
        start = text.find("{")
        raise SystemExit(f"tool error: {text[start:] if start >= 0 else text}")
    return res.structured_content or json.loads(res.content[0].text)


async def main(capability: str, tool: str, args: dict) -> None:  # type: ignore[type-arg]
    key = os.environ.get(f"LOCAL_OPS_KEY_{capability.upper()}_DEFAULT") or os.environ.get("LOCAL_OPS_KEY")
    if not key:
        raise SystemExit("set LOCAL_OPS_KEY_<CAPABILITY>_DEFAULT (see local-config/keys.env)")
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=httpx2.Timeout(30, read=120))
    async with Client(streamable_http_client(f"{BASE}/mcp/{capability}/", http_client=http)) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
        print("tools:", ", ".join(tools))
        sub = _result(await client.call_tool(tool, args))
        print("submitted:", json.dumps(sub, indent=2))
        if "request_id" not in sub:
            return
        rid = sub["request_id"]
        while True:
            st = _result(await client.call_tool("request_status", {"request_id": rid}))
            print(f"status: execution={st['execution_status']} response={st['response_status']} (review: {st['review_url']})")
            if st["response_status"] in ("released", "withheld") or st["execution_status"] in ("rejected", "expired", "cancelled"):
                break
            await asyncio.sleep(st.get("poll_after_ms", 1000) / 1000)
        if st["response_status"] == "released":
            res = _result(await client.call_tool("request_result", {"request_id": rid, "limit": 20}))
            print(json.dumps(res, indent=2)[:4000])


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}))
