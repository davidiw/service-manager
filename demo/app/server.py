"""Tiny stdlib-only demo HTTP server for the disposable local-ops kind cluster.

Routes:
  GET /health          -> 200 {"status": "ok"}  (500 {"status": "failing"} when DEMO_FAIL_HEALTH=1)
  GET /version         -> 200 {"version": DEMO_VERSION, "build": DEMO_BUILD}
  GET /                -> small text banner
  GET /slow?seconds=N  -> sleeps N seconds (bounded to 30) then 200
  GET /crash           -> exits the process with code 1 (failure mode)

Every request is logged as one JSON line on stdout. If DEMO_CRASH_ON_START=1 the process logs a
fatal line and exits 1 after one second (used to build the deliberately broken image).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = os.environ.get("DEMO_VERSION", "0.0.0")
BUILD = os.environ.get("DEMO_BUILD", "unknown")
PORT = int(os.environ.get("DEMO_PORT", "8080"))
MAX_SLOW_SECONDS = 30


def log(event: str, **fields: object) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, "version": VERSION, **fields}
    sys.stdout.write(json.dumps(rec, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    server_version = "demo-app/" + VERSION

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - BaseHTTPRequestHandler signature
        return  # request logging is done as JSON in _send

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        log("request", method=self.command, path=self.path, status=status, client=self.client_address[0])

    def _json(self, status: int, payload: dict[str, object]) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        path = url.path
        if path == "/health":
            if os.environ.get("DEMO_FAIL_HEALTH") == "1":
                self._json(500, {"status": "failing"})
            else:
                self._json(200, {"status": "ok"})
        elif path == "/version":
            self._json(200, {"version": VERSION, "build": BUILD})
        elif path == "/":
            self._send(200, f"demo-app {VERSION} (build {BUILD})\nroutes: /health /version /slow?seconds=N /crash\n".encode(), "text/plain; charset=utf-8")
        elif path == "/slow":
            try:
                seconds = float(parse_qs(url.query).get("seconds", ["1"])[0])
            except ValueError:
                seconds = 1.0
            seconds = max(0.0, min(seconds, MAX_SLOW_SECONDS))
            time.sleep(seconds)
            self._json(200, {"status": "ok", "slept_seconds": seconds})
        elif path == "/crash":
            self._json(200, {"status": "crashing"})
            log("crash", reason="requested via /crash")
            threading.Thread(target=lambda: (time.sleep(0.2), os._exit(1)), daemon=True).start()
        else:
            self._json(404, {"error": "not found", "path": path})


def main() -> int:
    if os.environ.get("DEMO_CRASH_ON_START") == "1":
        log("startup", port=PORT, build=BUILD, mode="broken")
        time.sleep(1)
        sys.stdout.write("fatal: simulated startup failure (missing dependency DEMO_DB_URL)\n")
        sys.stdout.flush()
        return 1
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("startup", port=PORT, build=BUILD, mode="normal")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        log("shutdown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
