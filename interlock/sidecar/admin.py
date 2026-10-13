"""A loopback-only admin endpoint for the sidecar: health, stats, metrics, config.

``interlock-sidecar --admin 127.0.0.1:19000`` serves:

==============  ===========================================================
``/healthz``    ``ok`` while the daemon runs
``/stats``      JSON: decisions by verdict, top policies, escalations,
                masked entities, dropped receipts, latency, uptime
``/metrics``    the same, in the Prometheus text format
``/config``     JSON: rule ids (never patterns), policy epoch, whether
                receipts and a fallback policy are configured
==============  ===========================================================

It binds loopback only (any other address is refused), answers only ``GET``,
checks the ``Host`` header against loopback names (so a web page can't reach
it through DNS rebinding) and sends no CORS headers. It carries no argument
values; still, treat its port as local-only.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Tuple

from .. import metrics

_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def parse_address(text: str) -> Tuple[str, int]:
    host, _, port = text.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host not in _LOOPBACK:
        raise ValueError("the admin endpoint binds loopback only, not {!r}".format(host))
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("admin address must look like 127.0.0.1:19000")
    return host, int(port)


def start(address: str, config: Callable[[], Dict[str, Any]]) -> ThreadingHTTPServer:
    """Serve the admin endpoint on a daemon thread; return the server."""
    host, port = parse_address(address)
    started = time.time()

    class Handler(BaseHTTPRequestHandler):
        server_version = "interlock-admin"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

        def _send(self, status: int, body: str, content_type: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            host_header = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            if host_header not in _LOOPBACK:
                self._send(403, "forbidden host\n", "text/plain")
                return
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send(200, "ok\n", "text/plain")
            elif path == "/stats":
                data = metrics.snapshot()
                data["uptime_seconds"] = round(time.time() - started, 1)
                self._send(200, json.dumps(data, indent=2) + "\n", "application/json")
            elif path == "/metrics":
                self._send(200, metrics.render_prometheus(), "text/plain; version=0.0.4")
            elif path == "/config":
                self._send(200, json.dumps(config(), indent=2) + "\n", "application/json")
            else:
                self._send(404, "not found\n", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            self._send(405, "read-only\n", "text/plain")

        do_PUT = do_DELETE = do_PATCH = do_POST

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="interlock-admin", daemon=True)
    thread.start()
    return server
