"""The console's HTTP server: routing, JSON helpers, static serving, the
error shape every endpoint shares.

Everything here is the Python standard library on purpose - no response goes
out, and no path is resolved, through any code this project does not own. Two
checks run ahead of routing, on every request, because both are about the
origin rather than about any one endpoint: the Host header (DNS-rebinding
defence) and, at the process level before a socket ever opens, the bound
host itself (``ConsoleServer`` refuses a non-loopback address the same way
:class:`interlock.sidecar.server.SidecarServer` refuses an unsafe socket
directory - a boundary a class only documents until it also enforces it).
"""
from __future__ import annotations

import json
import mimetypes
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import unquote, urlsplit

import interlock

#: The only hosts the console will ever answer for, or bind to.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

_JSON_HEADERS = (
    ("Content-Type", "application/json; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
)


def _health(handler: "ConsoleRequestHandler") -> Tuple[int, dict]:
    return 200, {"status": "ok", "version": interlock.__version__}


#: A route handler answers with ``(status, body)`` for the common JSON case,
#: or ``None`` when it has already written its own response (a streaming
#: route, which keeps the connection open past one JSON body).
RouteHandler = Callable[["ConsoleRequestHandler"], Optional[Tuple[int, dict]]]

#: path -> {HTTP method: handler}. A later spec adds entries here; it never
#: edits :class:`ConsoleRequestHandler`.
ROUTES: Dict[str, Dict[str, RouteHandler]] = {
    "/api/health": {"GET": _health},
}

#: path prefix (ending in "/") -> {HTTP method: handler}, for a route with one
#: dynamic trailing segment. ``ConsoleRequestHandler.path_tail`` carries the
#: segment for the handler to read, so a feature module still never edits
#: :class:`ConsoleRequestHandler` to add one.
PREFIX_ROUTES: Dict[str, Dict[str, RouteHandler]] = {}


class ConsoleRequestHandler(BaseHTTPRequestHandler):
    """One request: check the Host, then route to the API or the static tree."""

    server_version = "interlock-console/1"

    #: The trailing path segment for a :data:`PREFIX_ROUTES` match, set by
    #: :meth:`_handle_api` before it calls the handler.
    path_tail: str = ""

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        # Access logging is out of scope for this deliverable; silence the
        # base class's default stderr line so test output stays readable.
        pass

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        if not self._host_is_allowed():
            self._send_json(
                403,
                {
                    "error": {
                        "code": "forbidden_host",
                        "message": "the Host header does not name a loopback address for this server",
                    }
                },
            )
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            self._handle_api(path)
        else:
            self._handle_static(path)

    def _host_is_allowed(self) -> bool:
        port = self.server.server_port  # type: ignore[attr-defined]
        allowed = {
            "127.0.0.1:{}".format(port),
            "localhost:{}".format(port),
            "[::1]:{}".format(port),
        }
        return self.headers.get("Host", "") in allowed

    def _handle_api(self, path: str) -> None:
        routes = ROUTES.get(path)
        self.path_tail = ""
        if routes is None:
            for prefix, prefix_routes in PREFIX_ROUTES.items():
                if path.startswith(prefix):
                    routes = prefix_routes
                    self.path_tail = path[len(prefix):]
                    break
        if routes is None:
            self._send_json(
                404, {"error": {"code": "not_found", "message": "no such API path"}}
            )
            return
        handler = routes.get(self.command)
        if handler is None:
            self._send_json(
                405,
                {
                    "error": {
                        "code": "method_not_allowed",
                        "message": "{} is not supported for this path".format(self.command),
                    }
                },
            )
            return
        result = handler(self)
        if result is None:
            # The handler already wrote its own response (a stream kept the
            # connection open past one JSON body); there is nothing left to send.
            return
        status, body = result
        self._send_json(status, body)

    def _handle_static(self, path: str) -> None:
        static_root: Path = self.server.static_root  # type: ignore[attr-defined]
        root = static_root.resolve()
        relative = unquote(path).lstrip("/") or "index.html"
        target = (root / relative).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            self._send_plain(404, b"not found")
            return
        content_type, _ = mimetypes.guess_type(str(target))
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        for name, value in _JSON_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_plain(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class ConsoleServer(ThreadingHTTPServer):
    """A threaded HTTP server bound to one loopback address.

    The loopback check lives here, not only in the CLI: constructing this
    class directly with a non-loopback host must refuse just as surely as
    running the CLI with one does, or the constraint is only enforced by
    whichever caller happens to remember to check first.
    """

    daemon_threads = True

    def __init__(
        self,
        address: Tuple[str, int],
        static_root: Path,
        *,
        receipts_path: Optional[str] = None,
        receipts_key: Optional[bytes] = None,
    ) -> None:
        host = address[0]
        if host not in LOOPBACK_HOSTS:
            raise ValueError(
                "ConsoleServer refuses to bind non-loopback host {!r}".format(host)
            )
        self.address_family = socket.AF_INET6 if host == "::1" else socket.AF_INET
        self.static_root = static_root
        #: Path to the receipt log, and its MAC key, fixed at startup
        #: (spec 04-audit-log F1); None when the console was started without
        #: ``--receipts``/``--key-file``. Read by ``interlock.console.audit``.
        self.receipts_path = receipts_path
        self.receipts_key = receipts_key
        super().__init__(address, ConsoleRequestHandler)
