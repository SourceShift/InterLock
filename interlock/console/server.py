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
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

import interlock

#: The only hosts the console will ever answer for, or bind to.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

_JSON_HEADERS = (
    ("Content-Type", "application/json; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
)

#: Every HTML response - the bundle's ``index.html`` and the not-built page
#: alike - carries these (F7): a frame-busting header and a CSP that keeps
#: the page from loading anything off-origin.
_HTML_SECURITY_HEADERS = (
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'self'"),
)

#: The page served for ``GET /`` when the static directory the CLI was given
#: does not exist (F8): the bundle was never built, so this names the command
#: that builds it rather than a bare 404.
_NOT_BUILT_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>interlock console</title></head>
<body>
<h1>The console's web bundle is not built</h1>
<p>Run <code>npm --prefix web run build</code>, then restart the console.</p>
</body>
</html>
""".encode("utf-8")

#: A POST body larger than this is refused outright (F14); above this size it
#: is not worth reading off the socket just to reject it.
MAX_BODY_BYTES = 1024 * 1024


class ApiError(Exception):
    """One ``/api/`` failure: an HTTP status, an error ``code``, and a
    ``message`` - the shape every ``/api/`` error answers with (F13)."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def body(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message}}


def read_json_body(handler: "ConsoleRequestHandler") -> Dict[str, Any]:
    """The one shared body reader every POST route uses (A2).

    A declared ``Content-Length`` above :data:`MAX_BODY_BYTES` is refused
    before any of the body is read off the socket (F14); a ``Content-Type``
    other than ``application/json`` is refused next; only then is the body
    read and parsed, and it must decode to a JSON object.
    """
    try:
        length = int(handler.headers.get("Content-Length", "0") or "0")
    except ValueError:
        length = 0
    if length > MAX_BODY_BYTES:
        raise ApiError(
            413, "payload_too_large", "body exceeds {} bytes".format(MAX_BODY_BYTES)
        )
    content_type = handler.headers.get("Content-Type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise ApiError(
            415, "unsupported_media_type", "Content-Type must be application/json"
        )
    raw = handler.rfile.read(length) if length > 0 else b""
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "bad_json", "body is not valid JSON")
    if not isinstance(body, dict):
        raise ApiError(400, "bad_json", "body must be a JSON object")
    return body


#: Extra keys a feature module contributes to ``/api/health`` (F6): each is
#: called with the request handler and returns the keys it owns, merged into
#: the base body. A contributor only ever adds keys here - it never replaces
#: ``ROUTES["/api/health"]`` itself.
HealthContributor = Callable[["ConsoleRequestHandler"], Dict[str, Any]]
HEALTH_CONTRIBUTORS: List[HealthContributor] = []


def _health(handler: "ConsoleRequestHandler") -> Tuple[int, dict]:
    body: Dict[str, Any] = {"status": "ok", "version": interlock.__version__}
    for contributor in HEALTH_CONTRIBUTORS:
        body.update(contributor(handler))
    return 200, body


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


def _status_code_name(code: int) -> str:
    """A snake_case slug for ``code``, for a JSON error the standard library
    raised itself (F13) - ``not_implemented`` for 501, and so on."""
    try:
        phrase = HTTPStatus(code).phrase
    except ValueError:
        return "http_error"
    return phrase.lower().replace(" ", "_").replace("-", "_")


#: The ways a client shows it has gone away mid-request. Nothing can be sent
#: back once one of these is raised, so they close quietly rather than log.
_CLIENT_GONE = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)

_INTERNAL_ERROR = {
    "error": {"code": "internal_error", "message": "an unexpected error occurred"}
}


class ConsoleRequestHandler(BaseHTTPRequestHandler):
    """One request: check the Host, then route to the API or the static tree."""

    server_version = "interlock-console/1"

    #: The trailing path segment for a :data:`PREFIX_ROUTES` match, set by
    #: :meth:`_handle_api` before it calls the handler.
    path_tail: str = ""

    #: The status code of this request's response, recorded by
    #: :meth:`send_response` for the access log line :meth:`_dispatch` writes
    #: once the response is sent.
    _status_code: int = 0

    #: When this request started, recorded by :meth:`handle_one_request`
    #: before the base class even reads the request line - so a timestamp is
    #: available for :meth:`send_error` too, which the standard library calls
    #: for a malformed request line/version/headers or an unknown method,
    #: entirely bypassing :meth:`_dispatch` (F5 covers every request, not
    #: only the ones that reach a route).
    _request_start: float = 0.0

    #: Whether a status line has been queued for this request. Once it has, a
    #: second response cannot be started, so an exception can only close.
    _response_started: bool = False

    def handle_one_request(self) -> None:
        self._request_start = time.monotonic()
        self._response_started = False
        super().handle_one_request()

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        # The base class's default access line carries the full request line
        # (query string and all); F5 allows only method/path/status/duration
        # on stderr, so that line is silenced and _log_access below is the
        # only access logging this handler does.
        pass

    def send_response(self, code: int, message: Optional[str] = None) -> None:
        self._status_code = code
        self._response_started = True
        super().send_response(code, message)

    def send_error(
        self, code: int, message: Optional[str] = None, explain: Optional[str] = None
    ) -> None:
        # A standard-library-raised error (501 unknown method, 400 malformed
        # request line, ...) answers with the same JSON error shape as every
        # other /api/ error (F13), not the base class's HTML page.
        try:
            short_message, _long_message = self.responses[code]
        except KeyError:
            short_message = "???"
        if message is None:
            message = short_message
        body = json.dumps(
            {"error": {"code": _status_code_name(code), "message": message}}
        ).encode("utf-8")
        self.send_response(code, message)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)
        # parse_request rejects a request (bad request line/version, headers
        # too large, ...) before self.path - sometimes before self.command -
        # is ever set, and returns straight to handle_one_request without
        # calling a do_* method, so _dispatch's own logging never runs for
        # these; log the one F5 line here instead.
        raw_path = getattr(self, "path", None)
        self._log_access(urlsplit(raw_path).path if raw_path else "-")

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
        path = urlsplit(self.path).path
        try:
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
            if path.startswith("/api/"):
                self._handle_api(path)
            else:
                self._handle_static(path)
        except _CLIENT_GONE:
            # The client hung up mid-response: there is nobody left to answer.
            self.close_connection = True
        except Exception:
            self._fail_closed()
        finally:
            self._log_access(path)

    def _fail_closed(self) -> None:
        """The one exception boundary for every route, API and static alike.

        An unexpected exception never drops the connection while a reply is
        still possible (F13): it answers 500 internal_error in the JSON error
        shape, naming nothing from the exception, which can quote request data.
        Once the status line is out a second response cannot start, so the only
        honest move left is to close. Either way the request still gets its one
        access line from _dispatch and never a traceback (F5).
        """
        self.close_connection = True
        if self._response_started:
            return
        try:
            self._send_json(500, _INTERNAL_ERROR)
        except _CLIENT_GONE:
            pass

    def _log_access(self, path: str) -> None:
        duration_ms = (time.monotonic() - self._request_start) * 1000
        sys.stderr.write(
            "{} {} {} {:.3f} ms\n".format(
                self.command or "-", path, self._status_code, duration_ms
            )
        )
        sys.stderr.flush()

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
        # An exception here is answered by _dispatch's boundary, the same one
        # that covers static paths.
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
        if relative == "index.html" and not root.is_dir():
            self._send_html(200, _NOT_BUILT_HTML)
            return
        try:
            target = (root / relative).resolve()
            servable = target.is_relative_to(root) and target.is_file()
        except (OSError, ValueError):
            # A segment the filesystem itself rejects - an embedded null
            # byte, a name over NAME_MAX - raises out of resolve()/is_file()
            # instead of just failing is_relative_to; treated the same as
            # any other unservable path (F5: one access line and no
            # traceback, not a dropped connection).
            servable = False
        if not servable:
            self._send_plain(404, b"not found")
            return
        content_type, _ = mimetypes.guess_type(str(target))
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        if (content_type or "").startswith("text/html"):
            for name, value in _HTML_SECURITY_HEADERS:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        # Built assets carry a content hash in their name and never change;
        # the page that names them must be re-checked, or an upgraded console
        # keeps serving the old app to an open browser.
        immutable = relative.startswith("assets/")
        self.send_header("Cache-Control", "public, max-age=31536000, immutable" if immutable else "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_html(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for name, value in _HTML_SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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
    #: socketserver's default listen backlog is 5: a burst of connections (a
    #: page opening its streams, several tabs at once) overflows it and the
    #: kernel makes the extra clients retry a second later.
    request_queue_size = 64

    def __init__(
        self,
        address: Tuple[str, int],
        static_root: Path,
        *,
        receipts_path: Optional[str] = None,
        receipts_key: Optional[bytes] = None,
        receipts_head: Optional[str] = None,
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
        #: The mac the receipt log is expected to end at (``--receipts-head``),
        #: or None. ``audit._handle_verify`` passes it to ``verify_file`` so a
        #: rollback to a shorter, otherwise valid log is reported broken.
        self.receipts_head = receipts_head
        #: Guards ``_open_streams`` (F16): the receipt streams this server
        #: is currently answering, so the cap is per server instance rather
        #: than process-wide - two ``ConsoleServer``s in one process (as in
        #: the test suite) must not share one count. Read and updated by
        #: ``interlock.console.audit``.
        self._stream_lock = threading.Lock()
        self._open_streams = 0
        super().__init__(address, ConsoleRequestHandler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Replace socketserver's traceback with at most one line.

        An exception only reaches here from outside _dispatch's boundary: a
        client hanging up while its request line was read or during the final
        flush. A client that went away is not an error worth a line; anything
        else gets one line naming the exception type, never its message, which
        can quote request data.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, _CLIENT_GONE):
            return
        sys.stderr.write(
            "interlock-console: {} while handling a request\n".format(type(exc).__name__)
        )
        sys.stderr.flush()
