"""A framework-free ASGI app exposing the plane's liveness and readiness.

Exactly two routes exist in this skeleton: ``GET /healthz`` (the process is
alive) and ``GET /readyz`` (a database ping succeeds). Everything else is a
JSON 404, and a known path with any other method is a 405 with ``allow: GET``.
Every response carries ``x-request-id`` and ``content-type: application/json``
and is sent as one ``http.response.start`` plus one body event.

There is no third-party import here. The module-level :data:`app` is built with
the default (empty) config and therefore answers ``/readyz`` with 503 until a
DSN is configured; it deliberately does not call ``CloudConfig.validate()`` at
import time, because importing the app must work on a bare interpreter.

The body reader is here for the routes that follow: it reads at most 64 KiB and
:class:`PayloadTooLarge` maps to ``413 payload_too_large``.
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from . import db
from .config import CloudConfig

#: Refuse a request body larger than this before reading a byte of it.
MAX_BODY_BYTES = 64 * 1024

#: An inbound request id is echoed only when it looks like one we would mint.
#: ``fullmatch`` (rather than a trailing ``$``) matters: ``$`` also matches
#: before a final newline, which would echo a header-injection payload.
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")

JSON_HEADERS = ((b"content-type", b"application/json"),)

Handler = Callable[[], Awaitable[Tuple[int, Dict[str, Any]]]]


class PayloadTooLarge(Exception):
    """A request body exceeded :data:`MAX_BODY_BYTES`."""


def _header_map(headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    """Lowercase header names, first value wins (ASGI sends bytes)."""
    out: Dict[str, str] = {}
    for name, value in headers:
        key = name.decode("latin-1").lower()
        if key not in out:
            out[key] = value.decode("latin-1")
    return out


def request_id_for(headers: Iterable[Tuple[bytes, bytes]]) -> str:
    """Echo a well-formed inbound id, else mint 16 hex characters."""
    inbound = _header_map(headers).get("x-request-id")
    if inbound is not None and REQUEST_ID_PATTERN.fullmatch(inbound):
        return inbound
    return secrets.token_hex(8)


async def read_body(receive: Callable[[], Any], limit: int = MAX_BODY_BYTES) -> bytes:
    """Read one request body, refusing anything larger than ``limit``."""
    chunks: List[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            break
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > limit:
            raise PayloadTooLarge("request body exceeds {} bytes".format(limit))
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


class CloudApp:
    """The ASGI callable: a route table plus the shared response envelope."""

    def __init__(self, config: Optional[CloudConfig] = None,
                 ping: Callable[[str], bool] = db.ping) -> None:
        self.config = config or CloudConfig()
        self._ping = ping
        self.routes: Dict[str, Dict[str, Handler]] = {
            "/healthz": {"GET": self._healthz},
            "/readyz": {"GET": self._readyz},
        }

    # -- routes ---------------------------------------------------------
    async def _healthz(self) -> Tuple[int, Dict[str, Any]]:
        return 200, {"status": "ok", "service": "interlock-cloud"}

    async def _readyz(self) -> Tuple[int, Dict[str, Any]]:
        # The driver is blocking, so the ping runs in a worker thread: an
        # unreachable database must not stall the event loop and every other
        # request with it.
        if self.config.dsn and await asyncio.to_thread(self._ping, self.config.dsn):
            return 200, {"status": "ready"}
        return 503, {"status": "unavailable"}

    # -- ASGI -----------------------------------------------------------
    async def __call__(self, scope: Dict[str, Any], receive: Callable[[], Any],
                       send: Callable[[Dict[str, Any]], Any]) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self._lifespan_session(receive, send)
            return
        if kind != "http":
            return

        headers = scope.get("headers") or []
        request_id = request_id_for(headers)
        header_map = _header_map(headers)

        declared = header_map.get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = None
            if size is not None and size > MAX_BODY_BYTES:
                await self._respond(send, 413, {
                    "error": {"code": "payload_too_large",
                              "message": "request body exceeds {} bytes".format(
                                  MAX_BODY_BYTES)},
                }, request_id)
                return

        path = scope.get("path") or "/"
        method = str(scope.get("method") or "GET").upper()
        route = self.routes.get(path)
        if route is None:
            await self._respond(send, 404, {
                "error": {"code": "not_found", "message": "no such route"},
            }, request_id)
            return
        handler = route.get(method)
        if handler is None:
            await self._respond(send, 405, {
                "error": {"code": "method_not_allowed",
                          "message": "method not allowed"},
            }, request_id, {"allow": ", ".join(sorted(route))})
            return

        status, payload = await handler()
        await self._respond(send, status, payload, request_id)

    async def _respond(self, send: Callable[[Dict[str, Any]], Any], status: int,
                       payload: Dict[str, Any], request_id: str,
                       extra: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = list(JSON_HEADERS)
        headers.append((b"x-request-id", request_id.encode("latin-1")))
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        for name, value in (extra or {}).items():
            headers.append((name.encode("latin-1"), value.encode("latin-1")))
        await send({"type": "http.response.start", "status": status,
                    "headers": headers})
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})

    async def _lifespan_session(self, receive: Callable[[], Any],
                                send: Callable[[Dict[str, Any]], Any]) -> None:
        while True:
            message = await receive()
            kind = message.get("type")
            if kind == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif kind == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


app = CloudApp()
