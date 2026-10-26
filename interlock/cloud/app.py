"""A framework-free ASGI app for the cloud control plane.

C0's two routes are still exactly ``GET /healthz`` and ``GET /readyz`` with
their original bodies, envelope, ``x-request-id`` and one-start/one-body shape.
C1 extends the same route table with path parameters and a request object, so
authentication, authorization and org-scoped lookup happen in one place.
There is no third-party import here.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Union

from . import db
from .api.auth_routes import register as register_auth_routes
from .api.grant_routes import register as register_grant_routes
from .api.host_routes import register as register_host_routes
from .api.review_routes import register as register_review_routes
from .ui import register as register_ui_routes
from .crypto import parse_kek
from .db import CloudDependencyMissing
from .grants import (
    approval_public_key_hex as _approval_public_key_hex,
    read_seed_file,
)
from .auth import rbac
from .auth.agent import (
    AgentAuthError,
    AgentRevoked,
    agent_authenticate,
    require_scope,
)
from .auth.oidc import OIDCClient
from .auth.sessions import SESSION_COOKIE, SessionManager, Unauthenticated
from .auth.stepup import StepUpError
from .config import CloudConfig
from .http import (
    ApiError,
    PayloadTooLarge,
    Request,
    Response,
    error_response,
    header_map,
    parse_cookies,
    parse_query,
    read_body,
)
from .log import log_event
from .store import CrossOrgAccess, MemoryStore, PostgresStore

#: Refuse a request body larger than this before reading a byte of it.
MAX_BODY_BYTES = 64 * 1024

#: An inbound request id is echoed only when it looks like one we would mint.
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")

JSON_HEADERS = ((b"content-type", b"application/json"),)

RouteResult = Union[Tuple[int, Dict[str, Any]], Response]
Handler = Callable[[Request], Awaitable[RouteResult]]

_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _header_map(headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    """Backwards-compatible alias for :func:`interlock.cloud.http.header_map`."""
    return header_map(headers)


def request_id_for(headers: Iterable[Tuple[bytes, bytes]]) -> str:
    """Echo a well-formed inbound id, else mint 16 hex characters."""
    inbound = _header_map(headers).get("x-request-id")
    if inbound is not None and REQUEST_ID_PATTERN.fullmatch(inbound):
        return inbound
    return secrets.token_hex(8)


def compile_pattern(template: str) -> "re.Pattern[str]":
    """Compile ``/v1/members/{id}`` to a named-group regular expression."""
    parts: List[str] = []
    position = 0
    for match in _PARAM.finditer(template):
        parts.append(re.escape(template[position:match.start()]))
        parts.append(r"(?P<{}>[^/]+)".format(match.group(1)))
        position = match.end()
    parts.append(re.escape(template[position:]))
    return re.compile("^" + "".join(parts) + "$")


class CloudApp:
    """The ASGI callable: a route table plus the shared response envelope."""

    def __init__(self, config: Optional[CloudConfig] = None,
                 ping: Callable[[str], bool] = db.ping,
                 store: Any = None, oidc: Any = None,
                 clock: Callable[[], float] = time.time,
                 approval_seed: Optional[bytes] = None) -> None:
        self.config = config or CloudConfig()
        self._ping = ping
        self._clock = clock
        #: C3 signing material, loaded lazily. A test may inject the seed
        #: directly; production reads the operator's 0600 key file.
        self._approval_seed_override = approval_seed
        self._approval_seed: Optional[bytes] = None
        self._preview_kek: Optional[bytes] = None
        if store is None:
            store = (PostgresStore(self.config.dsn) if self.config.dsn
                     else MemoryStore())
        self.store = store
        secret = (self.config.session_secret
                  or "interlock-development-session-secret")
        self.sessions = SessionManager(
            self.store, secret,
            idle=self.config.session_idle_seconds,
            absolute=self.config.session_absolute_seconds,
            clock=clock,
        )
        self.oidc = oidc
        self._oidc_client: Any = None
        self.routes: Dict[str, Dict[str, Handler]] = {
            "/healthz": {"GET": self._healthz},
            "/readyz": {"GET": self._readyz},
        }
        #: ``(compiled, template, {method: handler})`` in registration order.
        self._patterns: List[Tuple[Any, str, Dict[str, Handler]]] = []
        register_auth_routes(self)
        register_host_routes(self)
        register_review_routes(self)
        register_grant_routes(self)
        register_ui_routes(self)

    # -- C3 signing and encryption material -----------------------------
    def approval_seed(self) -> bytes:
        """The org approval seed, loaded once from the operator's key file."""
        if self._approval_seed is None:
            if self._approval_seed_override is not None:
                self._approval_seed = bytes(self._approval_seed_override)
            elif self.config.approval_key_file:
                self._approval_seed = read_seed_file(self.config.approval_key_file)
            else:
                raise CloudDependencyMissing(
                    "IL_CLOUD_APPROVAL_KEY_FILE is not configured")
        return self._approval_seed

    def approval_public_key_hex(self) -> str:
        """The public key an enrolling host pins; empty when unconfigured."""
        try:
            return _approval_public_key_hex(self.approval_seed())
        except Exception:
            return ""

    def preview_kek(self) -> bytes:
        if self._preview_kek is None:
            if not self.config.preview_kek:
                raise CloudDependencyMissing(
                    "IL_CLOUD_PREVIEW_KEK is not configured")
            self._preview_kek = parse_kek(self.config.preview_kek)
        return self._preview_kek

    # -- route registration --------------------------------------------
    def add_route(self, path: str, method: str, handler: Handler) -> None:
        self.routes.setdefault(path, {})[method.upper()] = handler

    def add_pattern(self, template: str, method: str, handler: Handler) -> None:
        for _compiled, existing, methods in self._patterns:
            if existing == template:
                methods[method.upper()] = handler
                return
        self._patterns.append(
            (compile_pattern(template), template, {method.upper(): handler})
        )

    def oidc_client(self) -> Any:
        """The injected client, or one built from configuration."""
        if self.oidc is not None:
            return self.oidc
        if self._oidc_client is None:
            redirect = self.config.oidc_redirect_uri
            if not redirect and self.config.public_url:
                redirect = (self.config.public_url.rstrip("/")
                            + "/v1/auth/callback")
            self._oidc_client = OIDCClient(
                self.config.oidc_issuer, self.config.oidc_client_id,
                self.config.oidc_client_secret, redirect, clock=self._clock,
            )
        return self._oidc_client

    # -- routes ---------------------------------------------------------
    async def _healthz(self, request: Optional[Request] = None) -> Tuple[int, Dict[str, Any]]:
        return 200, {"status": "ok", "service": "interlock-cloud"}

    async def _readyz(self, request: Optional[Request] = None) -> Tuple[int, Dict[str, Any]]:
        # The driver is blocking, so the ping runs in a worker thread: an
        # unreachable database must not stall the event loop and every other
        # request with it.
        if self.config.dsn and await asyncio.to_thread(self._ping, self.config.dsn):
            return 200, {"status": "ready"}
        return 503, {"status": "unavailable"}

    # -- dispatch -------------------------------------------------------
    def _match(self, path: str) -> Tuple[Optional[Dict[str, Handler]],
                                         Dict[str, str], Optional[str]]:
        exact = self.routes.get(path)
        if exact is not None:
            return exact, {}, path
        for compiled, template, methods in self._patterns:
            match = compiled.match(path)
            if match is not None:
                return methods, match.groupdict(), template
        return None, {}, None

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
        header_map_local = _header_map(headers)

        declared = header_map_local.get("content-length")
        if declared is not None:
            try:
                size: Optional[int] = int(declared)
            except ValueError:
                size = None
            if size is not None and size > MAX_BODY_BYTES:
                await self._send(send, error_response(
                    413, "payload_too_large",
                    "request body exceeds {} bytes".format(MAX_BODY_BYTES),
                ), request_id)
                return

        path = scope.get("path") or "/"
        method = str(scope.get("method") or "GET").upper()
        route, params, _template = self._match(path)
        if route is None:
            await self._send(send, error_response(
                404, "not_found", "no such route"), request_id)
            return
        handler = route.get(method)
        if handler is None:
            await self._send(send, error_response(
                405, "method_not_allowed", "method not allowed",
                [("allow", ", ".join(sorted(route)))]), request_id)
            return

        try:
            body = await read_body(receive, MAX_BODY_BYTES)
        except PayloadTooLarge as exc:
            await self._send(send, error_response(
                413, "payload_too_large", str(exc)), request_id)
            return

        client = scope.get("client") or ("", 0)
        try:
            query = parse_query(scope.get("query_string") or b"")
        except ApiError as exc:
            await self._send(send, error_response(
                exc.status, exc.code, exc.message), request_id)
            return
        request = Request(
            method=method,
            path=path,
            params=params,
            headers=header_map_local,
            query=query,
            body=body,
            request_id=request_id,
            cookies=parse_cookies(header_map_local.get("cookie")),
            client_ip=str(client[0]) if client and client[0] else "",
        )

        try:
            await self._authenticate(request)
            result = await handler(request)
        except ApiError as exc:
            result = error_response(exc.status, exc.code, exc.message)
        except (AgentAuthError, AgentRevoked) as exc:
            result = error_response(exc.status, exc.code, str(exc))
        except Unauthenticated as exc:
            result = error_response(401, exc.code, str(exc))
        except rbac.Forbidden as exc:
            result = error_response(403, exc.code, str(exc))
        except StepUpError as exc:
            result = error_response(403, exc.code, exc.message)
        except CrossOrgAccess:
            result = error_response(404, "not_found", "no such resource")
        except Exception as exc:  # pragma: no cover - defensive
            # Log the class only: an exception message can carry tenant data.
            log_event("error", "unhandled_exception", request_id=request_id,
                      error=type(exc).__name__)
            result = error_response(500, "internal_error", "internal error")

        await self._send(send, result, request_id)

    async def _authenticate(self, request: Request) -> None:
        """Authenticate, authorize the route, then enforce CSRF (FR-050).

        A bearer agent key is branched on *before* the session/CSRF path: an
        agent key has no cookie and no CSRF token, and it may only reach the
        literal routes in ``rbac.AGENT_ROUTES``. Any other route with a bearer
        is ``403 forbidden``; the session path stays byte-identical for human
        requests.
        """
        if rbac.is_public(request.method, request.path):
            return
        authorization = request.header("authorization") or ""
        if authorization.lower().startswith("bearer "):
            if rbac.agent_route(request.method, request.path) is None:
                raise rbac.Forbidden(
                    "agent keys may not call {}".format(request.path)
                )
            context = agent_authenticate(self.store, request.headers)
            require_scope(context, rbac.required_agent_scope(
                request.method, request.path
            ))
            org = self.store.org_by_id(context.org_id)
            if org is None:
                raise Unauthenticated("authentication required")
            request.key = context
            request.org = org
            return
        raw = request.cookies.get(SESSION_COOKIE)
        if not raw:
            raise Unauthenticated("authentication required")
        try:
            session, user = self.sessions.resolve_cookie_session(raw)
        except Unauthenticated:
            raise
        org = self.store.org_by_id(session.org_id)
        if org is None:
            raise Unauthenticated("authentication required")
        request.session = session
        request.user = user
        request.org = org

        rbac.authorize(user.role, request.method, request.path)

        if request.method not in ("GET", "HEAD", "OPTIONS"):
            provided = request.header("x-csrf-token") or _form_csrf(request)
            if not self.sessions.check_csrf(session, provided):
                raise ApiError(403, "csrf", "CSRF token is missing or invalid")

    # -- responses ------------------------------------------------------
    async def _send(self, send: Callable[[Dict[str, Any]], Any],
                    result: RouteResult, request_id: str) -> None:
        if isinstance(result, Response):
            body = result.body
            content_type = result.content_type
            extra = result.headers
            status = result.status
        else:
            status, payload = result
            body = json_module_dumps(payload)
            content_type = "application/json"
            extra = []
        await self._respond(send, status, body, content_type, request_id, extra)

    async def _respond(self, send: Callable[[Dict[str, Any]], Any], status: int,
                       body: bytes, content_type: str, request_id: str,
                       extra: Optional[Iterable[Tuple[str, str]]] = None) -> None:
        headers = [(b"content-type", content_type.encode("latin-1"))]
        headers.append((b"x-request-id", request_id.encode("latin-1")))
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        for name, value in (extra or ()):
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


def _form_csrf(request: Request) -> Optional[str]:
    """Read the CSRF token from an HTML form body (the UI's forms post one).

    The JSON routes keep the header-only contract; the two server-rendered
    pages cannot set a header from a plain form, so the same token is accepted
    from a urlencoded body. The value is still checked by
    :meth:`SessionManager.check_csrf`, never trusted from the body alone.
    """
    content_type = (request.header("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded" or not request.body:
        return None
    from urllib.parse import parse_qs

    try:
        values = parse_qs(request.body.decode("utf-8"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        return None
    token = values.get("csrf")
    return token[0] if token else None


def json_module_dumps(payload: Any) -> bytes:
    """The one JSON encoder the envelope uses."""
    import json

    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


app = CloudApp()
