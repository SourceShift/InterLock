"""HTTP primitives shared by the cloud plane's routes.

The request is parsed once into :class:`Request`; handlers never touch ASGI
messages. Responses are :class:`Response` objects (or the C0 ``(status,
payload)`` pair) so a redirect can carry ``location`` and ``set-cookie`` while
JSON errors keep the C0 envelope.

No third-party import here: this module must import under ``python3 -I -S``.
"""
from __future__ import annotations

import html as _html
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs

#: A JSON body cap for admin routes. C0's app-level cap stays 64 KiB; this is
#: the bound the kickoff gives ``read_json`` for callers that read directly.
MAX_JSON_BYTES = 262144

#: At most this many query parameters are considered; more is a bad request.
MAX_QUERY_PARAMS = 32

CSP = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")

SESSION_COOKIE = "__Host-il_session"
CSRF_COOKIE = "il_csrf"
SESSION_COOKIE_PATH = "/"

JSON_HEADERS = (("content-type", "application/json"),)


class ApiError(Exception):
    """An error that maps directly onto the spec's status/code table."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class PayloadTooLarge(Exception):
    """A request body exceeded the configured cap."""


def header_map(headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    """Lowercase header names; first value wins (ASGI sends bytes)."""
    out: Dict[str, str] = {}
    for name, value in headers:
        key = name.decode("latin-1").lower()
        if key not in out:
            out[key] = value.decode("latin-1")
    return out


def parse_cookies(cookie_header: Optional[str]) -> Dict[str, str]:
    """Parse a ``cookie`` header, first value wins for duplicated names."""
    out: Dict[str, str] = {}
    if not cookie_header:
        return out
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name and name not in out:
            out[name] = value.strip()
    return out


def parse_query(query_string: bytes) -> Dict[str, List[str]]:
    """Parse the query string, keeping blanks and capping key count."""
    if not query_string:
        return {}
    try:
        text = query_string.decode("latin-1")
    except Exception:
        raise ApiError(422, "invalid_request", "malformed query string")
    parsed = parse_qs(text, keep_blank_values=True)
    if len(parsed) > MAX_QUERY_PARAMS:
        raise ApiError(422, "invalid_request", "too many query parameters")
    return parsed


def query_one(query: Mapping[str, List[str]], name: str) -> Optional[str]:
    values = query.get(name)
    return values[0] if values else None


@dataclass
class Request:
    """Everything a route may inspect, with no raw token material added."""

    method: str
    path: str
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, List[str]] = field(default_factory=dict)
    body: bytes = b""
    request_id: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    client_ip: str = ""
    # Filled in by :class:`interlock.cloud.app.CloudApp` after authentication.
    session: Any = None
    user: Any = None
    org: Any = None
    #: The agent :class:`~interlock.cloud.auth.agent.KeyContext`, when the
    #: request authenticated with a bearer agent key rather than a session.
    key: Any = None

    def cookie(self, name: str) -> Optional[str]:
        return self.cookies.get(name)

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def query_one(self, name: str) -> Optional[str]:
        return query_one(self.query, name)


@dataclass
class Response:
    """A rendered response; the ASGI layer sends it as one start + one body."""

    status: int
    body: bytes = b""
    headers: List[Tuple[str, str]] = field(default_factory=list)
    content_type: str = "application/json"

    def with_header(self, name: str, value: str) -> "Response":
        self.headers.append((name, value))
        return self

    def add_cookie(self, cookie: str) -> "Response":
        self.headers.append(("set-cookie", cookie))
        return self


def json_response(status: int, payload: Any,
                  headers: Optional[Iterable[Tuple[str, str]]] = None) -> Response:
    return Response(
        status=status,
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=list(headers or ()),
        content_type="application/json",
    )


def error_response(status: int, code: str, message: str,
                   headers: Optional[Iterable[Tuple[str, str]]] = None) -> Response:
    return json_response(status, {"error": {"code": code, "message": message}},
                         headers)


def html_response(status: int, text: str,
                  headers: Optional[Iterable[Tuple[str, str]]] = None) -> Response:
    out = [("content-security-policy", CSP)]
    out.extend(headers or ())
    return Response(status=status, body=text.encode("utf-8"), headers=out,
                    content_type="text/html; charset=utf-8")


def redirect_response(location: str,
                      headers: Optional[Iterable[Tuple[str, str]]] = None) -> Response:
    out = [("location", location)]
    out.extend(headers or ())
    return Response(status=302, body=b"", headers=out,
                    content_type="text/plain; charset=utf-8")


def escape(text: Any) -> str:
    """HTML-escape a value for the two server-rendered pages."""
    return _html.escape(str(text), quote=True)


# -- cookies ------------------------------------------------------------

def build_cookie(name: str, value: str, *, max_age: int,
                 path: str = SESSION_COOKIE_PATH, http_only: bool = True,
                 secure: bool = True, same_site: str = "Lax") -> str:
    """Build one ``Set-Cookie`` value with the attributes FR-049 requires.

    ``__Host-`` cookies must be ``Secure``, scoped to ``Path=/`` and carry no
    ``Domain``; the caller chooses the name, so the prefix contract is the
    caller's to keep.
    """
    parts = ["{}={}".format(name, value)]
    if secure:
        parts.append("Secure")
    parts.append("Path={}".format(path))
    if http_only:
        parts.append("HttpOnly")
    if same_site:
        parts.append("SameSite={}".format(same_site))
    parts.append("Max-Age={}".format(int(max_age)))
    return "; ".join(parts)


def clear_cookie(name: str, *, path: str = SESSION_COOKIE_PATH,
                 http_only: bool = True) -> str:
    return build_cookie(name, "", max_age=0, path=path, http_only=http_only)


def session_cookie(raw: str, max_age: int) -> str:
    return build_cookie(SESSION_COOKIE, raw, max_age=max_age)


def csrf_cookie(token: str, max_age: int) -> str:
    return build_cookie(CSRF_COOKIE, token, max_age=max_age, http_only=False)


# -- bodies -------------------------------------------------------------

async def read_body(receive: Any, limit: int = MAX_JSON_BYTES) -> bytes:
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
            raise PayloadTooLarge(
                "request body exceeds {} bytes".format(limit)
            )
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _is_json_content_type(headers: Mapping[str, str]) -> bool:
    raw = headers.get("content-type", "")
    return raw.split(";", 1)[0].strip().lower() == "application/json"


def parse_json_body(body: bytes, headers: Mapping[str, str],
                    allowed_fields: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Decode a JSON object body, enforcing the media type and fields."""
    if not _is_json_content_type(headers):
        raise ApiError(415, "unsupported_media_type",
                       "content-type must be application/json")
    try:
        parsed = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, ValueError):
        raise ApiError(422, "invalid_request", "malformed JSON body")
    if not isinstance(parsed, dict):
        raise ApiError(422, "invalid_request", "request body must be an object")
    if allowed_fields is not None:
        unknown = sorted(set(parsed) - set(allowed_fields))
        if unknown:
            raise ApiError(422, "invalid_request",
                           "unknown field: {}".format(unknown[0]))
    return parsed


async def read_json(scope: Mapping[str, Any], receive: Any,
                    max_bytes: int = MAX_JSON_BYTES,
                    allowed_fields: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Read and validate a JSON request body from raw ASGI messages."""
    headers = header_map(scope.get("headers") or ())
    if not _is_json_content_type(headers):
        raise ApiError(415, "unsupported_media_type",
                       "content-type must be application/json")
    try:
        body = await read_body(receive, max_bytes)
    except PayloadTooLarge as exc:
        raise ApiError(413, "payload_too_large", str(exc)) from None
    return parse_json_body(body, headers, allowed_fields)
