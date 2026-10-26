"""HTTP transports for the connector (FR-008, FR-009).

Two implementations share one tiny protocol: the real :class:`UrllibTransport`
and the deterministic :class:`FakeTransport` the tests and the live smoke use.
The transport moves bytes and reports the status; the *retry policy* lives in
:class:`interlock.cloud.connector.runner.Connector`, so a fake can exercise it
without sleeping.

``UrllibTransport`` refuses a non-TLS URL unless it is loopback, keeps TLS
verification on, follows no redirects (a redirect could downgrade or move the
credential to another origin) and caps a JSON response at 64 KiB.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlsplit

#: FR-009's response bound; anything larger is a broken or hostile plane.
MAX_RESPONSE_BYTES = 64 * 1024

LOOPBACK_HOSTS = frozenset(("127.0.0.1", "::1", "localhost"))

ResponseTuple = Tuple[int, Dict[str, str], bytes]


class TransportError(RuntimeError):
    """A request could not be completed (connection, TLS, timeout, size)."""


class Transport(Protocol):
    """The one method the connector needs from a transport."""

    def request(self, method: str, path: str, body: Optional[bytes] = None, *,
                headers: Optional[Mapping[str, str]] = None,
                timeout: float = 30) -> ResponseTuple:
        ...


def _check_url(url: str) -> None:
    parsed = urlsplit(url)
    if not parsed.hostname:
        raise TransportError("refusing a URL with no host")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS:
        return
    raise TransportError("refusing a non-TLS URL: {}".format(parsed.scheme or "?"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Returning ``None`` makes urllib surface the 3xx instead of following."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class UrllibTransport:
    """A stdlib transport: TLS on, redirects off, response size capped."""

    def __init__(self, base_url: str = "", *,
                 max_response_bytes: int = MAX_RESPONSE_BYTES,
                 timeout: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_response_bytes = int(max_response_bytes)
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _url(self, path: str) -> str:
        if path.startswith("https://") or path.startswith("http://"):
            url = path
        else:
            if not self.base_url:
                raise TransportError("no base URL configured")
            url = self.base_url + (path if path.startswith("/") else "/" + path)
        _check_url(url)
        return url

    def request(self, method: str, path: str, body: Optional[bytes] = None, *,
                headers: Optional[Mapping[str, str]] = None,
                timeout: float = 30) -> ResponseTuple:
        url = self._url(path)
        request = urllib.request.Request(
            url, data=body, method=method.upper(),
            headers={str(k): str(v) for k, v in (headers or {}).items()},
        )
        effective_timeout = self.timeout if timeout is None else timeout
        try:
            with self._opener.open(request, timeout=effective_timeout) as response:
                data = response.read(self.max_response_bytes + 1)
                if len(data) > self.max_response_bytes:
                    raise TransportError(
                        "response exceeds {} bytes".format(
                            self.max_response_bytes)
                    )
                return (int(response.status),
                        {k.lower(): v for k, v in response.headers.items()},
                        data)
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx is an answer, not a transport failure: the connector's
            # retry policy needs the status and Retry-After header.
            try:
                data = exc.read(self.max_response_bytes + 1)
            except Exception:
                data = b""
            if len(data) > self.max_response_bytes:
                data = data[: self.max_response_bytes]
            return (int(exc.code),
                    {k.lower(): v for k, v in (exc.headers or {}).items()},
                    data)
        except urllib.error.URLError as exc:
            raise TransportError(str(exc.reason)) from None
        except (OSError, ValueError) as exc:
            raise TransportError(str(exc)) from None


class FakeTransport:
    """Replay scripted responses; record every call.

    Each response is ``(status, headers, body)``; ``body`` may be ``str``.
    When the script is exhausted the transport answers ``(200, {}, b"{}")``,
    which the connector treats as an empty success - the live smoke relies on
    that. An entry that is an exception instance is raised instead, so a test
    can simulate a network failure.
    """

    def __init__(self, responses: Optional[Iterable[Any]] = None) -> None:
        self.responses: List[Any] = list(responses or [])
        self.calls: List[Tuple[str, str, Optional[bytes], Dict[str, str]]] = []

    def request(self, method: str, path: str, body: Optional[bytes] = None, *,
                headers: Optional[Mapping[str, str]] = None,
                timeout: float = 30) -> ResponseTuple:
        self.calls.append((method.upper(), path, body,
                           dict(headers or {})))
        if self.responses:
            item = self.responses.pop(0)
        else:
            return 200, {}, b"{}"
        if isinstance(item, BaseException):
            raise item
        status, response_headers, data = item
        if isinstance(data, str):
            data = data.encode("utf-8")
        return int(status), dict(response_headers or {}), bytes(data or b"")


__all__ = [
    "FakeTransport",
    "LOOPBACK_HOSTS",
    "MAX_RESPONSE_BYTES",
    "Transport",
    "TransportError",
    "UrllibTransport",
]
