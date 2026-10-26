"""Agent-key authentication for host routes (FR-002, FR-006, FR-054).

An agent key is ``ilk_<8-hex-prefix>_<43-char secret>``. The prefix is the only
searchable part, so the plane looks the row up by prefix, then compares
SHA-256 of the presented key against the stored hash in constant time. The raw
key is never logged or stored.

The key does not carry its org: the fixed format rules that out, and
``agent_keys`` is protected by row-level security. The connector therefore
sends the non-secret ``x-interlock-org`` it already has in ``cloud.json`` as an
RLS hint. A forged hint only selects an org in which the prefix does not
exist; it never selects the wrong key, because the hash still has to match.

Revocation is read from the row on every call, so a revoked key is refused on
its next request with ``410 revoked`` - there is no positive-authorization
cache to wait to expire.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from ..enrollment import AGENT_SCOPES, parse_agent_key
from ..store import AgentKey

#: The header the connector uses for the RLS org hint.
ORG_HEADER = "x-interlock-org"

#: Scopes that C2's agent routes know. Everything else is refused.
KNOWN_SCOPES = frozenset(AGENT_SCOPES)


class AgentAuthError(Exception):
    """An agent request could not be authenticated."""

    def __init__(self, message: str, *, status: int = 401,
                 code: str = "unauthenticated") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class AgentRevoked(AgentAuthError):
    """The key exists but has been revoked (``410 revoked``)."""

    def __init__(self, message: str = "agent key revoked") -> None:
        super().__init__(message, status=410, code="revoked")


@dataclass(frozen=True)
class KeyContext:
    """The authenticated principal a host route sees.

    ``scopes`` is exactly the key's stored scope list; a route compares
    against it. ``keys_version`` is derived from the host's key rows so a
    long-poll can notice a rotation without another read.
    """

    org_id: str
    host_id: str
    key_id: str
    scopes: Tuple[str, ...] = ()
    keys_version: int = 0
    host_state: str = "active"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


#: The name the kickoff uses for the return type.
HostPrincipal = KeyContext


def _lower_headers(header: Any) -> Mapping[str, str]:
    if header is None:
        return {}
    if isinstance(header, Mapping):
        return {str(name).lower(): str(value) for name, value in header.items()}
    return {}


def _bearer_value(header: Any) -> Optional[str]:
    """Accept a raw key string or an ``Authorization: Bearer`` header."""
    if isinstance(header, str):
        return header
    headers = _lower_headers(header)
    raw = headers.get("authorization")
    if not raw:
        return None
    scheme, _, value = raw.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def agent_authenticate(store: Any, header: Any, *,
                       now: Optional[float] = None) -> KeyContext:
    """Authenticate a bearer key and return the host-scoped principal.

    ``header`` may be the raw key (tests, smoke) or a header mapping with
    ``authorization`` and optional ``x-interlock-org``. Raises
    :class:`AgentAuthError` for a bad/expired key and :class:`AgentRevoked`
    for a revoked one; both are rendered by the app's error map.
    """
    raw = _bearer_value(header)
    if raw is None:
        raise AgentAuthError("an agent key is required")

    parsed = parse_agent_key(raw)
    if parsed is None:
        raise AgentAuthError("malformed agent key")
    prefix, _raw = parsed

    headers = _lower_headers(header) if not isinstance(header, str) else {}
    org_hint = headers.get(ORG_HEADER) or None

    try:
        key = store.agent_key_by_prefix(prefix, org_id=org_hint)
    except ValueError:
        # Postgres needs the org hint; without it the lookup cannot be safe,
        # so report the same generic authentication failure.
        raise AgentAuthError("an agent key is required") from None
    except Exception as exc:  # CrossOrgAccess and friends
        if type(exc).__name__ == "CrossOrgAccess":
            raise AgentAuthError("unknown agent key") from None
        raise

    if key is None:
        raise AgentAuthError("unknown agent key")
    if not hmac.compare_digest(_digest(raw), key.secret_hash):
        raise AgentAuthError("unknown agent key")
    if key.revoked_at is not None:
        raise AgentRevoked("agent key revoked")

    at = _now(now)
    if key.expires is not None and at >= float(key.expires):
        raise AgentAuthError("agent key expired")

    host = store.host_by_id(key.org_id, key.host_id)
    if host is None or host.state != "active":
        raise AgentAuthError("host is not active")

    scopes = tuple(scope for scope in key.scopes if scope in KNOWN_SCOPES)
    return KeyContext(
        org_id=key.org_id,
        host_id=key.host_id,
        key_id=key.id,
        scopes=scopes,
        keys_version=_keys_version(store, key.org_id, key.host_id),
        host_state=host.state,
    )


def require_scope(context: KeyContext, scope: Optional[str]) -> None:
    """Refuse a key without ``scope``; ``None`` means authenticated is enough."""
    if scope is not None and not context.has_scope(scope):
        raise AgentAuthError(
            "this key is not scoped for {}".format(scope),
            status=403, code="forbidden",
        )


def _keys_version(store: Any, org_id: str, host_id: str) -> int:
    """Derive the per-host key generation from the key rows."""
    try:
        keys = store.list_agent_keys(org_id, host_id)
    except Exception:
        return 0
    return len(keys) + sum(1 for key in keys if key.revoked_at is not None)


def _now(value: Optional[float]) -> float:
    import time

    return time.time() if value is None else float(value)


__all__ = [
    "AgentAuthError",
    "AgentRevoked",
    "HostPrincipal",
    "KNOWN_SCOPES",
    "KeyContext",
    "ORG_HEADER",
    "agent_authenticate",
    "require_scope",
]
