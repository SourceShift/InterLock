"""Server-side sessions and CSRF (FR-049, FR-050).

The raw session token is returned to the caller exactly once and only its
SHA-256 hash is stored. The cookie value is ``<org_id>.<raw>``: resolving a
token under Postgres row-level security needs the org *before* the sessions
query, so the (non-secret) org id travels beside the opaque token. The
one-argument :meth:`SessionManager.resolve` form stays valid for
:class:`~interlock.cloud.store.MemoryStore` and the live smoke.

Cookie headers are built by :mod:`interlock.cloud.http`; this module never
touches ASGI, so it is testable without a server.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any, Optional, Tuple

from ..store import CrossOrgAccess, Session, User

#: FR-049: half an hour idle, twelve hours absolute.
DEFAULT_IDLE = 30 * 60
DEFAULT_ABSOLUTE = 12 * 60 * 60

#: Touch ``last_seen`` at most once a minute; a touch per request would make
#: every GET a write and give an attacker a write-amplification lever.
TOUCH_INTERVAL = 60

COOKIE_NAME = "__Host-il_session"
SESSION_COOKIE = COOKIE_NAME
CSRF_COOKIE = "il_csrf"
CSRF_HEADER = "x-csrf-token"


class Unauthenticated(Exception):
    """No session, or the session is no longer usable."""

    def __init__(self, message: str = "authentication required") -> None:
        super().__init__(message)
        self.code = "unauthenticated"


class SessionExpired(Unauthenticated):
    """The session passed its idle or absolute deadline."""


def _as_bytes(secret: Any) -> bytes:
    if isinstance(secret, bytes):
        return secret
    return str(secret).encode("utf-8")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SessionManager:
    """Mint, resolve and revoke opaque server-side sessions."""

    cookie_name = COOKIE_NAME

    def __init__(self, store: Any, secret: Any, *, idle: int = DEFAULT_IDLE,
                 absolute: int = DEFAULT_ABSOLUTE,
                 clock: Any = time.time) -> None:
        self.store = store
        self.secret = _as_bytes(secret)
        self.idle = int(idle)
        self.absolute = int(absolute)
        self.clock = clock

    # -- token material -------------------------------------------------
    @staticmethod
    def hash(raw: str) -> str:
        """The public, deterministic at-rest hash of a raw token."""
        return _sha256_hex(raw)

    #: Alias used by callers that prefer a noun.
    hash_token = hash

    def csrf_token(self, session_id: str) -> str:
        """HMAC-SHA256(secret, session_id + "csrf"), hex encoded."""
        return hmac.new(
            self.secret, session_id.encode("utf-8") + b"csrf",
            hashlib.sha256,
        ).hexdigest()

    def check_csrf(self, session: Session, provided: Optional[str]) -> bool:
        """Constant-time check of a presented CSRF token (FR-050)."""
        if not provided or not isinstance(provided, str):
            return False
        expected = self.csrf_token(session.id)
        if not hmac.compare_digest(expected, provided):
            return False
        return hmac.compare_digest(_sha256_hex(provided), session.csrf_hash)

    # -- cookie value ---------------------------------------------------
    @staticmethod
    def cookie_value(org_id: str, raw: str) -> str:
        """The value placed in ``__Host-il_session``."""
        return "{}.{}".format(org_id, raw)

    @staticmethod
    def split_cookie(value: str) -> Tuple[Optional[str], str]:
        """Split ``<org>.<raw>``; a bare value is treated as a raw token."""
        org_id, separator, raw = value.partition(".")
        if not separator:
            return None, value
        return org_id, raw

    # -- lifecycle ------------------------------------------------------
    def login(self, user: User, *, ip: Optional[str] = None,
              user_agent: Optional[str] = None) -> str:
        """Create a session and return the raw token exactly once."""
        raw = secrets.token_urlsafe(32)
        now = self.clock()
        session_id = secrets.token_hex(16)
        self.store.create_session(
            org_id=user.org_id,
            user_id=user.id,
            token_hash=self.hash(raw),
            csrf_hash=_sha256_hex(self.csrf_token(session_id)),
            expires=now + self.absolute,
            id=session_id,
            created=now,
            last_seen=now,
            ip=ip,
            user_agent=user_agent,
        )
        return raw

    def resolve(self, raw: str, *, org_id: Optional[str] = None) -> User:
        """Return the authenticated user or raise :class:`Unauthenticated`."""
        session, user = self.resolve_session(raw, org_id=org_id)
        return user

    def resolve_session(self, raw: str, *,
                        org_id: Optional[str] = None) -> Tuple[Session, User]:
        try:
            session = self.store.session_by_token_hash(
                self.hash(raw), org_id=org_id
            )
        except CrossOrgAccess:
            raise Unauthenticated("unknown session") from None
        if session is None:
            raise Unauthenticated("unknown session")

        now = self.clock()
        idle_deadline = session.last_seen + self.idle
        if now >= session.expires or now >= idle_deadline:
            self.store.delete_session(session.org_id, session.id)
            raise SessionExpired("session expired")

        try:
            user = self.store.user_by_id(session.org_id, session.user_id)
        except CrossOrgAccess:
            user = None
        if user is None or user.status != "active":
            self.store.delete_session(session.org_id, session.id)
            raise Unauthenticated("user is not active")

        if now - session.last_seen >= TOUCH_INTERVAL:
            self.store.touch_session(session.org_id, session.id, now)
            session.last_seen = now
        return session, user

    def resolve_cookie(self, value: str) -> User:
        """Resolve a ``__Host-il_session`` value carrying an org prefix."""
        session, user = self.resolve_cookie_session(value)
        return user

    def resolve_cookie_session(self, value: str) -> Tuple[Session, User]:
        org_id, raw = self.split_cookie(value)
        return self.resolve_session(raw, org_id=org_id)

    def logout(self, org_id: str, session_id: str) -> None:
        self.store.delete_session(org_id, session_id)

    def disable_user(self, org_id: str, user_id: str) -> int:
        """Revoke every session of a user (FR-051)."""
        return self.store.delete_user_sessions(org_id, user_id)

    def mark_step_up(self, session: Session, method: str,
                     now: Optional[float] = None) -> None:
        """Record a completed step-up on the session row."""
        at = self.clock() if now is None else now
        self.store.touch_session(session.org_id, session.id,
                                 session.last_seen, step_up_at=at,
                                 step_up_method=method)
        session.step_up_at = at
        session.step_up_method = method


__all__ = [
    "CSRF_COOKIE",
    "CSRF_HEADER",
    "COOKIE_NAME",
    "SESSION_COOKIE",
    "DEFAULT_ABSOLUTE",
    "DEFAULT_IDLE",
    "SessionExpired",
    "SessionManager",
    "TOUCH_INTERVAL",
    "Unauthenticated",
]
