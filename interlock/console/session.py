"""Console settings, the shared request helpers, and the write gate.

Read routes answer anyone the server already lets in (a loopback Host, see
``server.py``). Write routes - deciding a review, saving the policy - also
need the **unlock token** of a browser tab that was unlocked by a human.

Why a token on top of the CSRF guard: JSON-only POSTs and the Host allowlist
stop a hostile *web page*. They do not stop an agent on this machine running
``curl`` against the console - and the coding-agent pack refuses ``interlock
reviews approve`` and writes under ``~/.interlock`` precisely so an agent can't
approve itself or loosen its own policy. A console that took those writes from
anyone on loopback would be the way round both.

So at launch the console makes a one-off **unlock code** and prints it, as a
link, to its own terminal - nowhere else: not a file, not argv, not a response.
A human pastes it into the tab (``POST /api/unlock``), which gets back a random
**token** held only in that tab's ``sessionStorage`` and sent as the
``X-Interlock-Unlock`` header. Tokens live in this process's memory, so
restarting the console re-locks every tab. Wrong codes are counted; after
``MAX_FAILURES`` the gate refuses every further attempt until a restart, so the
code can't be guessed.
"""
from __future__ import annotations

import getpass
import hmac
import os
import re
import secrets
import threading
from typing import Any, Optional, Set, Tuple

from .server import ROUTES, ApiError, read_json_body  # noqa: F401 - re-exported for the feature modules

#: The header a write request carries its unlock token in.
TOKEN_HEADER = "X-Interlock-Unlock"
#: Wrong unlock codes tolerated before the gate shuts until a restart.
MAX_FAILURES = 10

_CODE_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_IN_TEXT = re.compile(r"(?:^|/unlock/)([A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})\s*$")


def handles_errors(fn):
    """Turn an ``ApiError`` raised by a route into its error response."""
    def route(handler: Any):
        try:
            return fn(handler)
        except ApiError as exc:
            return exc.status, exc.body()
    route.__name__ = fn.__name__
    route.__doc__ = fn.__doc__
    return route


class WriteGate:
    """The per-launch unlock code and the tokens of unlocked tabs."""

    def __init__(self, code: Optional[str] = None) -> None:
        self.code = code or "-".join(
            "".join(secrets.choice(_CODE_ALPHABET) for _ in range(4)) for _ in range(3))
        self._tokens: Set[str] = set()
        self._failures = 0
        self._lock = threading.Lock()

    @property
    def shut(self) -> bool:
        return self._failures >= MAX_FAILURES

    def unlock(self, text: str) -> str:
        """A fresh token for a pasted code or link; ``ApiError`` otherwise."""
        with self._lock:
            if self.shut:
                raise ApiError(429, "unlock_shut",
                               "too many wrong codes: restart the console to get a new one")
            match = _CODE_IN_TEXT.search((text or "").strip())
            given = match.group(1) if match else ""
            if not given or not hmac.compare_digest(given.encode(), self.code.encode()):
                self._failures += 1
                raise ApiError(403, "bad_unlock_code",
                               "That code doesn't match this launch. Codes change every time "
                               "the console starts." if given else
                               "Paste the link or code from the console terminal.")
            token = secrets.token_urlsafe(32)
            self._tokens.add(token)
            return token

    def lock(self, token: Optional[str]) -> None:
        with self._lock:
            self._tokens.discard(token or "")

    def is_unlocked(self, token: Optional[str]) -> bool:
        if not token:
            return False
        with self._lock:
            return any(hmac.compare_digest(token, t) for t in self._tokens)


def configure(server: Any, *, policy_path: Optional[str] = None, reviews_db: Optional[str] = None,
              trust_path: Optional[str] = None, four_eyes: bool = False,
              sidecar: Optional[str] = None, sidecar_admin: Optional[str] = None,
              key_file: Optional[str] = None, cwd: Optional[str] = None,
              unlock_code: Optional[str] = None) -> WriteGate:
    """Attach the settings the console's feature modules read to ``server``.

    Kept off :class:`ConsoleServer`'s constructor so each module reads its own
    setting with :func:`setting` and a sensible default.
    """
    from ..adapters.config import policy_path as default_policy_path
    from ..reviews import default_path as default_reviews_path

    server.policy_path = os.path.abspath(os.path.expanduser(policy_path or default_policy_path()))
    server.reviews_db = os.path.abspath(os.path.expanduser(reviews_db or default_reviews_path()))
    server.trust_path = trust_path
    server.four_eyes = bool(four_eyes)
    server.sidecar = sidecar
    server.sidecar_admin = sidecar_admin
    server.key_file = key_file
    server.project_cwd = os.path.abspath(cwd or os.getcwd())
    server.write_gate = WriteGate(unlock_code)
    return server.write_gate


def setting(handler: Any, name: str, default: Any = None) -> Any:
    return getattr(handler.server, name, default)


def whoami() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def gate(handler: Any) -> WriteGate:
    existing = getattr(handler.server, "write_gate", None)
    if existing is None:  # a server built without configure(): locked for good
        existing = handler.server.write_gate = WriteGate()
    return existing


def require_unlocked(handler: Any) -> None:
    """Raise unless this request carries a live unlock token."""
    if not gate(handler).is_unlocked(handler.headers.get(TOKEN_HEADER)):
        raise ApiError(403, "locked", "Read-only: unlock writes first.")


# --- routes -------------------------------------------------------------------


@handles_errors
def _session(handler: Any) -> Tuple[int, dict]:
    from interlock import __version__

    g = gate(handler)
    server = handler.server
    return 200, {
        "version": __version__,
        "me": whoami(),
        "locked": not g.is_unlocked(handler.headers.get(TOKEN_HEADER)),
        "unlock_shut": g.shut,
        "four_eyes": bool(setting(handler, "four_eyes", False)),
        "receipts_path": getattr(server, "receipts_path", None),
        "key": getattr(server, "receipts_key", None) is not None,
        "policy_path": setting(handler, "policy_path"),
        "reviews_db": setting(handler, "reviews_db"),
        "home": os.path.expanduser("~"),
    }


@handles_errors
def _unlock(handler: Any) -> Tuple[int, dict]:
    body = read_json_body(handler)
    token = gate(handler).unlock(str(body.get("code") or ""))
    return 200, {"token": token}


@handles_errors
def _lock(handler: Any) -> Tuple[int, dict]:
    read_json_body(handler)
    gate(handler).lock(handler.headers.get(TOKEN_HEADER))
    return 200, {"locked": True}


ROUTES["/api/session"] = {"GET": _session}
ROUTES["/api/unlock"] = {"POST": _unlock}
ROUTES["/api/lock"] = {"POST": _lock}
