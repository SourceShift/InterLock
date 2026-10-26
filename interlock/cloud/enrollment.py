"""Single-use enrollment tokens and the one agent-key format.

Two credentials live here, and both have a deliberate shape:

* An **enrollment token** is ``ilkt_<org_id>_<secret>``. The org id is not a
  secret; it travels in the token because ``enrollment_tokens`` is protected
  by row-level security and the plane must set ``interlock.org_id`` *before*
  it can look the token hash up (C1's session cookie does the same). Only
  ``SHA-256(raw)`` is stored, so a database leak does not yield a usable
  token.
* An **agent key** is ``ilk_<8-hex-prefix>_<43-char base64url secret>``. The
  prefix is the searchable, non-secret half; the plane stores SHA-256 of the
  full key and compares it in constant time (FR-002). Nothing here derives a
  key from a password.

This module imports no third-party package and does not import the store, so
the store may import it for token minting and hashing.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Optional, Tuple

#: Token envelope prefix. The version letter leaves room for a format change.
ENROLLMENT_TOKEN_PREFIX = "ilkt_"

#: The one agent-key form the spec fixes (FR-002): ``ilk_`` + 8 hex + ``_`` +
#: 43 base64url characters (32 random bytes).
AGENT_KEY_PREFIX = "ilk_"
AGENT_KEY_PATTERN = re.compile(r"^ilk_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$")

#: FR-054: an agent key is scoped to exactly these four operations on its own
#: host. There is no wildcard and no admin scope.
AGENT_SCOPES = (
    "ingest:reviews",
    "ingest:receipts",
    "pull:policy",
    "poll:grants",
)

#: The org id is separated from the secret by an underscore. Org ids are hex
#: or slug-safe in this codebase; the secret is URL-safe base64.
_ORG_SEPARATOR = "_"


def hash_token(raw: str) -> str:
    """The at-rest hash of an enrollment token or agent key."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mint_enrollment_token(org_id: str) -> str:
    """A fresh raw enrollment token carrying its (non-secret) org id."""
    secret = secrets.token_urlsafe(32)
    return "{}{}{}{}".format(
        ENROLLMENT_TOKEN_PREFIX, org_id, _ORG_SEPARATOR, secret
    )


def enrollment_org(raw: object) -> Optional[str]:
    """Split the org id out of a raw token, or ``None`` when malformed.

    A malformed value is not an error the caller should distinguish from a
    wrong token: both produce the same ``401 token_invalid``.
    """
    if not isinstance(raw, str) or not raw.startswith(ENROLLMENT_TOKEN_PREFIX):
        return None
    rest = raw[len(ENROLLMENT_TOKEN_PREFIX):]
    org_id, separator, secret = rest.partition(_ORG_SEPARATOR)
    if not separator or not org_id or not secret:
        return None
    return org_id


def generate_agent_key() -> Tuple[str, str, str]:
    """Return ``(raw, prefix, hash)`` for a fresh agent key.

    ``raw`` is returned to the caller exactly once; only ``prefix`` and
    ``hash`` belong in storage, logs or audit rows.
    """
    prefix = secrets.token_hex(4)  # eight lowercase hex characters
    secret = secrets.token_urlsafe(32)  # 43 base64url characters
    raw = "{}{}_{}".format(AGENT_KEY_PREFIX, prefix, secret)
    return raw, prefix, hash_token(raw)


def parse_agent_key(raw: object) -> Optional[Tuple[str, str]]:
    """Strictly parse ``ilk_<prefix>_<secret>`` into ``(prefix, raw)``.

    Anything else - a truncated key, an uppercase prefix, a secret of the
    wrong length - is refused before any store lookup.
    """
    if not isinstance(raw, str):
        return None
    match = AGENT_KEY_PATTERN.match(raw)
    if match is None:
        return None
    return match.group(1), raw


def agent_key_secret(raw: str) -> str:
    """The secret half of a well-formed key; only used for hashing."""
    parsed = parse_agent_key(raw)
    if parsed is None:
        raise ValueError("malformed agent key")
    return raw.split("_", 2)[2]


__all__ = [
    "AGENT_KEY_PATTERN",
    "AGENT_KEY_PREFIX",
    "AGENT_SCOPES",
    "ENROLLMENT_TOKEN_PREFIX",
    "agent_key_secret",
    "enrollment_org",
    "generate_agent_key",
    "hash_token",
    "mint_enrollment_token",
    "parse_agent_key",
]
