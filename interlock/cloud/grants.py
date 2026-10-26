"""Ed25519 decision grants: signing on the plane, verification on the host.

A grant is the plane's *only* output for a review decision. It is a small JSON
envelope, signed with the org's approval key, that binds the org, the host, the
review, the review's binding hash, the decision, the reviewer and the step-up
assertion. The host verifies it before the local queue moves; a grant that does
not verify applies nothing (FR-025, FR-026).

The primitive is :mod:`interlock.mesh.ed25519`, the same pure-Python Ed25519
the receipt chain and mesh use - no new dependency. Canonical JSON for signing
is ``sort_keys=True, separators=(",", ":")`` with ``sig`` excluded, so both
sides sign and verify exactly the same bytes.

``seq`` is per host and strictly increasing, and ``prev`` is the previous
grant's signature (or ``GENESIS`` at sequence 1). A deleted or reordered grant
therefore breaks the chain visibly, even when every individual signature is
valid.

The approval seed is loaded from a file (``IL_CLOUD_APPROVAL_KEY_FILE``) by
the plane; it is never persisted in the database and never logged. The host
holds only the matching public key, pinned at enrollment.
"""
from __future__ import annotations

import json
import math
import os
import time
from typing import Any, Dict, Mapping, Optional

from ..mesh.ed25519 import KEY_SIZE, SIGNATURE_SIZE, generate_seed, public_key, sign, verify

#: A grant may never be valid for longer than this (FR-020's short-lived grant).
GRANT_MAX_TTL = 600

#: The host accepts this much clock skew when judging expiry and `issued_at`.
DEFAULT_MAX_SKEW = 60

#: The `prev` value of the first grant in a host's chain.
GENESIS = "GENESIS"

#: The check codes :func:`verify_grant` returns, in evaluation order.
CHECKS = ("version", "signature", "org", "host", "expiry", "future", "seq", "prev")


class GrantError(ValueError):
    """A grant could not be signed or parsed."""


def canonical_grant(envelope: Mapping[str, Any]) -> bytes:
    """The exact bytes a grant's signature covers (``sig`` is excluded)."""
    body = {key: value for key, value in envelope.items() if key != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_grant(seed: bytes, body: Mapping[str, Any]) -> Dict[str, Any]:
    """Return ``body`` plus a hex Ed25519 ``sig`` over canonical JSON.

    The test-facing wrapper the kickoff smoke uses. It refuses a grant whose
    ``expires_at`` is more than :data:`GRANT_MAX_TTL` after ``issued_at``:
    a decision that stays usable for longer than ten minutes is a policy bug,
    not a grant.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != KEY_SIZE:
        raise GrantError("an Ed25519 approval seed is 32 bytes")
    if not isinstance(body, Mapping):
        raise GrantError("a grant body must be an object")
    envelope = dict(body)
    envelope.pop("sig", None)
    try:
        issued = float(envelope["issued_at"])
        expires = float(envelope["expires_at"])
    except (KeyError, TypeError, ValueError):
        raise GrantError("a grant needs numeric issued_at and expires_at") from None
    if not math.isfinite(issued) or not math.isfinite(expires):
        raise GrantError("grant timestamps must be finite")
    if expires <= issued:
        raise GrantError("expires_at must be after issued_at")
    if expires - issued > GRANT_MAX_TTL:
        raise GrantError(
            "a grant may not be valid for more than {} seconds".format(GRANT_MAX_TTL))
    signature = sign(bytes(seed), canonical_grant(envelope))
    envelope["sig"] = signature.hex()
    return envelope


def approval_public_key(seed: bytes) -> bytes:
    """The 32-byte public half a host pins at enrollment."""
    return public_key(bytes(seed))


def approval_public_key_hex(seed: bytes) -> str:
    return approval_public_key(seed).hex()


def read_seed_file(path: str) -> bytes:
    """Read a hex-encoded 32-byte approval seed, refusing unsafe modes.

    The seed is the org's signing authority. A file another local account can
    read is a key compromise waiting to happen, so this mirrors the connector
    config's mode check: any group/world bit is refused.
    """
    import stat

    info = os.stat(path)
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(
            "{} is readable by other accounts; chmod 600 it".format(path))
    raw = open(path, "rb").read().strip()
    try:
        seed = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise GrantError("{} is not a hex Ed25519 seed".format(path)) from None
    if len(seed) != KEY_SIZE:
        raise GrantError("{} is not a 32-byte Ed25519 seed".format(path))
    return seed


def verify_grant(envelope: Any, public_key_bytes: bytes, *,
                 org_id: Optional[str] = None,
                 host_id: Optional[str] = None,
                 now: Optional[float] = None,
                 max_skew: float = DEFAULT_MAX_SKEW,
                 expected_seq: Optional[int] = None,
                 expected_prev: Optional[str] = None) -> Optional[str]:
    """Return the first failed check code, or ``None`` when the grant is good.

    Checks are evaluated in the order documented by :data:`CHECKS`. The
    envelope is treated as untrusted input: malformed values fail a check
    rather than raising, so a broken grant never crashes a connector cycle.
    ``expected_seq`` is exact match when given (the connector instead checks
    ``seq > last_seq`` itself, because it must also accept a skipped grant
    only after the chain check); ``expected_prev`` is exact match when given.
    """
    if not isinstance(envelope, Mapping):
        return "version"
    if envelope.get("v") != 1:
        return "version"

    signature_hex = envelope.get("sig")
    try:
        signature = bytes.fromhex(signature_hex) if isinstance(signature_hex, str) else b""
    except ValueError:
        return "signature"
    public = bytes(public_key_bytes) if isinstance(public_key_bytes, (bytes, bytearray)) else b""
    if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return "signature"
    try:
        if not verify(public, canonical_grant(envelope), signature):
            return "signature"
    except Exception:
        return "signature"

    if org_id is not None and envelope.get("org_id") != org_id:
        return "org"
    if host_id is not None and envelope.get("host_id") != host_id:
        return "host"

    at = time.time() if now is None else float(now)
    try:
        issued = float(envelope["issued_at"])
        expires = float(envelope["expires_at"])
        seq = int(envelope["seq"])
    except (KeyError, TypeError, ValueError):
        return "version"
    if not math.isfinite(issued) or not math.isfinite(expires):
        return "version"
    # A grant that was already usable for longer than the cap is refused even
    # while it is still inside its own lifetime.
    if expires - issued > GRANT_MAX_TTL + max_skew:
        return "expiry"
    if at > expires + max_skew:
        return "expiry"
    if issued > at + max_skew:
        return "future"

    if seq < 1:
        return "seq"
    if expected_seq is not None and seq != int(expected_seq):
        return "seq"
    if expected_prev is not None and envelope.get("prev") != expected_prev:
        return "prev"
    return None


__all__ = [
    "CHECKS",
    "DEFAULT_MAX_SKEW",
    "GENESIS",
    "GRANT_MAX_TTL",
    "GrantError",
    "approval_public_key",
    "approval_public_key_hex",
    "canonical_grant",
    "generate_seed",
    "read_seed_file",
    "sign_grant",
    "verify_grant",
]
