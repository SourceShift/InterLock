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

A grant may also name the grant that delegated its authority, as
``parent_grant``. A host that is given the parent envelopes then answers the
auditor's hardest question - was the authority valid at the moment of use - by
walking ``parent_grant`` up to :data:`MAX_ANCESTRY_DEPTH` links: every parent
must verify under the same key for the same org and host, must be an
``approve``, and must itself have been valid when the child was issued. A
grant that names no parent is unchanged, so an existing chain verifies exactly
as before.
"""
from __future__ import annotations

import json
import math
import os
import time
from typing import Any, Dict, List, Mapping, Optional

from ..mesh.ed25519 import KEY_SIZE, SIGNATURE_SIZE, generate_seed, public_key, sign, verify

#: A grant may never be valid for longer than this (FR-020's short-lived grant).
GRANT_MAX_TTL = 600

#: The host accepts this much clock skew when judging expiry and `issued_at`.
DEFAULT_MAX_SKEW = 60

#: The `prev` value of the first grant in a host's chain.
GENESIS = "GENESIS"

#: How many ``parent_grant`` links :func:`verify_grant` will walk. Four is
#: enough for plane -> operator -> reviewer -> host reconciliation; a longer
#: chain is a policy smell, not a delegation, so it is refused as ``ancestry``.
MAX_ANCESTRY_DEPTH = 4

#: The check codes :func:`verify_grant` returns, in evaluation order.
CHECKS = ("version", "signature", "org", "host", "expiry", "future", "seq", "prev",
          "ancestry")


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
    parent = envelope.get("parent_grant")
    if parent is not None:
        # A self-reference is never a delegation, and an empty id names
        # nothing to look up - both are bugs at the signing side, where the
        # plane is the only author.
        if not isinstance(parent, str) or not parent:
            raise GrantError("parent_grant must be a non-empty grant id")
        if parent == envelope.get("grant_id"):
            raise GrantError("a grant may not name itself as its parent")
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
                 expected_prev: Optional[str] = None,
                 parents: Any = None) -> Optional[str]:
    """Return the first failed check code, or ``None`` when the grant is good.

    Checks are evaluated in the order documented by :data:`CHECKS`. The
    envelope is treated as untrusted input: malformed values fail a check
    rather than raising, so a broken grant never crashes a connector cycle.
    ``expected_seq`` is exact match when given (the connector instead checks
    ``seq > last_seq`` itself, because it must also accept a skipped grant
    only after the chain check); ``expected_prev`` is exact match when given.

    ``parents`` supplies the envelopes a ``parent_grant`` link names: a
    mapping of grant id to envelope, or a callable taking the id and returning
    the envelope (or ``None``). It is only consulted when the envelope names a
    parent, so a grant without one verifies with no parents at all.
    """
    if not isinstance(envelope, Mapping):
        return "version"
    if envelope.get("v") != 1:
        return "version"

    public = bytes(public_key_bytes) if isinstance(public_key_bytes, (bytes, bytearray)) else b""
    if not _signature_ok(envelope, public):
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
    return _ancestry_problem(envelope, public, org_id=org_id, host_id=host_id,
                             parents=parents, issued=issued, max_skew=max_skew)


def _signature_ok(envelope: Mapping[str, Any], public: bytes) -> bool:
    """Whether ``envelope``'s ``sig`` verifies under ``public`` (never raises).

    Separated from :func:`verify_grant` so a parent envelope is checked with
    exactly the same rules as the grant naming it - one signature rule for
    the whole chain.
    """
    signature_hex = envelope.get("sig")
    try:
        signature = bytes.fromhex(signature_hex) if isinstance(signature_hex, str) else b""
    except ValueError:
        return False
    if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        return bool(verify(public, canonical_grant(envelope), signature))
    except Exception:
        return False


def _lookup(source: Any, grant_id: str) -> Any:
    """The envelope ``grant_id`` names in ``source``, or ``None``.

    Accepts a mapping (``.get``) or a callable; a source that raises is a
    missing parent, not a crashed connector cycle.
    """
    if source is None:
        return None
    getter = getattr(source, "get", None)
    try:
        if callable(getter):
            return getter(grant_id)
        if callable(source):
            return source(grant_id)
    except Exception:
        return None
    return None


def _ancestry_problem(envelope: Mapping[str, Any], public: bytes, *,
                      org_id: Optional[str], host_id: Optional[str],
                      parents: Any, issued: float,
                      max_skew: float) -> Optional[str]:
    """Walk ``parent_grant`` links; return ``"ancestry"`` or ``None``.

    Each link must name an envelope the host was given, verify under the same
    approval key for the same org and host, be an ``approve`` (nothing else
    delegates authority), and have been inside its own lifetime when the child
    was issued. A lapsed parent therefore cannot be used to keep a new grant
    alive: "was the authority valid at the moment of use" is answered on the
    chain, not on the child's own clock.
    """
    depth = 0
    seen: set = set()
    own = envelope.get("grant_id")
    if isinstance(own, str):
        # A grant that (forged or not) names itself is a one-link loop.
        seen.add(own)
    child, child_issued = envelope, issued
    while True:
        parent_id = child.get("parent_grant")
        if parent_id is None:
            return None
        if not isinstance(parent_id, str) or not parent_id or parent_id in seen:
            return "ancestry"
        depth += 1
        if depth > MAX_ANCESTRY_DEPTH:
            return "ancestry"
        seen.add(parent_id)
        parent = _lookup(parents, parent_id)
        if not isinstance(parent, Mapping) or parent.get("grant_id") != parent_id:
            return "ancestry"
        if not _signature_ok(parent, public):
            return "ancestry"
        if org_id is not None and parent.get("org_id") != org_id:
            return "ancestry"
        if host_id is not None and parent.get("host_id") != host_id:
            return "ancestry"
        if parent.get("decision") != "approve":
            return "ancestry"
        try:
            parent_issued = float(parent["issued_at"])
            parent_expires = float(parent["expires_at"])
        except (KeyError, TypeError, ValueError):
            return "ancestry"
        if not math.isfinite(parent_issued) or not math.isfinite(parent_expires):
            return "ancestry"
        if parent_expires - parent_issued > GRANT_MAX_TTL + max_skew:
            return "ancestry"
        if not (parent_issued - max_skew <= child_issued <= parent_expires + max_skew):
            return "ancestry"
        child, child_issued = parent, parent_issued


def ancestry_chain(envelope: Any, parents: Any = None) -> List[str]:
    """The grant ids an envelope's authority descends from, oldest first.

    Names only, bounded by :data:`MAX_ANCESTRY_DEPTH`; it does not verify, so
    pair it with a :func:`verify_grant` call over the same ``parents``. A
    receipt records the result, which is how an auditor later asks "under
    whose authority was this settled" without storing any argument value.
    """
    chain: List[str] = []
    current = envelope
    seen: set = set()
    if isinstance(envelope, Mapping) and isinstance(envelope.get("grant_id"), str):
        seen.add(envelope["grant_id"])
    while isinstance(current, Mapping) and len(chain) < MAX_ANCESTRY_DEPTH:
        parent_id = current.get("parent_grant")
        if not isinstance(parent_id, str) or not parent_id or parent_id in seen:
            break
        seen.add(parent_id)
        chain.append(parent_id)
        current = _lookup(parents, parent_id)
    chain.reverse()
    return chain


__all__ = [
    "CHECKS",
    "DEFAULT_MAX_SKEW",
    "GENESIS",
    "GRANT_MAX_TTL",
    "MAX_ANCESTRY_DEPTH",
    "GrantError",
    "ancestry_chain",
    "approval_public_key",
    "approval_public_key_hex",
    "canonical_grant",
    "generate_seed",
    "read_seed_file",
    "sign_grant",
    "verify_grant",
]
