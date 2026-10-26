"""Signed policy manifests and kill switches (C5, FR-043/FR-046/FR-067).

A manifest is the unit of distribution: a small Ed25519-signed envelope that
names an immutable artifact by sha256, a strictly increasing version, a
target, a mode and an expiry.  A host never applies bytes a manifest did not
name, and the connector's highest-accepted version is persisted outside the
artifact directory so a plane restored from backup cannot roll a host back.

The primitive is :mod:`interlock.mesh.ed25519`, the same dependency-free
Ed25519 used by grants and the receipt chain.  Canonical JSON for signing is
``sort_keys=True, separators=(",", ":")`` with ``sig`` excluded, so both sides
sign and verify exactly the same bytes.

``verify_manifest`` returns ``None`` on success or a short refusal code (the
first failed check, in :data:`MANIFEST_CHECKS` order).  It never raises on
malformed input: an untrusted envelope is a refusal, not a connector crash.
"""
from __future__ import annotations

import json
import math
import time
from typing import Any, Mapping, Optional

from ...mesh.ed25519 import KEY_SIZE, SIGNATURE_SIZE, keyid, public_key, sign, verify

#: FR-043: a manifest expires at most seven days after it was issued.
MANIFEST_MAX_TTL = 7 * 24 * 60 * 60

#: Clock skew tolerated when judging issue/expiry timestamps.
DEFAULT_MAX_SKEW = 60

#: Modes a manifest may carry.  ``monitor`` observes, ``warn`` records but
#: enforces nothing irreversible, ``enforce`` decides.
MANIFEST_MODES = ("monitor", "warn", "enforce")

#: Target kinds, most specific first (also the selection precedence).
TARGET_KINDS = ("host", "ring", "org")

#: The check codes :func:`verify_manifest` returns, in evaluation order.
MANIFEST_CHECKS = (
    "version", "signature", "org", "target", "manifest_version",
    "expiry", "expired", "future", "minimum_agent", "mode", "artifact",
)

#: The check codes :func:`verify_kill` returns.
KILL_CHECKS = ("version", "signature", "org", "target")


class ManifestError(ValueError):
    """A manifest could not be signed or is structurally unusable."""


def canonical_manifest(envelope: Mapping[str, Any]) -> bytes:
    """The exact bytes a manifest's signature covers (``sig`` excluded)."""
    body = {key: value for key, value in envelope.items() if key != "sig"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def policy_key_id(public_key_bytes: bytes) -> str:
    """The key id derived from the public key (metadata only, never trusted)."""
    return "policy-" + keyid(bytes(public_key_bytes))[:16]


def _check_seed(seed: Any) -> bytes:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != KEY_SIZE:
        raise ManifestError("an Ed25519 seed is 32 bytes")
    return bytes(seed)


def _check_window(envelope: Mapping[str, Any]) -> tuple:
    try:
        issued = float(envelope["issued_at"])
        expires = float(envelope["expires_at"])
    except (KeyError, TypeError, ValueError):
        raise ManifestError("a manifest needs numeric issued_at and expires_at") from None
    if not math.isfinite(issued) or not math.isfinite(expires):
        raise ManifestError("manifest timestamps must be finite")
    if expires <= issued:
        raise ManifestError("expires_at must be after issued_at")
    if expires - issued > MANIFEST_MAX_TTL:
        raise ManifestError(
            "a manifest may not be valid for more than {} seconds".format(
                MANIFEST_MAX_TTL
            )
        )
    return issued, expires


def _check_target(target: Any) -> dict:
    if not isinstance(target, Mapping):
        raise ManifestError("target must be an object")
    kind = target.get("kind")
    identifier = target.get("id")
    if kind not in TARGET_KINDS:
        raise ManifestError("target kind must be one of {}".format(", ".join(TARGET_KINDS)))
    if not isinstance(identifier, str) or not identifier:
        raise ManifestError("target id must be a non-empty string")
    return {"kind": kind, "id": identifier}


def sign_manifest(seed: bytes, body: Mapping[str, Any]) -> dict:
    """Return ``body`` plus a hex Ed25519 ``sig`` over its canonical JSON."""
    seed = _check_seed(seed)
    if not isinstance(body, Mapping):
        raise ManifestError("a manifest body must be an object")
    envelope = dict(body)
    envelope.pop("sig", None)
    if envelope.get("v") != 1:
        raise ManifestError("a manifest must be version 1")
    _check_window(envelope)
    envelope["target"] = _check_target(envelope.get("target"))
    if envelope.get("mode") not in MANIFEST_MODES:
        raise ManifestError("mode must be one of {}".format(", ".join(MANIFEST_MODES)))
    artifact = envelope.get("artifact")
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("sha256"), str):
        raise ManifestError("artifact must name a sha256")
    envelope["sig"] = sign(seed, canonical_manifest(envelope)).hex()
    return envelope


def sign_kill(seed: bytes, body: Mapping[str, Any]) -> dict:
    """Sign a kill document; kills do not expire, removal is a publication."""
    seed = _check_seed(seed)
    if not isinstance(body, Mapping):
        raise ManifestError("a kill body must be an object")
    envelope = dict(body)
    envelope.pop("sig", None)
    if envelope.get("v") != 1:
        raise ManifestError("a kill must be version 1")
    if not isinstance(envelope.get("reason"), str) or not envelope["reason"]:
        raise ManifestError("a kill needs a reason")
    if not isinstance(envelope.get("id"), str) or not envelope["id"]:
        raise ManifestError("a kill needs an id")
    try:
        issued = float(envelope["issued_at"])
    except (KeyError, TypeError, ValueError):
        raise ManifestError("a kill needs a numeric issued_at") from None
    if not math.isfinite(issued):
        raise ManifestError("kill timestamps must be finite")
    envelope["target"] = _check_target(envelope.get("target"))
    envelope["sig"] = sign(seed, canonical_manifest(envelope)).hex()
    return envelope


def _public_bytes(public_key_bytes: Any) -> bytes:
    if isinstance(public_key_bytes, str):
        try:
            return bytes.fromhex(public_key_bytes)
        except ValueError:
            return b""
    if isinstance(public_key_bytes, (bytes, bytearray)):
        return bytes(public_key_bytes)
    return b""


def _signature_ok(envelope: Mapping[str, Any], public: bytes) -> bool:
    signature_hex = envelope.get("sig")
    try:
        signature = bytes.fromhex(signature_hex) if isinstance(signature_hex, str) else b""
    except ValueError:
        return False
    if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        return bool(verify(public, canonical_manifest(envelope), signature))
    except Exception:
        return False


def _target_matches(target: Any, *, org_id: Optional[str],
                    host_id: Optional[str], ring: Optional[str]) -> bool:
    if not isinstance(target, Mapping):
        return False
    kind, identifier = target.get("kind"), target.get("id")
    if kind == "org":
        return org_id is not None and identifier == org_id
    if kind == "ring":
        return ring is not None and identifier == ring
    if kind == "host":
        return host_id is not None and identifier == host_id
    return False


def _version_tuple(value: Any) -> Optional[tuple]:
    if not isinstance(value, str) or not value:
        return None
    parts = value.split(".")
    out = []
    for part in parts:
        if not part.isdigit():
            return None
        out.append(int(part))
    return tuple(out)


def _minimum_agent_ok(required: Any, agent_version: Optional[str]) -> bool:
    """True when the running agent satisfies ``minimum_agent``.

    An absent minimum is satisfied.  A malformed minimum is a refusal.  A
    caller that does not supply its agent version is asking a plane-side
    question (the live smoke and manifest inspection do this), so the pin is
    treated as unjudged rather than failed; the connector always supplies
    ``agent_version``, which is where the minimum is enforced for real.
    """
    if required in (None, "", "0", "0.0.0"):
        return True
    required_parts = _version_tuple(required)
    if required_parts is None:
        return False
    if agent_version is None:
        return True
    running = _version_tuple(agent_version)
    if running is None:
        return False
    width = max(len(running), len(required_parts))
    return running + (0,) * (width - len(running)) >= required_parts + (0,) * (
        width - len(required_parts)
    )


def verify_manifest(
    envelope: Any,
    public_key_bytes: Any,
    *,
    org_id: Optional[str] = None,
    host_id: Optional[str] = None,
    ring: Optional[str] = None,
    now: Optional[float] = None,
    min_version: Optional[int] = None,
    agent_version: Optional[str] = None,
    max_skew: float = DEFAULT_MAX_SKEW,
) -> Optional[str]:
    """Return the first failed check code, or ``None`` when the manifest is good."""
    if not isinstance(envelope, Mapping) or envelope.get("v") != 1:
        return "version"
    public = _public_bytes(public_key_bytes)
    if not _signature_ok(envelope, public):
        return "signature"
    if org_id is not None and envelope.get("org_id") != org_id:
        return "org"
    if not _target_matches(envelope.get("target"), org_id=org_id,
                           host_id=host_id, ring=ring):
        return "target"

    try:
        version = int(envelope["version"])
    except (KeyError, TypeError, ValueError):
        return "version"
    if version < 1:
        return "version"
    if min_version is not None and version <= int(min_version):
        return "manifest_version"

    at = time.time() if now is None else float(now)
    try:
        issued = float(envelope["issued_at"])
        expires = float(envelope["expires_at"])
    except (KeyError, TypeError, ValueError):
        return "expiry"
    if not math.isfinite(issued) or not math.isfinite(expires):
        return "expiry"
    if expires - issued > MANIFEST_MAX_TTL + max_skew:
        return "expiry"
    if at > expires + max_skew:
        return "expired"
    if issued > at + max_skew:
        return "future"
    if not _minimum_agent_ok(envelope.get("minimum_agent"), agent_version):
        return "minimum_agent"
    if envelope.get("mode") not in MANIFEST_MODES:
        return "mode"
    artifact = envelope.get("artifact")
    if not isinstance(artifact, Mapping):
        return "artifact"
    if not isinstance(artifact.get("sha256"), str) or not artifact["sha256"]:
        return "artifact"
    try:
        size = int(artifact.get("size"))
    except (TypeError, ValueError):
        return "artifact"
    if size < 0:
        return "artifact"
    return None


def verify_kill(
    envelope: Any,
    public_key_bytes: Any,
    *,
    org_id: Optional[str] = None,
    host_id: Optional[str] = None,
    ring: Optional[str] = None,
) -> Optional[str]:
    """Return the first failed check code for a kill document, or ``None``."""
    if not isinstance(envelope, Mapping) or envelope.get("v") != 1:
        return "version"
    if not _signature_ok(envelope, _public_bytes(public_key_bytes)):
        return "signature"
    if org_id is not None and envelope.get("org_id") != org_id:
        return "org"
    if not _target_matches(envelope.get("target"), org_id=org_id,
                           host_id=host_id, ring=ring):
        return "target"
    return None


def kill_applies(envelope: Mapping[str, Any], *, org_id: Optional[str],
                 host_id: Optional[str], ring: Optional[str]) -> bool:
    """True when a *verified* kill names this host, its ring or its org."""
    return _target_matches(envelope.get("target"), org_id=org_id,
                           host_id=host_id, ring=ring)


__all__ = [
    "DEFAULT_MAX_SKEW",
    "KILL_CHECKS",
    "MANIFEST_CHECKS",
    "MANIFEST_MAX_TTL",
    "MANIFEST_MODES",
    "ManifestError",
    "TARGET_KINDS",
    "canonical_manifest",
    "kill_applies",
    "policy_key_id",
    "public_key",
    "sign_kill",
    "sign_manifest",
    "verify_kill",
    "verify_manifest",
]
