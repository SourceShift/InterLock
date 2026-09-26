"""Durable receipts for enforced decisions: what was decided, provably.

Every guarded action produces a Decision that used to vanish with the stack
frame - a ``_log.debug`` line and nothing else. This module turns a decision
into a Receipt: a small record with the time, action, verdict, reason, policy
id, ``attributed_to``, principal, span id, phase, and a digest of the
arguments. Receipts are written by the enforcement sites (the decorator's
``_emit`` and both MCP enforce functions) to an installed sink, never by a
policy rule: a MODIFY is terminal in the engine's rule loop, so a receipt
implemented as a rule would be short-circuited by an earlier stamp or would
short-circuit everything after it.

Design note - the stamps' fate. The four stamp detectors
(``event_hmac_stamp`` & co.) KEEP their current behaviour: their MODIFY
verdicts still merge the stamp field into the outgoing call, and the receipt
does not absorb or re-digest the stamp. The receipt digests ``event.args`` -
the arguments the caller passed, which is exactly what the policy judged -
because the engine never merges ``modified_args`` back into the event. A stamp
decision therefore shows up as a receipt with verdict MODIFY and the stamp's
policy id, while the stamp itself rides the call as before. Nothing a detector
computes is lost; nothing the tool receives changes.

Design note - no values at rest. A receipt is the most durable object in the
process, so an argument value copied into it is a value at rest. The receipt
stores a SHA-256 digest over the arguments instead of the arguments: the
digest covers the values (any edit changes it) without storing them.
``attributed_to`` is already a name by contract and is copied as a name. The
``reason`` field is copied from the decision verbatim - the receipt machinery
itself never interpolates a value into any field, so with the suite's
fixed-string reasons no argument value can appear in a serialized receipt.

Design note - MAC, not a signature. The default signer is stdlib
``hmac.new(key, message, sha256)`` keyed with a per-process random secret. A
MAC proves the receipt was produced by a holder of the shared secret - it does
NOT prove which principal produced it, and any verifier must also hold the
secret. That is a different and weaker claim than a public-key signature such
as Ed25519 (anyone can verify, only the key holder can produce). The seam is
the ``Signer`` callable (``key, message -> bytes``): a caller who has
``cryptography`` installed can inject an Ed25519 signer without interlock
depending on it - ``interlock`` must stay dependency-free
(``pyproject.toml`` ``dependencies = []``).
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Callable, Optional

from .enforce import Decision
from .event import SensorEvent

# A signer maps (key, message) -> tag. hmac_sha256 below is the default; an
# Ed25519 signer from `cryptography` can be injected through the same seam.
Signer = Callable[[bytes, bytes], bytes]


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Default signer: an HMAC-SHA256 MAC over ``message`` keyed with ``key``.

    This is a MAC, not a public-key signature. The claim it makes: the receipt
    was produced by a holder of the shared secret, and its content has not
    changed since. The claim it does NOT make: which of the holders produced
    it, or anything verifiable by a party without the secret.
    """
    return hmac.new(key, message, hashlib.sha256).digest()


# The default signing key: random per process, so receipts chained under the
# default signer are verifiable inside the process that wrote them. A durable
# deployment passes its own long-lived key to the sink.
_PROCESS_SECRET = secrets.token_bytes(32)


def process_secret() -> bytes:
    """Return this process's default receipt-signing secret."""
    return _PROCESS_SECRET


# The prev value of the first receipt in a chain (64 zeros: sha256-shaped, so
# a genesis prev is indistinguishable in width from any later mac).
GENESIS = "0" * 64


def digest_args(args: Any) -> str:
    """SHA-256 over the arguments, without storing them.

    Deterministic for the same argument dict: pairs are ``(repr(key),
    repr(value))`` so mixed-type keys still sort, and repr (unlike str) keeps
    ``1`` distinct from ``"1"``. Arguments that cannot be rendered fall back
    to ``repr(args)`` - still a digest of the content, never the content.
    """
    if isinstance(args, dict):
        try:
            payload = repr(sorted((repr(k), repr(v)) for k, v in args.items()))
        except Exception:
            payload = repr(args)
    else:
        payload = repr(args)
    try:
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
    except Exception:  # a repr that explodes on encode: digest a constant
        return hashlib.sha256(b"<unencodable args>").hexdigest()


@dataclasses.dataclass
class Receipt:
    """One enforced decision, as written to the audit sink.

    ``prev`` and ``mac`` are assigned by the sink at write time: ``prev`` is
    the previous receipt's ``mac`` (GENESIS for the first), and ``mac`` is the
    signer's tag over the canonical JSON of every other field. Together they
    make the sink tamper-evident - editing a receipt breaks its mac, deleting
    or reordering breaks the next receipt's prev linkage.
    """

    ts: float
    action: str
    verdict: str
    reason: str = ""
    policy_id: Optional[str] = None
    attributed_to: Optional[str] = None
    principal: Optional[str] = None
    span_id: Optional[str] = None
    phase: str = "call"
    args_digest: str = ""
    prev: str = GENESIS
    mac: str = ""

    def to_json(self) -> str:
        """Canonical one-line serialization (sorted keys, tight separators)."""
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )

    @classmethod
    def from_json(cls, line: str) -> "Receipt":
        return cls(**json.loads(line))


def compute_mac(receipt: Receipt, signer: Signer, key: bytes) -> str:
    """The signer's tag over the receipt's canonical bytes (mac excluded)."""
    body = {
        k: v for k, v in dataclasses.asdict(receipt).items() if k != "mac"
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return signer(key, canonical.encode("utf-8")).hex()


def verify_chain(
    receipts: list, signer: Signer, key: bytes
) -> Optional[str]:
    """Walk a receipt chain and report the first break, or None if intact.

    Two independent checks per receipt: the prev linkage (a delete, reorder,
    or splice breaks it) and the mac (an edit to any field, or verifying with
    the wrong key, breaks it). The message names the first bad index, because
    "the chain is broken" without an index leaves the auditor hunting.
    """
    previous_mac = GENESIS
    for index, receipt in enumerate(receipts):
        if receipt.prev != previous_mac:
            return "receipt {}: chain break (prev does not match the preceding receipt's mac)".format(
                index
            )
        if receipt.mac != compute_mac(receipt, signer, key):
            return "receipt {}: MAC mismatch (edited, or verified with a different key)".format(
                index
            )
        previous_mac = receipt.mac
    return None


# --- the installed sink ------------------------------------------------------
#
# Off by default: no sink installed means emit_receipt writes nothing and the
# guard behaves byte-identically to a build without receipts. Installing a
# sink is explicit - set_sink(...) or install(sink=...).

_sink: Optional[Any] = None


def set_sink(sink: Optional[Any]) -> None:
    """Install (or with None, remove) the process-global receipt sink."""
    global _sink
    _sink = sink


def get_sink() -> Optional[Any]:
    return _sink


def emit_receipt(event: SensorEvent, decision: Decision) -> None:
    """Build one Receipt from the enforced decision and write it to the sink.

    No sink installed: a no-op. Called from the enforcement sites only - the
    decorator's ``_emit`` and both MCP enforce functions - never from a rule.
    """
    sink = get_sink()
    if sink is None:
        return
    sink.write(
        Receipt(
            ts=time.time(),
            action=event.action,
            verdict=decision.verdict.name,
            reason=decision.reason,
            policy_id=decision.policy_id,
            attributed_to=decision.attributed_to,
            principal=event.principal,
            span_id=event.span_id,
            phase=getattr(event, "phase", "call"),
            args_digest=digest_args(event.args),
        )
    )
