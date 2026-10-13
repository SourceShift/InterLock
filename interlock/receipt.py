"""Durable receipts for enforced decisions: what was decided, provably.

Every guarded action produces a Decision that used to vanish with the stack
frame - a ``_log.debug`` line and nothing else. This module turns a decision
into a Receipt: a small record with the time, action, verdict, reason, policy
id, ``attributed_to``, principal, span id, phase, and a digest of the
arguments. Receipts are written by the enforcement sites (the decorator's
``_emit`` and both MCP enforce functions) to an installed sink, never by a
policy rule: the enforcement site is the only place that knows the final,
combined decision and whether it was enforced or only observed.

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
(``pyproject.toml`` ``dependencies = []``). Verifying normally recomputes each
tag, which needs the signing key; a public-key scheme passes a ``Verifier``
(``message, tag -> bool``) instead, so an auditor can check the chain holding
only the public key.

Design note - observed decisions. Under ``enforcement="monitor"`` a decision
that would have blocked or rewritten the call is recorded with
``observed=True``: the call went through, and the receipt must not read as
enforcement. The field is serialized (and covered by the mac) only when true,
so receipts written before it existed verify unchanged.

Design note - provenance fields (R17). Every field added after the first
release is optional and omitted from the serialized form (and the mac) while
empty, the same rule ``observed`` follows, so older chains verify unchanged:

- ``call_id`` links the receipts of one guarded call: its call-side decision,
  its result-side decision, and an ``outcome`` receipt if the tool failed.
- ``policy_epoch`` identifies the rule set that decided (see
  ``PolicyEngine.epoch``).
- ``policy_verdict`` is set when what happened differs from what policy said:
  an ESCALATE that was approved (``verdict`` ALLOW) or not (``verdict`` BLOCK).
  ``verdict`` is what was enforced. Monitor-mode receipts are the one
  exception, kept for compatibility: their ``verdict`` is the policy verdict
  and ``observed`` says it was not enforced.
- ``approval`` records how an escalation was settled: ``approved:once``,
  ``approved:session``, ``approved:ttl``, ``reused:session``, ``reused:ttl``,
  ``declined``, ``no-approver`` or ``approver-error``.
- ``outcome`` and ``enforcer`` appear on ``phase="outcome"`` receipts, written
  when a tool that was allowed to run then failed: ``outcome`` is ``failed``
  and ``enforcer`` is ``os`` for a permission error from the operating system
  (which, under BRACE, is the sandbox refusing), else ``tool``.
- ``elapsed_us`` is how long the policy evaluation took.

A sink that fails to write is not allowed to turn into a silent gap: the
failed write raises :class:`~interlock.enforce.Blocked` (fail closed), and the
next successful write is preceded by a ``receipts.dropped`` receipt saying how
many were lost.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any, Callable, Optional

from .enforce import Blocked, Decision
from .event import SensorEvent

# A signer maps (key, message) -> tag. hmac_sha256 below is the default; an
# Ed25519 signer from `cryptography` can be injected through the same seam.
Signer = Callable[[bytes, bytes], bytes]

# A verifier maps (message, tag) -> bool: True when the tag is valid for the
# message. With one, verification never needs the signing key - the shape a
# public-key scheme needs (sign with the private key, verify with the public).
Verifier = Callable[[bytes, bytes], bool]


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
    # True when monitor mode recorded a decision it did not enforce. Kept out of
    # the serialized form (and the mac) while False, so older receipts and
    # older readers are unaffected.
    observed: bool = False
    # Provenance (R17). Each is omitted while None, like observed while False.
    call_id: Optional[str] = None
    policy_epoch: Optional[str] = None
    policy_verdict: Optional[str] = None
    approval: Optional[str] = None
    outcome: Optional[str] = None
    enforcer: Optional[str] = None
    elapsed_us: Optional[int] = None

    def fields(self, *, include_mac: bool = True) -> dict:
        """The receipt as a dict, in its canonical (serialized) shape."""
        body = dataclasses.asdict(self)
        if not body["observed"]:
            del body["observed"]
        for name in _OPTIONAL_FIELDS:
            if body[name] is None:
                del body[name]
        if not include_mac:
            del body["mac"]
        return body

    def to_json(self) -> str:
        """Canonical one-line serialization (sorted keys, tight separators)."""
        return json.dumps(self.fields(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> "Receipt":
        return cls(**json.loads(line))


_OPTIONAL_FIELDS = (
    "call_id", "policy_epoch", "policy_verdict", "approval", "outcome",
    "enforcer", "elapsed_us",
)


def signing_payload(receipt: Receipt) -> bytes:
    """The exact bytes a receipt's mac is computed over (every field but mac)."""
    canonical = json.dumps(
        receipt.fields(include_mac=False), sort_keys=True, separators=(",", ":")
    )
    return canonical.encode("utf-8")


def compute_mac(receipt: Receipt, signer: Signer, key: bytes) -> str:
    """The signer's tag over the receipt's canonical bytes (mac excluded)."""
    return signer(key, signing_payload(receipt)).hex()


def verify_chain(
    receipts: list,
    signer: Signer,
    key: bytes,
    *,
    verifier: Optional[Verifier] = None,
    head: Optional[str] = None,
) -> Optional[str]:
    """Walk a receipt chain and report the first break, or None if intact.

    Two independent checks per receipt: the prev linkage (a delete, reorder,
    or splice breaks it) and the mac (an edit to any field, or verifying with
    the wrong key, breaks it). The message names the first bad index, because
    "the chain is broken" without an index leaves the auditor hunting.

    ``verifier`` replaces recomputing each tag with ``signer`` and ``key``: pass
    one to check a public-key chain without the signing key. ``head`` is the
    last mac you recorded elsewhere; a chain ending anywhere else had receipts
    cut off its end, which the linkage alone cannot show.
    """
    previous_mac = GENESIS
    for index, receipt in enumerate(receipts):
        if receipt.prev != previous_mac:
            return "receipt {}: chain break (prev does not match the preceding receipt's mac)".format(
                index
            )
        if verifier is not None:
            try:
                valid = bool(verifier(signing_payload(receipt), bytes.fromhex(receipt.mac)))
            except Exception:
                valid = False
            if not valid:
                return "receipt {}: signature rejected by the verifier (edited, or signed with a different key)".format(
                    index
                )
        elif receipt.mac != compute_mac(receipt, signer, key):
            return "receipt {}: MAC mismatch (edited, or verified with a different key)".format(
                index
            )
        previous_mac = receipt.mac
    if head is not None and previous_mac != head:
        return "chain ends at receipt {} but the expected head is {}...: receipts were cut from the end, or this is not the log that head came from".format(
            len(receipts) - 1, head[:16]
        )
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


#: The policy id on a block caused by the audit sink itself failing.
SINK_POLICY_ID = "audit_sink"

_drop_lock = threading.Lock()
_dropped = 0
_last_drop_error = ""


def dropped_receipts() -> int:
    """How many receipts failed to write and are not yet reported in the log."""
    with _drop_lock:
        return _dropped


def emit_receipt(
    event: SensorEvent,
    decision: Decision,
    *,
    observed: bool = False,
    policy_epoch: Optional[str] = None,
    policy_verdict: Optional[str] = None,
    approval: Optional[str] = None,
    outcome: Optional[str] = None,
    enforcer: Optional[str] = None,
    elapsed_us: Optional[int] = None,
    phase: Optional[str] = None,
) -> None:
    """Build one Receipt from the enforced decision and write it to the sink.

    No sink installed: a no-op. Called from the enforcement sites only - the
    decorator, the MCP enforce functions and the approval path - never from a
    rule. ``observed`` marks a monitor-mode decision that was recorded, not
    enforced; the keyword fields are the R17 provenance fields described in
    the module docstring.

    A write that raises is fail-closed: it raises :class:`Blocked` (policy id
    :data:`SINK_POLICY_ID`) chained to the sink's error, so the guarded call
    does not proceed unrecorded, and the loss is counted and reported by a
    ``receipts.dropped`` receipt ahead of the next successful write.
    """
    sink = get_sink()
    if sink is None:
        return
    receipt = Receipt(
        ts=time.time(),
        action=event.action,
        verdict=decision.verdict.name,
        reason=decision.reason,
        policy_id=decision.policy_id,
        attributed_to=decision.attributed_to,
        principal=event.principal,
        span_id=event.span_id,
        phase=phase or getattr(event, "phase", "call"),
        args_digest=digest_args(event.args),
        observed=observed,
        call_id=getattr(event, "call_id", None),
        policy_epoch=policy_epoch,
        policy_verdict=policy_verdict,
        approval=approval,
        outcome=outcome,
        enforcer=enforcer,
        elapsed_us=elapsed_us,
    )
    _write(sink, receipt, event.action)


def _write(sink: Any, receipt: Receipt, action: str) -> None:
    global _dropped, _last_drop_error
    with _drop_lock:
        try:
            if _dropped:
                sink.write(Receipt(
                    ts=time.time(),
                    action="receipts.dropped",
                    verdict="ALLOW",
                    reason="{} receipt(s) could not be written; last error: {}".format(
                        _dropped, _last_drop_error),
                    policy_id=SINK_POLICY_ID,
                ))
                _dropped = 0
                _last_drop_error = ""
            sink.write(receipt)
        except Exception as exc:
            _dropped += 1
            _last_drop_error = type(exc).__name__
            raise Blocked(
                Decision.block(
                    "audit sink write failed, denied fail-closed: {}".format(
                        type(exc).__name__),
                    policy_id=SINK_POLICY_ID,
                ),
                action,
            ) from exc
