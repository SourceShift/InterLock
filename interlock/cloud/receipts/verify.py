"""Verify receipt chains on arrival and before export (FR-032 .. FR-040).

A receipt chain is tamper-evident in two independent ways: every receipt's
``mac`` covers its own fields, and every receipt's ``prev`` names the previous
receipt's mac. The host writes the chain; the plane only ever reads it. This
module answers:

* **Does this batch continue the chain we stored?** :func:`verify_batch`.
  Ed25519 hosts have every signature checked (``verified``); HMAC hosts can
  only have ``prev`` linkage checked, so their chain is ``linkage_only`` until
  a signed checkpoint attests it - and ``receipts_unverified`` once the newest
  checkpoint is more than 24 hours old (FR-035).
* **Is the signed checkpoint genuine?** :func:`verify_checkpoint`. It is
  Ed25519 over the canonical JSON of the six documented fields, signed even by
  HMAC hosts - the only non-repudiation such a host has.
* **Is this export intact?** :func:`verify_export`, which the export route
  runs before writing a byte.

``status`` is always one of :data:`VERIFICATION_LEVELS` (or ``ok`` for an empty
batch and ``fork`` for a break); it is never a boolean.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from ...receipt import GENESIS, Receipt, verify_chain
from ...receipt_ed25519 import ed25519_verifier
from ...mesh.ed25519 import KEY_SIZE, sign, verify

#: FR-035: a linkage-only chain with no checkpoint for this long is unverified.
CHECKPOINT_MAX_AGE = 24 * 60 * 60

#: The exact verification levels the API exposes.
VERIFICATION_LEVELS = ("verified", "linkage_only", "receipts_unverified")

#: A batch result's status may also be one of these two non-level values.
BATCH_STATUSES = ("ok", "fork") + VERIFICATION_LEVELS

#: The fields a checkpoint signature covers, in the documented order.
CHECKPOINT_FIELDS = ("v", "org_id", "host_id", "head_mac", "count", "issued_at")

_BAD_INDEX = re.compile(r"receipt (\d+):")


@dataclass(frozen=True)
class BatchResult:
    """The outcome of verifying one incoming batch.

    ``status`` is ``ok`` (empty/replay), ``fork``, or one of
    :data:`VERIFICATION_LEVELS`. ``head`` is the chain head after the batch
    (unchanged on a fork or replay), ``count`` the total receipt count, and
    ``first_bad`` the zero-based index of the first rejected receipt, if any.
    """

    status: str
    first_bad: Optional[int] = None
    head: Optional[str] = None
    count: int = 0
    reason: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.status in ("ok",) + VERIFICATION_LEVELS

    @property
    def verification(self) -> str:
        """The level to store for this batch (``ok`` keeps the current one)."""
        return self.status if self.status in VERIFICATION_LEVELS else "receipts_unverified"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "first_bad": self.first_bad,
            "head": self.head,
            "count": int(self.count),
            "reason": self.reason,
        }


def _first_bad(message: str) -> Optional[int]:
    match = _BAD_INDEX.search(message or "")
    return int(match.group(1)) if match else None


def _pin_value(pin: Any) -> Optional[str]:
    if isinstance(pin, str):
        return pin
    if isinstance(pin, Mapping):
        value = pin.get("public_key") or pin.get("key")
        return value if isinstance(value, str) else None
    return None


def receipt_public_key(host: Any) -> Optional[bytes]:
    """The host's pinned Ed25519 receipt key as 32 raw bytes, or ``None``.

    Accepts the shapes the codebase already uses: a ``Host`` row or a dict
    with ``public_keys``; ``public_keys`` may be a list of pin dicts (as
    enrollment stores it) or a single dict with a ``receipt`` entry (the live
    smoke's shape). A pin marked ``use``/``kind`` ``receipt`` wins; otherwise
    the host's identity pin is the receipt key, which is what a connector
    signing receipts with its enrollment seed pins.
    """
    if isinstance(host, Mapping):
        pins = host.get("public_keys")
    else:
        pins = getattr(host, "public_keys", None)
    value: Optional[str] = None
    if isinstance(pins, Mapping):
        value = pins.get("receipt") or pins.get("host")
    elif isinstance(pins, Sequence) and not isinstance(pins, (str, bytes)):
        preferred = None
        for pin in pins:
            if isinstance(pin, Mapping) and (
                pin.get("use") == "receipt" or pin.get("kind") == "receipt"
            ):
                preferred = _pin_value(pin)
                break
        value = preferred or (_pin_value(pins[0]) if pins else None)
    if not isinstance(value, str) or len(value) != KEY_SIZE * 2:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw if len(raw) == KEY_SIZE else None


def _looks_ed25519(chain: Sequence[Receipt]) -> bool:
    """True when every mac is a hex Ed25519 signature, not an HMAC tag.

    ``interlock.receipt`` writes the tag as hex: 64 characters for HMAC-SHA256
    and 128 for an Ed25519 signature. A chain that claims a pinned receipt key
    but carries 64-character tags was signed with the HMAC default, so it must
    take the linkage-only path - the plane must not pretend a shared-secret
    MAC is a public-key signature.
    """
    if not chain:
        return False
    for receipt in chain:
        tag = receipt.mac or ""
        if len(tag) != KEY_SIZE * 4:
            return False
        try:
            bytes.fromhex(tag)
        except ValueError:
            return False
    return True


def canonical_checkpoint(doc: Mapping[str, Any]) -> bytes:
    """The exact bytes a checkpoint's signature covers (``sig`` excluded)."""
    body = {name: doc.get(name) for name in CHECKPOINT_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_checkpoint(seed: bytes, body: Mapping[str, Any]) -> Dict[str, Any]:
    """Return ``body`` plus a hex Ed25519 ``sig`` over its canonical form."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != KEY_SIZE:
        raise ValueError("an Ed25519 seed is 32 bytes")
    doc = {name: body.get(name) for name in CHECKPOINT_FIELDS}
    doc["v"] = 1 if doc.get("v") is None else doc["v"]
    doc["sig"] = sign(bytes(seed), canonical_checkpoint(doc)).hex()
    return doc


def verify_checkpoint(
    doc: Any,
    public_key: Optional[bytes],
    *,
    host_id: Optional[str] = None,
    org_id: Optional[str] = None,
    now: Optional[float] = None,
    max_age: Optional[float] = None,
) -> Optional[str]:
    """Return ``None`` when ``doc`` is a valid checkpoint, else the failed check.

    The check names are stable for tests and logs: ``malformed``, ``version``,
    ``org``, ``host``, ``count``, ``signature`` and (when ``max_age`` is
    supplied) ``stale``. An untrusted document never raises.
    """
    if not isinstance(doc, Mapping):
        return "malformed"
    if doc.get("v") != 1:
        return "version"
    if org_id is not None and str(doc.get("org_id")) != str(org_id):
        return "org"
    if host_id is not None and str(doc.get("host_id")) != str(host_id):
        return "host"
    count = doc.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return "count"
    issued = doc.get("issued_at")
    if isinstance(issued, bool) or not isinstance(issued, (int, float)):
        return "issued_at"
    head_mac = doc.get("head_mac")
    if not isinstance(head_mac, str) or not head_mac:
        return "head_mac"
    if public_key is None or len(public_key) != KEY_SIZE:
        return "key"
    signature = doc.get("sig")
    if not isinstance(signature, str):
        return "signature"
    try:
        tag = bytes.fromhex(signature)
    except ValueError:
        return "signature"
    if not verify(public_key, canonical_checkpoint(doc), tag):
        return "signature"
    if max_age is not None and now is not None:
        if float(now) - float(issued) > float(max_age):
            return "stale"
    return None


def _valid_checkpoints(
    checkpoints: Optional[Iterable[Any]],
    public_key: Optional[bytes],
    *,
    host_id: Optional[str],
    org_id: Optional[str],
) -> List[Dict[str, Any]]:
    valid: List[Dict[str, Any]] = []
    for doc in checkpoints or ():
        if verify_checkpoint(doc, public_key, host_id=host_id, org_id=org_id) is None:
            valid.append(dict(doc))
    return valid


def _level_for_linkage(
    checkpoints: Optional[Iterable[Any]],
    public_key: Optional[bytes],
    *,
    host_id: Optional[str],
    org_id: Optional[str],
    first_prev: str,
    now: float,
) -> str:
    """The verification level for a chain whose macs cannot be recomputed.

    With no signed checkpoint the chain is still ``linkage_only`` - it is
    linked, just not attested yet. A newest checkpoint older than
    :data:`CHECKPOINT_MAX_AGE` means the host stopped attesting and the chain
    is ``receipts_unverified`` (FR-035). A checkpoint that does not name the
    stored head is not evidence for this batch and is treated as absent.
    """
    valid = _valid_checkpoints(checkpoints, public_key,
                               host_id=host_id, org_id=org_id)
    covering = [doc for doc in valid
                if str(doc.get("head_mac")) == str(first_prev)]
    if not covering:
        return "linkage_only"
    newest = max(float(doc.get("issued_at") or 0.0) for doc in covering)
    if float(now) - newest > CHECKPOINT_MAX_AGE:
        return "receipts_unverified"
    return "linkage_only"


def _as_receipts(items: Iterable[Any]) -> List[Receipt]:
    out: List[Receipt] = []
    for item in items:
        if isinstance(item, Receipt):
            out.append(item)
        elif isinstance(item, Mapping):
            out.append(Receipt(**dict(item)))
        else:  # pragma: no cover - callers pass Receipts or their fields
            raise TypeError("a receipt must be a Receipt or a mapping")
    return out


def verify_batch(
    receipts: Iterable[Any],
    *,
    host: Any,
    previous_head: Optional[str] = None,
    checkpoints: Optional[Iterable[Any]] = None,
    now: float = 0.0,
    previous_count: int = 0,
    known_macs: Optional[Iterable[str]] = None,
    host_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> BatchResult:
    """Verify one batch against the stored chain head.

    ``previous_head`` is the stored head (``None`` or ``GENESIS`` for a new
    chain); ``checkpoints`` are the host's stored checkpoint documents;
    ``known_macs`` are the macs already stored, used only to recognise an
    exact replay (a retried batch), which is ``ok`` and does not move the
    head. Everything else that does not continue the head is a ``fork``.
    """
    chain = _as_receipts(receipts)
    head = GENESIS if previous_head is None else str(previous_head)
    count = int(previous_count or 0)
    if not chain:
        return BatchResult("ok", None, head, count, "empty batch")

    if chain[0].prev != head:
        macs = [receipt.mac for receipt in chain]
        if known_macs is not None and set(macs) <= set(known_macs):
            return BatchResult("ok", None, head, count, "duplicate replay")
        return BatchResult(
            "fork", 0, head, count,
            "receipt 0: chain break (prev does not match the stored head)",
        )

    public_key = receipt_public_key(host)
    if public_key is not None and _looks_ed25519(chain):
        problem = verify_chain(
            chain, None, b"",
            verifier=ed25519_verifier(public_key),
            start_prev=head,
        )
        if problem is not None:
            return BatchResult("fork", _first_bad(problem), head, count, problem)
        return BatchResult("verified", None, chain[-1].mac, count + len(chain))

    # HMAC host: the mac cannot be recomputed without the host secret, so only
    # the prev linkage is checked. The chain is linked, not signed.
    expected = head
    for index, receipt in enumerate(chain):
        if receipt.prev != expected:
            return BatchResult(
                "fork", index, head, count,
                "receipt {}: chain break (prev does not match the stored head)".format(index),
            )
        expected = receipt.mac
    level = _level_for_linkage(
        checkpoints, _checkpoint_key(host), host_id=host_id, org_id=org_id,
        first_prev=head, now=float(now),
    )
    return BatchResult(level, None, chain[-1].mac, count + len(chain))


def _checkpoint_key(host: Any) -> Optional[bytes]:
    """The key that must sign a checkpoint.

    A host that signs receipts with Ed25519 uses that same pinned key. An HMAC
    host has no receipt key, so the enrollment identity pin is what it signs a
    checkpoint with - the only public key the plane ever received from it.
    """
    return receipt_public_key(host)


def verify_export(
    receipts: Iterable[Any],
    *,
    host: Any,
    start_prev: Optional[str] = None,
) -> Optional[str]:
    """Walk an exported chain; ``None`` when intact, else the first break.

    The export starts wherever retention left the chain, so ``start_prev`` is
    the first retained receipt's ``prev`` (default: :data:`GENESIS`). Ed25519
    hosts get every signature checked; HMAC hosts get linkage only, exactly as
    ingest did.
    """
    chain = _as_receipts(receipts)
    if not chain:
        return None
    public_key = receipt_public_key(host)
    if public_key is not None and _looks_ed25519(chain):
        return verify_chain(
            chain, None, b"",
            verifier=ed25519_verifier(public_key),
            start_prev=GENESIS if start_prev is None else start_prev,
        )
    expected = GENESIS if start_prev is None else start_prev
    for index, receipt in enumerate(chain):
        if receipt.prev != expected:
            return "receipt {}: chain break (prev does not match the preceding receipt's mac)".format(
                index
            )
        expected = receipt.mac
    return None


__all__ = [
    "BATCH_STATUSES",
    "CHECKPOINT_FIELDS",
    "CHECKPOINT_MAX_AGE",
    "VERIFICATION_LEVELS",
    "BatchResult",
    "canonical_checkpoint",
    "receipt_public_key",
    "sign_checkpoint",
    "verify_batch",
    "verify_checkpoint",
    "verify_export",
]
