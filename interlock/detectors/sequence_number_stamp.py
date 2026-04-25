"""Monotonic per-rule sequence stamp: attach a ``__seq__`` ordinal to every
event's args so downstream storage can order, deduplicate and attribute the
events a single rule instance observed.

An ordinal that only increases in observation order is what makes a capture
stream reconstructible: if two stored records carry sequence 4 and 5, the store
knows their relative position even when wall-clock ``ts`` is missing, coarse, or
spoofed by the sensor. Because the counter lives in the rule's closure and not
in the event, an agent that forges ``ts`` cannot forge arrival order.

This is the MODIFY point of the allow/modify/block spectrum. No event is
suspect - every event is stamped - so the rule never blocks; it attaches the
computed field and lets the event proceed to storage or the next rule. The
engine merges the returned keys over the original args.

The stamp is a *content-addressed* ordinal, which is what reconciles the two
properties the stamp must have:

* **monotonic** - the first time a given ``(action, args)`` content is seen it
  receives the next integer; distinct content therefore takes strictly
  increasing values (1, 2, 3, ...) in first-observation order.
* **deterministic** - re-observing the same content returns the ordinal it was
  first assigned rather than consuming a new one, so identical events stamp
  identically no matter how many times the rule runs.

The identity of an event is ``sha256(repr((action, sorted((str(k), str(v))
...))))`` with the stamp field itself excluded. Values are stringified, never
inspected, so nested containers, ints and ``None`` are harmless, and mixed
key types cannot make the key set unorderable. Excluding ``__seq__`` from the
digest is what makes the rule idempotent - re-stamping a correctly stamped event
recomputes the same ordinal and returns None instead of advancing the counter.

The sequence is per rule instance: two rules built by two calls to
``sequence_number_stamp()`` each start at 0 and count independently, so the
stamp is attributable to the producing rule rather than to a process-global
clock. The ``secret`` parameter is accepted for interface uniformity with the
sibling provenance annotators but is unused - the ordinal is not keyed.

Follows the detector robustness rule: a non-dict ``args`` (nowhere to write the
stamp) or a value whose ``repr`` raises yields None - no opinion - rather than
an exception. The rule never raises.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "sequence_stamp"

# The arg key the computed ordinal is written under.
FIELD = "__seq__"

# Default (unused) secret. The ordinal is a sequence number, not a keyed
# signature, so no secret is mixed in; the parameter exists so this factory
# matches the sibling provenance annotators' call shape.
DEFAULT_SECRET = b"interlock"


def _content_key(event: SensorEvent) -> Optional[str]:
    """Return a stable digest identifying ``event``'s content, or None.

    None is returned for a non-dict ``args`` (nowhere to attach the stamp) or a
    value whose ``repr`` raises - the rule skips what it cannot fingerprint
    rather than crashing. Keys and values are stringified so mixed types cannot
    make the pairs unorderable.
    """
    args = getattr(event, "args", None)
    if not isinstance(args, dict):
        return None

    try:
        pairs = sorted(
            (str(key), str(value)) for key, value in args.items() if key != FIELD
        )
        raw = repr((getattr(event, "action", None), pairs)).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        # A value whose __repr__ raises, or any other oddity: this event cannot
        # be fingerprinted, so the rule has no opinion on it.
        return None


def _carries_correct(existing: object, value: int) -> bool:
    """True if ``existing`` is already the sequence number ``value``.

    ``bool`` is excluded because ``True == 1`` in Python; a boolean stored under
    the stamp field is a forged value, not the ordinal 1.
    """
    return isinstance(existing, int) and not isinstance(existing, bool) and existing == value


def sequence_number_stamp(secret: bytes = DEFAULT_SECRET) -> Rule:
    """Build a Rule that stamps every event's args with a monotonic sequence number.

    For an event with a dict ``args``, the rule returns a MODIFY carrying
    ``{FIELD: <int>}`` keyed on ``POLICY_ID``. New content receives the next
    ordinal; content the rule has already seen receives the ordinal it was first
    assigned, so the same event stamps identically every time. If the event
    already carries the correct ordinal it returns None, so re-evaluating an
    in-flight event is a no-op; a stale or forged value is overwritten. A
    non-dict ``args`` returns None: nowhere to stamp.
    """

    # Accepted for interface uniformity with the sibling provenance annotators;
    # a sequence number is not keyed, so no secret is mixed into it.
    del secret

    counter = 0
    # Content digest -> the ordinal assigned the first time that content was seen.
    assigned: dict = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        nonlocal counter

        key = _content_key(event)
        if key is None:
            return None

        existing = event.args.get(FIELD)

        if key in assigned:
            value = assigned[key]
            if _carries_correct(existing, value):
                return None
            return Decision.modify(
                {FIELD: value}, reason=POLICY_ID, policy_id=POLICY_ID
            )

        # Content not seen before: it would take the next ordinal.
        candidate = counter + 1
        if _carries_correct(existing, candidate):
            # Already carries the ordinal it would receive: nothing to add, and
            # the counter is not advanced for a stamp that was not written.
            return None

        counter = candidate
        assigned[key] = candidate
        return Decision.modify(
            {FIELD: candidate}, reason=POLICY_ID, policy_id=POLICY_ID
        )

    return rule
