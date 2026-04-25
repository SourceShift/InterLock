"""Per-event content digest stamp: attach a plain SHA-256 fingerprint of an
event's action and arguments so downstream storage can detect after-the-fact
edits and attribute each record to the exact content that was captured.

This is the content-integrity half of provenance. An HMAC stamp (see
``event_hmac_stamp``) additionally proves *who* captured the event, because only
a holder of the secret can produce the value. A plain digest proves only that the
content has not changed since the stamp was written: anyone can recompute it, but
any edit to the args invalidates it. When no shared secret is available - or when
attribution is handled elsewhere - this gives a cheap, dependency-free
tamper-evident fingerprint.

This is the MODIFY point of the allow/modify/block spectrum. The event is not
suspect - every event is fingerprinted - so the rule does not block; it attaches
a computed field (``__digest__``) to the args and lets the event proceed to
storage or the next rule. The engine merges the returned keys over the original
args.

The digested message is ``repr((action, sorted((k, str(v)) ...)))``: the action
name plus every argument pair except keys beginning with ``__``, sorted so dict
iteration order cannot change the result. Excluding the stamp field (and any
other dunder key) from the message is what makes the rule idempotent -
re-stamping a correctly stamped event recomputes the same digest, so it returns
None instead of looping.

Follows the detector robustness rule: a non-dict ``args``, a key set that cannot
be ordered, or any other oddity yields None (no opinion) rather than an
exception. Values it cannot render are stringified, never inspected, so nested
containers and ints are harmless. The rule never raises.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "content_digest"

# The arg key the computed digest is written under.
FIELD = "__digest__"

# Default secret. The plain digest is unkeyed, so this value is unused; it is
# kept so the factory signature matches the other stamp rules. Pass a per-holder
# secret to ``event_hmac_stamp`` instead when attribution is required.
DEFAULT_SECRET = b"interlock"


def _digest(event: SensorEvent) -> Optional[str]:
    """Compute the content digest for ``event``, or None if it cannot be hashed.

    None is returned for a non-dict ``args`` or a key set whose ``(key, value)``
    pairs will not sort (e.g. mixed str/int keys) - the rule skips what it cannot
    digest rather than crashing.
    """
    args = getattr(event, "args", None)
    if not isinstance(args, dict):
        return None

    try:
        pairs = sorted(
            (key, str(value))
            for key, value in args.items()
            if not key.startswith("__")
        )
        message = repr((getattr(event, "action", None), pairs)).encode()
        return hashlib.sha256(message).hexdigest()
    except Exception:
        # Unorderable keys, a key with no stable repr, or any other oddity: this
        # event cannot be digested, so the rule has no opinion on it.
        return None


def content_digest_stamp(secret: bytes = DEFAULT_SECRET) -> Rule:
    """Build a Rule that stamps every event's args with a SHA-256 content digest.

    For an event with a dict ``args``, the rule returns a MODIFY carrying
    ``{FIELD: <digest>}`` keyed on ``POLICY_ID``. If the event already carries the
    correct digest - the recomputed value matches the stored one - it returns
    None, so re-evaluating an in-flight event is a no-op. A wrong or stale digest
    is overwritten with the correct one. A non-dict ``args`` or an unorderable
    key set returns None: nothing to stamp.
    """
    del secret  # unused: the digest is unkeyed; kept for signature uniformity

    def rule(event: SensorEvent) -> Optional[Decision]:
        computed = _digest(event)
        if computed is None:
            return None

        existing = event.args.get(FIELD)
        if existing == computed:
            return None

        return Decision.modify(
            {FIELD: computed}, reason=POLICY_ID, policy_id=POLICY_ID
        )

    return rule
