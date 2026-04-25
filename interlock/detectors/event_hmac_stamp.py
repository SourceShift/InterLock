"""Per-event HMAC integrity stamp: sign an event's arguments so storage can prove
they were not altered after capture, and attribute each event to a holder of the
secret.

A plain hash of the arguments proves nothing: an attacker who rewrites the args
recomputes the hash just as easily. An HMAC keyed with a secret only the sensor
holds does prove something - a stamped event could only have been produced by a
party that knows the secret, and any later edit to the args invalidates the
stamp. That is the provenance property: tamper-evident and attributable.

This is the MODIFY point of the allow/modify/block spectrum. The event is not
suspect - every event is signed - so the rule does not block; it attaches a
computed field (``__hmac__``) to the args and lets the event proceed to storage
or the next rule. The engine merges the returned keys over the original args.

The signed message is ``repr((action, sorted((k, str(v)) ...)))``: the action
name plus every argument key/value pair except the stamp field itself, sorted so
dict iteration order cannot change the result. Excluding ``__hmac__`` from the
message is what makes the rule idempotent - re-stamping a correctly stamped
event recomputes the same digest, so it returns None instead of looping.

Follows the detector robustness rule: a non-dict ``args``, a key set that cannot
be ordered, or any other oddity yields None (no opinion) rather than an
exception. Values it cannot render are stringified, never inspected, so nested
containers and ints are harmless. The rule never raises.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "event_hmac"

# The arg key the computed stamp is written under.
FIELD = "__hmac__"

# Default signing secret. Callers that want real tamper-evidence pass their own,
# process-private secret to event_hmac_stamp(); this default keeps the rule
# usable (and testable) out of the box.
DEFAULT_SECRET = b"interlock"


def _stamp(secret: bytes, event: SensorEvent) -> Optional[str]:
    """Compute the HMAC stamp for ``event``, or None if it cannot be signed.

    None is returned for a non-dict ``args`` or a key set whose ``(key, value)``
    pairs will not sort (e.g. mixed str/int keys) - the rule skips what it cannot
    digest rather than crashing.
    """
    args = getattr(event, "args", None)
    if not isinstance(args, dict):
        return None

    try:
        pairs = sorted(
            (key, str(value)) for key, value in args.items() if key != FIELD
        )
        message = repr((getattr(event, "action", None), pairs)).encode()
        return hmac.new(secret, msg=message, digestmod=hashlib.sha256).hexdigest()
    except Exception:
        # Unorderable keys, a key with no stable repr, or any other oddity: this
        # event cannot be signed, so the rule has no opinion on it.
        return None


def event_hmac_stamp(secret: bytes = DEFAULT_SECRET) -> Rule:
    """Build a Rule that stamps every event's args with an HMAC integrity value.

    For an event with a dict ``args``, the rule returns a MODIFY carrying
    ``{FIELD: <hmac>}`` keyed on ``POLICY_ID``. If the event already carries the
    correct stamp - the recomputed digest matches the stored one - it returns
    None, so re-evaluating an in-flight event is a no-op. A wrong or stale stamp
    is overwritten with the correct one. A non-dict ``args`` or an unorderable
    key set returns None: nothing to sign.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        computed = _stamp(secret, event)
        if computed is None:
            return None

        existing = event.args.get(FIELD)
        if existing == computed:
            return None

        return Decision.modify(
            {FIELD: computed}, reason=POLICY_ID, policy_id=POLICY_ID
        )

    return rule
