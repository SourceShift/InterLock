"""Provenance origin tagging: attach a computed ``__provenance__`` field recording
*who* did *what*, *when*, so a downstream store can attribute each event.

Attribution is a precondition for accountability. If a record reaches storage with
no statement of the principal that produced it, the action and the capture time,
then a later audit cannot say who caused an entry or whether it was replayed under
a different identity. The tag closes that gap: it binds the event's principal, its
action name, and its capture timestamp into one value that travels with the args.

This is the MODIFY point of the allow/modify/block spectrum. No event is suspect -
every event is tagged - so the rule never blocks. It attaches its field and lets the
event proceed to storage or the next rule; the engine merges the returned keys over
the original args. There is no secret to key the tag (it is a plain origin label,
not a signature), but the ``secret`` parameter is kept for interface uniformity with
the other provenance annotators.

The value is ``str(principal) + "|" + action + "|" + str(int(ts))``. It is derived
from the event's *envelope*, never from ``args``, so nested containers and non-string
values cannot change or destabilize it. Idempotency comes from recomputing the value
and comparing it to the stored one: a correctly tagged event yields None (no work to
do), while a missing or stale tag is (re)written.

Follows the detector robustness rule: a non-dict ``args`` (nowhere to write the tag)
or a ``ts`` that cannot be read as an integer yields None - no opinion - rather than
an exception. The rule never raises.
"""
from __future__ import annotations

from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "provenance_tag"

# The arg key the computed tag is written under.
FIELD = "__provenance__"

# Default (unused) secret. The tag is an origin label, not a keyed signature, so no
# secret is mixed in; the parameter exists so this factory matches the sibling
# provenance annotators' call shape.
DEFAULT_SECRET = b"interlock"


def _tag(event: SensorEvent) -> Optional[str]:
    """Compute the origin tag for ``event``, or None if it cannot be computed.

    None is returned for a non-dict ``args`` (there is nowhere to attach the tag)
    or a ``ts`` that cannot be read as an integer - the rule skips what it cannot
    handle rather than crashing.
    """
    args = getattr(event, "args", None)
    if not isinstance(args, dict):
        return None

    try:
        captured = int(getattr(event, "ts"))
        return "{}|{}|{}".format(
            getattr(event, "principal", None),
            getattr(event, "action", None),
            captured,
        )
    except Exception:
        # ts is None, a non-numeric string, or otherwise unreadable: this event
        # cannot be attributed, so the rule has no opinion on it.
        return None


def provenance_origin_tag(secret: bytes = DEFAULT_SECRET) -> Rule:
    """Build a Rule that tags every event's args with its provenance origin.

    For an event with a dict ``args`` and a readable ``ts``, the rule returns a
    MODIFY carrying ``{FIELD: <principal|action|ts>}`` keyed on ``POLICY_ID``. If
    the event already carries the correct tag it returns None, so re-evaluating an
    in-flight event is a no-op. A stale or wrong tag is overwritten with the correct
    one. A non-dict ``args`` or an unreadable ``ts`` returns None: nothing to tag.
    """

    # Accepted for interface uniformity with the sibling provenance annotators;
    # an origin label is not keyed, so no secret is mixed into the tag.
    del secret

    def rule(event: SensorEvent) -> Optional[Decision]:
        computed = _tag(event)
        if computed is None:
            return None

        existing = event.args.get(FIELD)
        if existing == computed:
            return None

        return Decision.modify(
            {FIELD: computed}, reason=POLICY_ID, policy_id=POLICY_ID
        )

    return rule
