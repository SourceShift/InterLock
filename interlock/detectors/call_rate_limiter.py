"""Per-principal call-rate limiter: cap how many calls one principal may make.

Most rules here judge a *single* call in isolation - is this payload too big, is
this argument a secret, is this command destructive. None of them notice that the
same principal has fired ten thousand perfectly ordinary-looking calls. Rate is
itself the signal: an agent stuck in a runaway loop, or one being ridden by an
attacker to burn budget and amplify a small primitive into a large one, looks
innocent one call at a time and abuses only in aggregate.

This Rule keeps one running count per principal in this process and blocks every
call once a principal has exceeded ``limit`` calls. The boundary is inclusive at
the limit, matching how operators read "N calls allowed": with ``limit=2`` the
second call still passes and the third is refused.

The counter lives in the closure, so each factory call owns fresh state - two
rules built from separate ``call_rate_limiter()`` calls never share a tally and
cannot trip each other. The key is the event's principal, falling back to
``"<anon>"`` when it is absent or not a string, so a missing identity is still
rate-limited rather than silently exempt. The rule returns None (no opinion)
while a principal is within budget and never raises on odd input.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "call_rate"

# Identity used when an event carries no usable principal. A subject we cannot
# name is still counted, so it cannot escape the limit by staying anonymous.
ANON = "<anon>"

DEFAULT_LIMIT = 100


def call_rate_limiter(limit: int = DEFAULT_LIMIT) -> Rule:
    """Rule: block once one principal's call count exceeds *limit*.

    The count is keyed by ``event.principal`` (falling back to ``"<anon>"`` when
    it is None or not a string) and incremented on every event. While a key's
    running count is <= *limit* the rule returns None; once it is strictly
    greater it returns a BLOCK Decision. Each call to this factory returns a Rule
    with its own fresh counter.
    """
    counts: Dict[str, int] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        principal = getattr(event, "principal", None)
        if not isinstance(principal, str):
            principal = ANON

        counts[principal] = counts.get(principal, 0) + 1
        if counts[principal] > limit:
            return Decision.block(
                reason="call_rate: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
