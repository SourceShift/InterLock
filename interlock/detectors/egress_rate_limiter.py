"""Per-principal egress rate limiter: cap outbound calls per principal.

Destination allowlists answer "may data go *here*?"; payload redaction answers
"what may be in it?". Neither answers "how *much* may this principal send?" - so
an agent with a legitimate allowlisted host can still stream data out at
machine speed, and every individual call looks fine. The volume is the signal.

This Rule counts egress actions (``http_post``/``fetch``/``send``/``upload``) per
``event.principal`` in this process and, once a principal has made more than
``limit`` such calls, blocks every further one. The principal is the right axis
because a rate is a property of the actor, not of the destination: two agents
posting to the same host should not share one budget, and one agent spreading
its calls across many hosts should not escape the cap.

The boundary is inclusive at the limit: with ``limit=20`` the twentieth call
still passes and the twenty-first is refused, so a limit of N reads as "up to N
egress calls are covered".

Only egress actions are counted; every other action returns None without
touching the counter, so an in-process tool call never spends egress budget.
State is local to the closure, so two rules built from separate factory calls
never share a tally. An event whose principal is not a string has no stable key
to count under and is skipped rather than counted - the rule returns None and
never raises, even when fields are absent or hostile.

Out of scope, left to other rules: deciding which destinations are legitimate
(an allowlist) and what the right N is. This rule counts what it is shown.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "egress_rate"

# Actions that send data off the process and therefore spend egress budget.
DEFAULT_EGRESS_ACTIONS = frozenset({"http_post", "fetch", "send", "upload"})


def egress_rate_limiter(
    limit: int = 20,
) -> Rule:
    """Rule: block once a principal exceeds `limit` egress calls.

    Each call to the factory owns a fresh per-principal counter, so limits are
    independent across rules. Returns None (no opinion) while a principal's
    running egress count is <= limit, and a BLOCK Decision once it exceeds it.
    Non-egress actions are ignored and do not consume budget; an event whose
    principal is not a string is skipped.
    """
    counts: Dict[str, int] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action not in DEFAULT_EGRESS_ACTIONS:
            return None
        principal = event.principal
        if not isinstance(principal, str):
            return None
        counts[principal] = counts.get(principal, 0) + 1
        if counts[principal] > limit:
            return Decision.block(
                "egress_rate: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
