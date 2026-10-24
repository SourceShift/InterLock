"""Per-tool-name call budget: cap how many times one tool may be called.

Most rules here judge a *single* call in isolation - is this argument a secret,
is this command destructive, is this payload too large. None of them notice that
one particular tool has been invoked a hundred times when the task only ever
needed three. Volume against a single tool is itself the signal: a runaway loop
retrying a flaky call, or an attacker given a narrow primitive and riding it to
turn a small foothold into a large effect, looks perfectly ordinary one call at
a time and abuses only in aggregate.

This Rule keeps one running count per action name in this process and blocks
every further call to a tool once that tool has been seen more than ``limit``
times. The boundary is inclusive at the limit, matching how operators read "N
calls allowed": with ``limit=2`` the second call still passes and the third is
refused.

The counter lives in the closure, so every factory call owns fresh state - two
rules built from separate ``tool_budget_limiter()`` calls never share a tally
and cannot trip each other. Keying is by ``event.action``: each tool gets its
own budget, so one loud tool does not spend another's. The rule returns None
(no opinion) while a tool is within budget, and never raises on odd input - an
event whose action is not a string has no name to key on and is skipped.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "tool_budget"

DEFAULT_LIMIT = 50


def tool_budget_limiter(limit: int = DEFAULT_LIMIT) -> Rule:
    """Rule: block once one tool name has been called more than *limit* times.

    The count is keyed by ``event.action`` and incremented on every event whose
    action is a string. While a tool's running count is <= *limit* the rule
    returns None; once it is strictly greater it returns a BLOCK Decision. Each
    call to this factory returns a Rule with its own fresh counter. *limit*
    must be a positive non-bool integer; anything else raises ``ValueError`` at
    construction. The counter is incremented under a per-rule lock, so
    concurrent calls cannot lose a count.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    counts: Dict[str, int] = {}
    lock = threading.Lock()

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = getattr(event, "action", None)
        if not isinstance(action, str):
            return None

        with lock:
            counts[action] = counts.get(action, 0) + 1
            over_limit = counts[action] > limit
        if over_limit:
            return Decision.block(
                reason="tool_budget: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
