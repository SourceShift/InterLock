"""MCP high-risk tool consent budget: block past N uses in a session.

A one-time approval is not the same as a standing licence. An operator may
consent to a high-risk MCP tool - a shell, a payments call, a data export -
for a handful of genuinely intended uses, and that yes should not silently
become an unbounded grant. Nothing about the *first* call is suspicious; it is
the tenth that has drifted away from the decision that authorised it.

This Rule makes the approval a budget. It keeps a running count per action
name in this process ("session"), and once a key has been seen more than
``limit`` times it blocks every further call until the operator re-approves
(typically by re-installing the rule with a fresh budget, or by raising the
limit). The counter is stateful but local to the closure: two rules built from
separate factory calls never share a tally, so one tool's spend cannot trip
another's.

The boundary is deliberately inclusive at the limit: with ``limit=3`` the
third call still passes and the fourth is refused. A limit of N therefore means
"up to N uses are covered by the approval", which is how an operator reads it.

Out of scope, and left to other rules: deciding *which* tools are high-risk
(that is a policy/allowlist concern) and what the right N is. This rule counts
what it is shown. An event whose action is not a string has no name to key on,
so it is skipped rather than counted - the rule returns None and never raises,
even when args are absent or hostile.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_consent_budget"


def mcp_consent_budget(limit: int = 3) -> Rule:
    """Rule: block once an action has been used more than `limit` times.

    Each call to the factory owns a fresh counter, so budgets are independent
    across rules. Returns None (no opinion) while the running count for the
    event's action is <= limit, and a BLOCK Decision once it exceeds it. An
    event with a non-str action is ignored.
    """
    counts: Dict[str, int] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = event.action
        if not isinstance(action, str):
            return None
        counts[action] = counts.get(action, 0) + 1
        if counts[action] > limit:
            return Decision.block(
                "mcp_consent_budget: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
