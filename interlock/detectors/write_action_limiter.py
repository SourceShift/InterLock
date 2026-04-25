"""Per-principal write/mutation budget: cap state-changing actions per principal.

``call_rate_limiter`` counts *every* call a principal makes, so a busy reader
can exhaust an agent's allowance without ever changing a byte of state. What a
budget usually wants to bound is the opposite: how much the agent *mutates*.
Writes, deletes, updates and creates are the actions with irreversible effects
and real cost - a runaway agent renaming files in a loop is a different failure
from one reading them in a loop.

This Rule counts only mutating actions (``action`` starting with ``write``,
``delete``, ``update`` or ``create``) and keys the tally by ``event.principal``.
Non-mutating actions return None without touching the counter, so a principal's
budget is spent only by the actions that consume it. Once a principal's running
count exceeds ``limit`` the rule returns a BLOCK Decision; the boundary is
inclusive at the limit, matching how operators read "N writes allowed": with
``limit=2`` the second write still passes and the third is refused.

The counter lives in the closure, so each factory call owns fresh state and two
rules cannot trip each other. An event whose action is missing or not a string
is not recognised as mutating and is skipped, so odd input never raises.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "write_budget"

# Identity used when an event carries no usable principal. A subject we cannot
# name is still budgeted, so it cannot escape the limit by staying anonymous.
ANON = "<anon>"

DEFAULT_LIMIT = 30

# Action-name prefixes that mark a state-changing operation. Matched
# case-insensitively against the start of the action.
MUTATING_PREFIXES = ("write", "delete", "update", "create")


def _is_mutating(action: object) -> bool:
    """True when *action* names a state-changing operation.

    Returns False for anything that is not a string so an unreadable event is
    skipped rather than counted or raised on.
    """
    if not isinstance(action, str):
        return False
    lowered = action.lower()
    return lowered.startswith(MUTATING_PREFIXES)


def write_action_limiter(limit: int = DEFAULT_LIMIT) -> Rule:
    """Rule: block once one principal's mutating-action count exceeds *limit*.

    Only actions whose name starts with write/delete/update/create are counted;
    every other action returns None without spending budget. The count is keyed
    by ``event.principal`` (falling back to ``"<anon>"`` when it is None or not
    a string). While a key's running count is <= *limit* the rule returns None;
    once it is strictly greater it returns a BLOCK Decision. Each call to this
    factory returns a Rule with its own fresh counter.
    """
    counts: Dict[str, int] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = getattr(event, "action", None)
        if not _is_mutating(action):
            return None

        principal = getattr(event, "principal", None)
        if not isinstance(principal, str):
            principal = ANON

        counts[principal] = counts.get(principal, 0) + 1
        if counts[principal] > limit:
            return Decision.block(
                reason="write_budget: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
