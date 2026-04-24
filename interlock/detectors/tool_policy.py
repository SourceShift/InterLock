"""Tool-call capability policy: allowlist (least privilege) and its inverse.

Two policy Rules that decide on the *action name* alone, before a tool runs.
They have opposite defaults, and that asymmetry is the whole point:

- An ALLOWLIST is fail-closed: only an explicitly permitted action passes, and
  every other action - an unknown tool, a renamed tool, a malformed event - is
  denied. This is the least-privilege posture. A new tool is off until it is
  added to the list, so the failure mode of a forgotten entry is a block, not
  an over-permission.
- A DENYLIST is fail-open: only a named action is denied and everything else
  falls through to the engine's default-allow. Use it to retire one specific
  dangerous tool without having to enumerate the whole safe set.

Both stay silent (return None) when they have no objection, leaving the
engine's default-allow path untouched for traffic the policy permits.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Set

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

ALLOWLIST_POLICY_ID = "tool_allowlist"
DENYLIST_POLICY_ID = "tool_denylist"


def _as_name_set(names: Optional[Iterable[str]]) -> Set[str]:
    """Collect str action names into a set.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the policy instead of crashing or silently widening it.
    """
    if names is None:
        return set()
    if isinstance(names, str):
        items: Iterable[Any] = (names,)
    else:
        items = names
    return {name for name in items if isinstance(name, str)}


def tool_allowlist(
    allowed: Iterable[str], reason: str = "tool not on allowlist"
) -> Rule:
    """Rule: permit only actions in `allowed`; deny everything else.

    Fail-closed by construction: the permit branch is a strict membership test,
    so a non-str or missing action can never match and is denied like any other
    unknown tool. Returns None (no opinion) only for an explicitly permitted
    action.
    """
    permitted = _as_name_set(allowed)

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = event.action
        if isinstance(action, str) and action in permitted:
            return None
        return Decision.block(reason, policy_id=ALLOWLIST_POLICY_ID)

    return rule


def tool_denylist(denied: Iterable[str], reason: str = "tool denied by policy") -> Rule:
    """Rule: deny actions in `denied`; permit everything else.

    The inverse of the allowlist: an action is blocked only when it is named.
    Anything else returns None and falls through to the engine's default-allow.
    """
    blocked = _as_name_set(denied)

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = event.action
        if isinstance(action, str) and action in blocked:
            return Decision.block(reason, policy_id=DENYLIST_POLICY_ID)
        return None

    return rule
