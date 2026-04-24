"""The policy engine and its evaluate() contract.

M0 evaluates an ordered list of Python-function rules. This is the seam that
later milestones replace: M2 loads declarative YAML/JSON policies with a safe
condition evaluator, M6 swaps in a Rust core over ctypes. The evaluate()
signature stays identical, so nothing above it changes.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from ..enforce import Decision, Verdict
from ..event import SensorEvent

# A rule returns a Decision if it has an opinion, else None (no opinion).
Rule = Callable[[SensorEvent], Optional[Decision]]


class PolicyEngine:
    def __init__(self, rules: Optional[List[Rule]] = None):
        self._rules: List[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> "PolicyEngine":
        self._rules.append(rule)
        return self

    def evaluate(self, event: SensorEvent) -> Decision:
        """First rule to return a non-ALLOW verdict wins. Default: allow."""
        for rule in self._rules:
            decision = rule(event)
            if decision is not None and decision.verdict != Verdict.ALLOW:
                return decision
        return Decision.allow()


def deny_tool(
    name: str, reason: str = "tool not permitted", policy_id: Optional[str] = None
) -> Rule:
    """Rule: deny any call to the named tool."""

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action == name:
            return Decision.block(reason, policy_id)
        return None

    return rule


def deny_when(
    predicate: Callable[[SensorEvent], bool],
    reason: str,
    policy_id: Optional[str] = None,
) -> Rule:
    """Rule: deny when predicate(event) is true. Fail-closed: a predicate that
    raises is treated as a match and denies, it does not silently allow.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        try:
            hit = predicate(event)
        except Exception as exc:  # fail-closed
            return Decision.block(
                "rule error, denied fail-closed: {} ({})".format(reason, exc),
                policy_id,
            )
        return Decision.block(reason, policy_id) if hit else None

    return rule
