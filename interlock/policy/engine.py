"""The policy engine and its evaluate() contract.

M0 evaluates an ordered list of Python-function rules. This is the seam that
later milestones replace: M2 loads declarative YAML/JSON policies with a safe
condition evaluator, M6 swaps in a Rust core over ctypes. The evaluate()
signature stays identical, so nothing above it changes.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Dict, List, Optional

from ..enforce import Decision, Verdict
from ..event import SensorEvent, result_payload

# A rule returns a Decision if it has an opinion, else None (no opinion).
Rule = Callable[[SensorEvent], Optional[Decision]]


class PolicyEngine:
    def __init__(self, rules: Optional[List[Rule]] = None):
        self._rules: List[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> "PolicyEngine":
        self._rules.append(rule)
        return self

    def __len__(self) -> int:
        """How many rules are installed.

        Public because "is this engine empty?" is a safety question, not an
        implementation detail: an empty engine allows everything, so a component
        that must not run unguarded (the sidecar daemon) asks this instead of
        reaching into ``_rules``.
        """
        return len(self._rules)

    def evaluate(self, event: SensorEvent) -> Decision:
        """Combine every rule's opinion on one event. Default: allow.

        A BLOCK from any rule wins and ends evaluation. A MODIFY does *not* end
        it: the rewrite is applied to a working copy of the event and the
        remaining rules judge the rewritten call (or result). Stopping at the
        first MODIFY used to let a rewrite placed before a block skip the block
        entirely - redaction in front of an egress allowlist sent the masked
        payload to the attacker's host. Several rewrites compose in rule order;
        a later rewrite of the same argument wins. The caller's event is never
        mutated.

        The result is ALLOW, the BLOCK, or one MODIFY: the rule's own decision
        when it was the only rewrite, otherwise a combined decision carrying
        every change (``modified_args`` merged, or the final
        ``modified_result``), the reasons joined with ``"; "``, and the first
        rewrite's ``policy_id`` and ``attributed_to``.

        Phase separation: a rule tagged ``phase="result"`` (set the attribute
        on the callable) sees only result-phase events; an untagged rule is
        call-side - the side every existing rule was written for - and sees
        only call-phase events. A call-side rule therefore never re-judges a
        result payload under the same action name, and a result-side rule
        never fires on the arguments being sent.
        """
        is_result = getattr(event, "phase", "call") == "result"
        working = event
        rewrites: List[Decision] = []
        merged_args: Dict[str, Any] = {}
        final_result: Any = None
        replaced_result = False
        for rule in self._rules:
            if (getattr(rule, "phase", "call") == "result") != is_result:
                continue
            decision = rule(working)
            if decision is None or decision.verdict == Verdict.ALLOW:
                continue
            if decision.verdict != Verdict.MODIFY:
                return decision
            rewrites.append(decision)
            if is_result:
                if decision.modified_result is not None:
                    final_result = decision.modified_result
                    replaced_result = True
                    working = replace(working, args=result_payload(final_result))
            elif decision.modified_args:
                merged_args.update(decision.modified_args)
                working = replace(working, args={**working.args, **decision.modified_args})
        if not rewrites:
            return Decision.allow()
        if len(rewrites) == 1:
            return rewrites[0]
        first = rewrites[0]
        return Decision(
            verdict=Verdict.MODIFY,
            reason="; ".join(d.reason for d in rewrites if d.reason),
            policy_id=first.policy_id,
            modified_args=merged_args or None,
            attributed_to=first.attributed_to,
            modified_result=final_result if replaced_result else None,
        )


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
