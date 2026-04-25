"""Cumulative cost-budget guard: block once spend exceeds a running total.

Per-call rules judge one action at a time. A single cheap call is never a
problem, so an agent - or an attacker driving one - can drain a wallet or an
API quota with any number of individually harmless calls and no per-call rule
notices. Cost is itself the signal: many small charges that sum past a budget
are a runaway loop or an economic denial-of-wallet attack, and only the total
reveals it.

This Rule accumulates the numeric ``cost`` carried on each event in this
process and blocks the event that pushes the running total strictly above
``budget``. The boundary is inclusive at the budget, matching how operators
read "spend up to N": with ``budget=1.0`` a charge landing exactly on 1.0 still
passes and the next charge over it is refused.

The total lives in the closure, so each factory call owns fresh state - two
rules built from separate ``cost_budget_guard()`` calls never share a tally and
cannot trip each other. A missing, non-numeric, or boolean cost counts as 0 and
does not advance the total. The rule returns None (no opinion) while the total
is within budget and never raises on odd input.
"""
from __future__ import annotations

from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "cost_budget"

DEFAULT_BUDGET = 10.0

# Argument key carrying the numeric cost of this event.
COST_KEY = "cost"


def _event_cost(args: object) -> float:
    """The numeric cost on *args*, or 0.0 when there is no usable number.

    A non-dict ``args``, a missing key, ``None``, a string, and a bool all count
    as zero rather than being coerced - ``True``/``False`` are ``int`` subclasses
    but are not meaningful costs, so they are skipped instead of stringified or
    cast. A nested container is likewise skipped.
    """
    if not isinstance(args, dict):
        return 0.0
    value = args.get(COST_KEY)
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def cost_budget_guard(budget: float = DEFAULT_BUDGET) -> Rule:
    """Build a Rule that blocks once accumulated cost exceeds *budget*.

    Each event's numeric ``args["cost"]`` is added to a running total kept in
    this closure. When the total after adding is strictly greater than *budget*
    the rule returns a BLOCK naming the budget; otherwise (including a
    non-numeric or missing cost, which adds 0) it returns None. Each call to
    this factory returns a Rule with its own fresh total.
    """
    total = 0.0

    def rule(event: SensorEvent) -> Optional[Decision]:
        nonlocal total
        total += _event_cost(getattr(event, "args", None))
        if total > budget:
            return Decision.block(
                reason="cost_budget_guard: budget {} exceeded".format(budget),
                policy_id=POLICY_ID,
            )
        return None

    return rule
