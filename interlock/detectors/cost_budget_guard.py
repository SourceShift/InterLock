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

import math
import threading
from typing import Optional, Union

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "cost_budget"

DEFAULT_BUDGET = 10.0

# Argument key carrying the numeric cost of this event.
COST_KEY = "cost"


class _MalformedCost:
    """A numeric cost the guard refuses to add: NaN, infinite, negative, huge."""

    __slots__ = ("value",)

    def __init__(self, value: Union[int, float]) -> None:
        self.value = value


def _event_cost(args: object) -> Union[float, _MalformedCost]:
    """The numeric cost to charge for *args*, or a malformed-cost marker.

    A non-dict ``args``, a missing key, ``None``, a string, and a bool all count
    as zero rather than being coerced - ``True``/``False`` are ``int`` subclasses
    but are not meaningful costs, so they are skipped instead of stringified or
    cast. A nested container is likewise skipped.

    An ``int`` or ``float`` that is not a finite, non-negative number cannot be
    added up: NaN and infinities poison every later comparison, a negative cost
    refunds real spend, and an integer too large for a float cannot be
    represented at all. Those come back as :class:`_MalformedCost` so the rule
    can refuse the event without touching the running total.
    """
    if not isinstance(args, dict):
        return 0.0
    value = args.get(COST_KEY)
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, float):
        if not math.isfinite(value):
            return _MalformedCost(value)
        cost = value
    elif isinstance(value, int):
        try:
            cost = float(value)
        except OverflowError:
            return _MalformedCost(value)
    else:
        return 0.0
    if cost < 0:
        return _MalformedCost(value)
    return cost


def cost_budget_guard(budget: float = DEFAULT_BUDGET) -> Rule:
    """Build a Rule that blocks once accumulated cost exceeds *budget*.

    Each event's numeric ``args["cost"]`` is added to a running total kept in
    this closure. When the total after adding is strictly greater than *budget*
    the rule returns a BLOCK naming the budget; otherwise (including a
    non-numeric or missing cost, which adds 0) it returns None. Each call to
    this factory returns a Rule with its own fresh total.

    A numeric cost that is NaN, infinite, negative, or too large to represent
    is refused with a BLOCK naming the value, and the total is left untouched,
    so honest prior spend still judges later events. *budget* must itself be a
    finite, non-negative number; anything else raises ``ValueError`` at
    construction. The total is updated under a per-rule lock, so concurrent
    calls cannot lose a charge.
    """
    if isinstance(budget, bool) or not isinstance(budget, (int, float)):
        raise ValueError("budget must be a finite non-negative number")
    try:
        budget_is_finite = math.isfinite(budget)
    except OverflowError:
        budget_is_finite = False
    if not budget_is_finite or budget < 0:
        raise ValueError("budget must be a finite non-negative number")

    total = 0.0
    lock = threading.Lock()

    def rule(event: SensorEvent) -> Optional[Decision]:
        nonlocal total
        cost = _event_cost(getattr(event, "args", None))
        if isinstance(cost, _MalformedCost):
            return Decision.block(
                reason="cost_budget_guard: malformed cost {!r} (policy {})".format(
                    cost.value, POLICY_ID
                ),
                policy_id=POLICY_ID,
            )
        with lock:
            total += cost
            over_budget = total > budget
        if over_budget:
            return Decision.block(
                reason="cost_budget_guard: budget {} exceeded".format(budget),
                policy_id=POLICY_ID,
            )
        return None

    return rule
