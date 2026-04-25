"""cost_budget_guard: allow path (total within budget), block path (the charge
that overshoots), zero-cost handling, odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.cost_budget_guard import (
    POLICY_ID,
    cost_budget_guard,
)


def _event(action="charge", cost=None):
    args = {} if cost is None else {"cost": cost}
    return SensorEvent(action=action, args=args)


# --- allow path -------------------------------------------------------------


def test_charges_within_budget_return_none():
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost=0.6)) is None
    assert detector(_event(cost=0.4)) is None


def test_exactly_at_budget_returns_none():
    # Strictly greater than the budget blocks; landing exactly on it is allowed.
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost=1.0)) is None


def test_default_budget_allows_small_charges():
    detector = cost_budget_guard()
    assert detector(_event(cost=5.0)) is None
    assert detector(_event(cost=5.0)) is None


# --- block path -------------------------------------------------------------


def test_charge_over_budget_blocks():
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost=0.6)) is None
    assert detector(_event(cost=0.4)) is None

    decision = detector(_event(cost=0.1))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "budget 1.0 exceeded" in decision.reason


def test_single_charge_over_budget_blocks():
    detector = cost_budget_guard(budget=1.0)
    decision = detector(_event(cost=5.0))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_over_budget_stays_blocked():
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost=2.0)) is not None
    # The total never resets, so a further charge is still refused.
    assert detector(_event(cost=0.0)) is not None


def test_factory_calls_have_independent_totals():
    spent = cost_budget_guard(budget=1.0)
    fresh = cost_budget_guard(budget=1.0)

    assert spent(_event(cost=1.0)) is None
    # A second rule has its own total and is unaffected by the first.
    assert fresh(_event(cost=1.0)) is None
    assert spent(_event(cost=0.1)) is not None


# --- zero-cost handling -----------------------------------------------------


def test_missing_cost_adds_nothing():
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost=0.6)) is None
    # No cost key: the total stays at 0.6, leaving room under the budget.
    assert detector(_event()) is None
    assert detector(_event(cost=0.4)) is None
    assert detector(_event(cost=0.1)) is not None


def test_non_numeric_cost_counts_as_zero():
    detector = cost_budget_guard(budget=1.0)
    assert detector(_event(cost="lots")) is None
    assert detector(_event(cost=None)) is None
    assert detector(_event(cost={"nested": [1, 2]})) is None
    assert detector(_event(cost=True)) is None
    # None of the above advanced the total, so a 1.0 charge still fits.
    assert detector(_event(cost=1.0)) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = cost_budget_guard(budget=1.0)
    event = SensorEvent(action="charge", args=cast(Any, "cost=99"))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_over_budget_event():
    engine = PolicyEngine(rules=[cost_budget_guard(budget=1.0)])

    assert engine.evaluate(_event(cost=0.6)).verdict is Verdict.ALLOW
    assert engine.evaluate(_event(cost=0.4)).verdict is Verdict.ALLOW

    blocked = engine.evaluate(_event(cost=0.1))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID
