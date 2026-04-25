"""failed_auth_lockout: allow path (under limit), block path (over limit),
per-principal keying, selective counting, state isolation, odd-input safety,
and engine integration."""
from typing import Any, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.failed_auth_lockout import (
    ANON,
    POLICY_ID,
    failed_auth_lockout,
)


def _failed(principal: Any = "agent-1", args=None):
    return SensorEvent(action="auth", args=args if args is not None else {"ok": False}, principal=principal)


# --- allow path -------------------------------------------------------------


def test_failures_within_limit_return_none():
    rule = failed_auth_lockout(limit=2)
    assert rule(_failed()) is None  # 1st failure
    assert rule(_failed()) is None  # 2nd failure, still within budget


def test_limit_is_inclusive_at_the_boundary():
    # The Nth failure passes; only the (N+1)th is refused.
    rule = failed_auth_lockout(limit=1)
    assert rule(_failed()) is None


def test_successful_auth_never_counts_or_blocks():
    rule = failed_auth_lockout(limit=1)
    assert rule(SensorEvent(action="auth", args={"ok": True}, principal="a")) is None
    assert rule(SensorEvent(action="auth", args={"ok": True}, principal="a")) is None
    # A success did not spend the budget: the first real failure still passes.
    assert rule(_failed(principal="a")) is None


def test_unrelated_actions_return_none_and_do_not_count():
    rule = failed_auth_lockout(limit=1)
    assert rule(SensorEvent(action="run_tool", args={}, principal="a")) is None
    assert rule(SensorEvent(action="run_tool", args={}, principal="a")) is None
    # None of the above were failures, so the first failure is still allowed.
    assert rule(_failed(principal="a")) is None


# --- block path -------------------------------------------------------------


def test_failure_over_limit_blocks():
    rule = failed_auth_lockout(limit=2)
    assert rule(_failed()) is None
    assert rule(_failed()) is None

    decision = cast(Decision, rule(_failed()))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "limit 2 exceeded" in decision.reason


def test_every_failure_past_limit_keeps_blocking():
    rule = failed_auth_lockout(limit=1)
    assert rule(_failed()) is None
    for _ in range(5):
        assert cast(Decision, rule(_failed())).verdict is Verdict.BLOCK


# --- per-principal keying ---------------------------------------------------


def test_principals_have_independent_budgets():
    rule = failed_auth_lockout(limit=1)
    assert rule(_failed(principal="alice")) is None
    # bob's first failure is unaffected by alice's failures.
    assert rule(_failed(principal="bob")) is None
    assert cast(Decision, rule(_failed(principal="alice"))).verdict is Verdict.BLOCK


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_a_fresh_counter():
    first = failed_auth_lockout(limit=2)
    assert first(_failed()) is None
    assert first(_failed()) is None
    assert cast(Decision, first(_failed())).verdict is Verdict.BLOCK

    second = failed_auth_lockout(limit=2)
    # A brand-new rule starts from zero even though `first` is tripped.
    assert second(_failed()) is None


# --- odd-input safety -------------------------------------------------------


def test_missing_principal_falls_back_to_anon_and_is_still_limited():
    rule = failed_auth_lockout(limit=1)
    assert rule(_failed(principal=None)) is None
    decision = rule(_failed(principal=None))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_non_str_principal_does_not_crash():
    rule = failed_auth_lockout(limit=1)
    assert rule(_failed(principal=cast(Any, 12345))) is None
    assert cast(Decision, rule(_failed(principal=cast(Any, 12345)))).verdict is Verdict.BLOCK
    # The int key collapsed to the anon bucket, which is already spent.
    assert cast(Decision, rule(_failed(principal=None))).verdict is Verdict.BLOCK


def test_non_dict_args_are_treated_as_failed_without_crashing():
    rule = failed_auth_lockout(limit=1)
    assert rule(SensorEvent(action="auth", args=cast(Any, None), principal="a")) is None
    assert cast(Decision, rule(SensorEvent(action="auth", args=cast(Any, 7), principal="a"))).verdict is Verdict.BLOCK


def test_anon_constant_is_used_for_missing_identity():
    assert ANON == "<anon>"


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[failed_auth_lockout(limit=1)])

    first = engine.evaluate(_failed())
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_failed())
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
