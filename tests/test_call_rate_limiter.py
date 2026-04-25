"""call_rate_limiter: allow path (within budget), block path (over budget),
per-principal keying, per-rule state isolation, odd-input safety, and engine
integration."""
from typing import Any, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.call_rate_limiter import (
    ANON,
    POLICY_ID,
    call_rate_limiter,
)


def _event(principal: Any = "agent-1", action="run_tool", args=None):
    return SensorEvent(action=action, args=args or {}, principal=principal)


# --- allow path -------------------------------------------------------------


def test_calls_within_limit_return_none():
    rule = call_rate_limiter(limit=2)
    assert rule(_event()) is None  # 1st
    assert rule(_event()) is None  # 2nd, still within budget


def test_limit_is_inclusive_at_the_boundary():
    # The Nth call passes; only the (N+1)th is refused.
    rule = call_rate_limiter(limit=1)
    assert rule(_event()) is None


def test_every_action_counts_toward_the_same_principal():
    # A principal's budget is not partitioned by tool name.
    rule = call_rate_limiter(limit=2)
    assert rule(_event(action="read_file")) is None
    assert rule(_event(action="write_file")) is None
    assert cast(Decision, rule(_event(action="exec"))).verdict is Verdict.BLOCK


# --- block path -------------------------------------------------------------


def test_call_over_limit_blocks():
    rule = call_rate_limiter(limit=2)
    assert rule(_event()) is None
    assert rule(_event()) is None

    decision = rule(_event())
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "limit 2 exceeded" in decision.reason


def test_every_call_past_limit_keeps_blocking():
    rule = call_rate_limiter(limit=1)
    assert rule(_event()) is None
    for _ in range(5):
        assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


# --- per-principal keying ---------------------------------------------------


def test_principals_have_independent_budgets():
    rule = call_rate_limiter(limit=1)
    assert rule(_event(principal="alice")) is None
    # bob's first call is unaffected by alice's spend.
    assert rule(_event(principal="bob")) is None
    assert cast(Decision, rule(_event(principal="alice"))).verdict is Verdict.BLOCK


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_a_fresh_counter():
    first = call_rate_limiter(limit=2)
    assert first(_event()) is None
    assert first(_event()) is None
    assert cast(Decision, first(_event())).verdict is Verdict.BLOCK

    second = call_rate_limiter(limit=2)
    # A brand-new rule starts from zero even though `first` is tripped.
    assert second(_event()) is None


# --- odd-input safety -------------------------------------------------------


def test_missing_principal_falls_back_to_anon_and_is_still_limited():
    rule = call_rate_limiter(limit=1)
    assert rule(_event(principal=None)) is None
    decision = rule(_event(principal=None))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_non_str_principal_does_not_crash():
    rule = call_rate_limiter(limit=1)
    assert rule(_event(principal=cast(Any, 12345))) is None
    assert cast(Decision, rule(_event(principal=cast(Any, 12345)))).verdict is Verdict.BLOCK
    # The int key collapsed to the anon bucket, which is already spent.
    assert cast(Decision, rule(_event(principal=None))).verdict is Verdict.BLOCK


def test_anon_constant_is_used_for_missing_identity():
    assert ANON == "<anon>"


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[call_rate_limiter(limit=1)])

    first = engine.evaluate(_event())
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_event())
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
