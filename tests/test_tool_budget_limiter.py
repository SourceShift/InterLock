"""tool_budget_limiter: allow path (within budget), block path (over budget),
per-tool-name keying, per-rule state isolation, odd-input safety, and engine
integration."""
from typing import Any, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.tool_budget_limiter import (
    DEFAULT_LIMIT,
    POLICY_ID,
    tool_budget_limiter,
)


def _event(action: Any = "run_tool", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_calls_within_limit_return_none():
    rule = tool_budget_limiter(limit=2)
    assert rule(_event()) is None  # 1st
    assert rule(_event()) is None  # 2nd, still within budget


def test_limit_is_inclusive_at_the_boundary():
    # The Nth call passes; only the (N+1)th is refused.
    rule = tool_budget_limiter(limit=1)
    assert rule(_event()) is None


def test_default_limit_is_50():
    assert DEFAULT_LIMIT == 50
    rule = tool_budget_limiter()
    for _ in range(50):
        assert rule(_event()) is None
    assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


# --- block path -------------------------------------------------------------


def test_call_over_limit_blocks():
    rule = tool_budget_limiter(limit=2)
    assert rule(_event()) is None
    assert rule(_event()) is None

    decision = rule(_event())
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "limit 2 exceeded" in decision.reason


def test_every_call_past_limit_keeps_blocking():
    rule = tool_budget_limiter(limit=1)
    assert rule(_event()) is None
    for _ in range(5):
        assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


# --- per-tool-name keying ---------------------------------------------------


def test_tools_have_independent_budgets():
    rule = tool_budget_limiter(limit=1)
    assert rule(_event(action="read_file")) is None
    # A second tool's first call is unaffected by the first tool's spend.
    assert rule(_event(action="write_file")) is None
    assert (
        cast(Decision, rule(_event(action="read_file"))).verdict is Verdict.BLOCK
    )


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_a_fresh_counter():
    first = tool_budget_limiter(limit=2)
    assert first(_event()) is None
    assert first(_event()) is None
    assert cast(Decision, first(_event())).verdict is Verdict.BLOCK

    second = tool_budget_limiter(limit=2)
    # A brand-new rule starts from zero even though `first` is tripped.
    assert second(_event()) is None


# --- odd-input safety -------------------------------------------------------


def test_non_str_action_is_skipped_and_does_not_crash():
    rule = tool_budget_limiter(limit=1)
    # Un-keyable actions are ignored, so they never count nor block.
    assert rule(_event(action=cast(Any, 12345))) is None
    assert rule(_event(action=cast(Any, None))) is None
    assert rule(_event(action=cast(Any, ["run_tool"]))) is None
    # A real tool name still gets its own, untouched budget.
    assert rule(_event(action="run_tool")) is None
    assert cast(Decision, rule(_event(action="run_tool"))).verdict is Verdict.BLOCK


def test_nested_and_odd_args_do_not_crash():
    rule = tool_budget_limiter(limit=1)
    assert rule(_event(action="run_tool", args={"deep": {"a": [1, 2, None]}})) is None
    assert (
        cast(Decision, rule(_event(action="run_tool", args={"deep": None}))).verdict
        is Verdict.BLOCK
    )


def test_policy_id_constant():
    assert POLICY_ID == "tool_budget"


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[tool_budget_limiter(limit=1)])

    first = engine.evaluate(_event())
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_event())
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
