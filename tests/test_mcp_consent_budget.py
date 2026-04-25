"""MCP consent budget: the under-limit allow path, the over-limit block path,
per-rule isolation of the counter, odd-input safety, and engine integration.
Every test asserts on a return value; none is vacuous.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_consent_budget import (
    POLICY_ID,
    mcp_consent_budget,
)


def _event(action, args=None):
    return SensorEvent(action=action, args=args if args is not None else {})


# --- allow path: the Nth call is still within the approved budget -----------


def test_first_calls_under_limit_return_no_opinion():
    rule = mcp_consent_budget(limit=2)
    assert rule(_event("shell_exec")) is None
    assert rule(_event("shell_exec")) is None


def test_the_limitth_call_still_passes_strict_greater_than():
    # limit=1 means exactly one use is approved: the 1st passes, the 2nd does
    # not. Proves the boundary is `count > limit`, not `count >= limit`.
    rule = mcp_consent_budget(limit=1)
    assert rule(_event("payments.transfer")) is None


def test_other_actions_have_their_own_budget():
    # Spending one tool's budget must not consume another's: the counter is
    # keyed per action.
    rule = mcp_consent_budget(limit=1)
    assert rule(_event("shell_exec")) is None
    blocked = rule(_event("shell_exec"))
    assert blocked is not None
    assert rule(_event("payments.transfer")) is None


# --- block path: past the limit ---------------------------------------------


def test_over_limit_call_is_blocked():
    rule = mcp_consent_budget(limit=2)
    assert rule(_event("shell_exec")) is None
    assert rule(_event("shell_exec")) is None
    decision = rule(_event("shell_exec"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.policy_id == "mcp_consent_budget"
    assert decision.reason == "mcp_consent_budget: limit 2 exceeded"


def test_every_call_after_the_limit_is_also_blocked():
    rule = mcp_consent_budget(limit=2)
    for _ in range(2):
        assert rule(_event("shell_exec")) is None
    for _ in range(3):
        decision = rule(_event("shell_exec"))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


# --- isolation: each factory call owns a fresh counter ----------------------


def test_second_rule_has_a_fresh_counter():
    first = mcp_consent_budget(limit=2)
    trip = lambda r: [r(_event("shell_exec")) for _ in range(3)]  # noqa: E731
    trip(first)

    second = mcp_consent_budget(limit=2)
    # The first rule is still tripped, yet the second rule is untouched: state
    # lives in the closure, not in a module global.
    assert second(_event("shell_exec")) is None
    assert second(_event("shell_exec")) is None
    assert second(_event("shell_exec")) is not None


# --- odd input: skip, never raise -------------------------------------------


def test_non_str_action_is_ignored():
    rule = mcp_consent_budget(limit=1)
    for bad in (None, 3, ["shell_exec"], {"a": 1}):
        assert rule(SensorEvent(action=bad, args={})) is None, bad  # type: ignore[arg-type]
    # The skipped events did not consume the budget.
    assert rule(_event("shell_exec")) is None
    assert rule(_event("shell_exec")) is not None


def test_missing_or_hostile_args_do_not_matter():
    rule = mcp_consent_budget(limit=1)
    assert rule(SensorEvent(action="shell_exec", args=None)) is None  # type: ignore[arg-type]
    assert rule(SensorEvent(action="shell_exec", args={"nested": [1, {"x": None}]})) is not None


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[mcp_consent_budget(limit=1)])

    first = engine.evaluate(_event("shell_exec"))
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_event("shell_exec"))
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
