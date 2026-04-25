"""write_action_limiter: allow path (within budget), block path (over budget),
only-mutating-actions count, per-principal keying, per-rule state isolation,
odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.write_action_limiter import (
    POLICY_ID,
    write_action_limiter,
)


def _event(principal: Any = "agent-1", action="write_file", args=None):
    return SensorEvent(action=action, args=args or {}, principal=principal)


# --- allow path -------------------------------------------------------------


def test_writes_within_limit_return_none():
    rule = write_action_limiter(limit=2)
    assert rule(_event(action="write_file")) is None  # 1st
    assert rule(_event(action="write_file")) is None  # 2nd, still within budget


def test_limit_is_inclusive_at_the_boundary():
    # The Nth mutating call passes; only the (N+1)th is refused.
    rule = write_action_limiter(limit=1)
    assert rule(_event(action="create_user")) is None


def test_all_mutating_verbs_share_one_budget():
    rule = write_action_limiter(limit=3)
    assert rule(_event(action="write_file")) is None
    assert rule(_event(action="update_row")) is None
    assert rule(_event(action="delete_key")) is None
    assert cast(Decision, rule(_event(action="create_bucket"))).verdict is Verdict.BLOCK


# --- block path -------------------------------------------------------------


def test_write_over_limit_blocks():
    rule = write_action_limiter(limit=2)
    assert rule(_event(action="write_file")) is None
    assert rule(_event(action="write_file")) is None

    decision = rule(_event(action="write_file"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "limit 2 exceeded" in decision.reason


def test_every_write_past_limit_keeps_blocking():
    rule = write_action_limiter(limit=1)
    assert rule(_event(action="delete_file")) is None
    for _ in range(5):
        assert cast(Decision, rule(_event(action="delete_file"))).verdict is Verdict.BLOCK


# --- only mutating actions count --------------------------------------------


def test_non_mutating_actions_return_none_and_spend_no_budget():
    rule = write_action_limiter(limit=1)
    # Reads are not budgeted and must not consume the single write allowance.
    for _ in range(10):
        assert rule(_event(action="read_file")) is None
        assert rule(_event(action="search")) is None
    # The write budget is still whole: the first write passes, the second blocks.
    assert rule(_event(action="write_file")) is None
    assert cast(Decision, rule(_event(action="write_file"))).verdict is Verdict.BLOCK


# --- per-principal keying ---------------------------------------------------


def test_principals_have_independent_budgets():
    rule = write_action_limiter(limit=1)
    assert rule(_event(principal="alice", action="write_file")) is None
    # bob's first write is unaffected by alice's spend.
    assert rule(_event(principal="bob", action="write_file")) is None
    assert cast(
        Decision, rule(_event(principal="alice", action="write_file"))
    ).verdict is Verdict.BLOCK


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_a_fresh_counter():
    first = write_action_limiter(limit=2)
    assert first(_event(action="write_file")) is None
    assert first(_event(action="write_file")) is None
    assert cast(Decision, first(_event(action="write_file"))).verdict is Verdict.BLOCK

    second = write_action_limiter(limit=2)
    # A brand-new rule starts from zero even though `first` is tripped.
    assert second(_event(action="write_file")) is None


# --- odd-input safety -------------------------------------------------------


def test_missing_principal_falls_back_to_anon_and_is_still_limited():
    rule = write_action_limiter(limit=1)
    assert rule(_event(principal=None, action="write_file")) is None
    decision = rule(_event(principal=None, action="write_file"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_non_str_principal_does_not_crash():
    rule = write_action_limiter(limit=1)
    assert rule(_event(principal=cast(Any, 12345), action="write_file")) is None
    assert cast(
        Decision, rule(_event(principal=cast(Any, 12345), action="write_file"))
    ).verdict is Verdict.BLOCK
    # The int key collapsed to the anon bucket, which is already spent.
    assert cast(
        Decision, rule(_event(principal=None, action="write_file"))
    ).verdict is Verdict.BLOCK


def test_non_str_action_is_skipped_not_counted():
    rule = write_action_limiter(limit=1)
    # An unreadable action is not recognised as mutating: no opinion, no spend.
    assert rule(_event(action=cast(Any, None))) is None
    assert rule(_event(action=cast(Any, 42))) is None
    assert rule(_event(action=cast(Any, {"a": 1}))) is None
    # The budget is untouched: one write still passes, the next blocks.
    assert rule(_event(action="write_file")) is None
    assert cast(Decision, rule(_event(action="write_file"))).verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[write_action_limiter(limit=1)])

    first = engine.evaluate(_event(action="write_file"))
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_event(action="write_file"))
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID


def test_engine_leaves_non_mutating_actions_allowed():
    engine = PolicyEngine(rules=[write_action_limiter(limit=1)])

    for _ in range(5):
        assert engine.evaluate(_event(action="read_file")).verdict is Verdict.ALLOW
