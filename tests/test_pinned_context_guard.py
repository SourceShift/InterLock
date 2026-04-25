"""pinned_context_guard: allow path, block path, key fallback, odd-input
safety, protected-config robustness, and engine integration for agent-memory
writes that target a load-bearing context key."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.pinned_context_guard import (
    POLICY_ID,
    pinned_context_guard,
)

PROTECTED = {"system_prompt", "safety_policy"}


def _event(action="memory_write", args=None):
    return SensorEvent(action=action, args=args if args is not None else {})


# --- allow path -------------------------------------------------------------


def test_ordinary_key_returns_none():
    detector = pinned_context_guard(PROTECTED)
    event = _event(args={"key": "user_pref", "value": "x"})
    assert detector(event) is None


def test_empty_protected_set_never_blocks():
    detector = pinned_context_guard([])
    assert detector(_event(args={"key": "system_prompt", "value": "evil"})) is None


def test_non_memory_action_targeting_protected_key_returns_none():
    detector = pinned_context_guard(PROTECTED)
    event = _event(action="read_file", args={"key": "system_prompt", "value": "x"})
    assert detector(event) is None


def test_missing_key_returns_none():
    detector = pinned_context_guard(PROTECTED)
    assert detector(_event(args={"value": "x"})) is None


# --- block path -------------------------------------------------------------


def test_protected_key_blocks():
    detector = pinned_context_guard(PROTECTED)
    decision = detector(_event(args={"key": "system_prompt", "value": "evil"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_reason_names_the_protected_key():
    detector = pinned_context_guard(PROTECTED)
    decision = detector(_event(args={"key": "safety_policy", "value": "evil"}))
    assert decision is not None
    assert decision.reason == "pinned_context_guard: protected key safety_policy"


def test_every_protected_key_blocks():
    detector = pinned_context_guard(PROTECTED)
    for key in PROTECTED:
        decision = detector(_event(args={"key": key, "value": "evil"}))
        assert decision is not None, key
        assert decision.verdict is Verdict.BLOCK
        assert key in decision.reason


def test_every_memory_action_blocks():
    detector = pinned_context_guard(PROTECTED)
    for action in ("memory_write", "context_set", "set_state"):
        decision = detector(_event(action=action, args={"key": "system_prompt"}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


def test_protected_key_match_is_exact_not_case_folded():
    # The reader looks up the literal key; "System_Prompt" is a different entry.
    detector = pinned_context_guard(PROTECTED)
    assert detector(_event(args={"key": "System_Prompt", "value": "x"})) is None


# --- key fallback -----------------------------------------------------------


def test_name_field_is_used_when_key_is_absent():
    detector = pinned_context_guard(PROTECTED)
    decision = detector(_event(args={"name": "system_prompt", "value": "evil"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_key_field_wins_over_name_field():
    detector = pinned_context_guard(PROTECTED)
    event = _event(args={"key": "user_pref", "name": "system_prompt"})
    assert detector(event) is None


def test_non_str_key_falls_back_to_name():
    detector = pinned_context_guard(PROTECTED)
    event = _event(args={"key": 42, "name": "system_prompt"})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = pinned_context_guard(PROTECTED)
    event = SensorEvent(action="memory_write", args=cast(Any, ["system_prompt"]))
    assert detector(event) is None


def test_non_str_key_returns_none():
    detector = pinned_context_guard(PROTECTED)
    assert detector(_event(args={"key": None, "value": "x"})) is None


def test_nested_and_scalar_values_do_not_crash():
    detector = pinned_context_guard(PROTECTED)
    event = _event(
        args={
            "key": "user_pref",
            "value": {"nested": {"deep": ["system_prompt"]}},
            "count": 3,
        }
    )
    assert detector(event) is None


def test_protected_config_with_junk_entries_is_skipped():
    detector = pinned_context_guard(cast(Any, [None, 7, "system_prompt"]))
    decision = detector(_event(args={"key": "system_prompt"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_protected_config_as_bare_string_is_not_split_into_chars():
    detector = pinned_context_guard(cast(Any, "system_prompt"))
    decision = detector(_event(args={"key": "system_prompt"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_none_protected_config_blocks_nothing():
    detector = pinned_context_guard(cast(Any, None))
    assert detector(_event(args={"key": "system_prompt"})) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_protected_write_and_allows_ordinary_write():
    engine = PolicyEngine(rules=[pinned_context_guard(PROTECTED)])

    blocked = engine.evaluate(
        SensorEvent(action="memory_write", args={"key": "system_prompt", "value": "evil"})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    clean = engine.evaluate(
        SensorEvent(action="memory_write", args={"key": "user_pref", "value": "metric"})
    )
    assert clean.verdict is Verdict.ALLOW
