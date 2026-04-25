"""memory_write_size_guard: allow path (value within limit), block path (value
over the limit), non-memory actions, odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.memory_write_size_guard import (
    POLICY_ID,
    memory_write_size_guard,
)


def _event(action="memory_write", value=None):
    args = {} if value is None else {"value": value}
    return SensorEvent(action=action, args=args)


# --- allow path -------------------------------------------------------------


def test_small_value_returns_none():
    detector = memory_write_size_guard(max_bytes=100)
    assert detector(_event(value="short note")) is None


def test_value_exactly_at_limit_returns_none():
    # Strictly greater than the limit blocks; landing exactly on it is allowed.
    detector = memory_write_size_guard(max_bytes=16)
    assert detector(_event(value="x" * 16)) is None


def test_default_limit_allows_ordinary_write():
    detector = memory_write_size_guard()
    assert detector(_event(value="the user prefers dark mode")) is None


def test_all_memory_actions_are_recognised():
    detector = memory_write_size_guard(max_bytes=8)
    for action in ("memory_write", "context_set", "remember"):
        decision = detector(_event(action=action, value="y" * 32))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


# --- block path -------------------------------------------------------------


def test_oversized_value_blocks():
    detector = memory_write_size_guard(max_bytes=100)
    decision = detector(_event(value="x" * 101))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "value too large" in decision.reason


def test_byte_length_not_char_count_is_measured():
    # A multibyte string is longer in utf-8 bytes than in characters: 32 "é"
    # chars are 64 bytes, so a 50-byte limit must reject it while a plain
    # 32-char ASCII value would fit.
    detector = memory_write_size_guard(max_bytes=50)
    assert detector(_event(value="a" * 32)) is None
    assert detector(_event(value="é" * 32)) is not None


# --- non-memory actions -----------------------------------------------------


def test_non_memory_action_with_huge_value_returns_none():
    detector = memory_write_size_guard(max_bytes=8)
    assert detector(_event(action="http_post", value="z" * 100_000)) is None
    assert detector(_event(action="shell_exec", value="z" * 100_000)) is None


# --- odd-input safety -------------------------------------------------------


def test_missing_value_key_returns_none():
    detector = memory_write_size_guard(max_bytes=8)
    assert detector(_event()) is None


def test_odd_value_types_do_not_crash():
    # str() renders each of these without raising; all fit under the limit.
    detector = memory_write_size_guard(max_bytes=64)
    assert detector(_event(value=None)) is None
    assert detector(_event(value=12345)) is None
    assert detector(_event(value={"nested": [1, 2, 3]})) is None
    assert detector(_event(value=["a", "b"])) is None


def test_non_dict_args_does_not_crash():
    detector = memory_write_size_guard(max_bytes=8)
    event = SensorEvent(action="memory_write", args=cast(Any, "value=big"))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_oversized_write_allows_small():
    engine = PolicyEngine(rules=[memory_write_size_guard(max_bytes=64)])

    allowed = engine.evaluate(_event(value="fits"))
    assert allowed.verdict is Verdict.ALLOW

    blocked = engine.evaluate(_event(value="x" * 65))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID
