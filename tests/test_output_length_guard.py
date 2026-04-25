"""output_length_guard: allow path (small output, non-output action), block path
(oversized output), odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.output_length_guard import (
    OUTPUT_ACTIONS,
    POLICY_ID,
    output_length_guard,
)


def _event(action="respond", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_small_output_returns_none():
    detector = output_length_guard(max_bytes=1000)
    assert detector(_event(args={"text": "hello", "content": "world"})) is None


def test_default_threshold_allows_ordinary_output():
    detector = output_length_guard()
    assert detector(_event(args={"text": "x" * 49_999})) is None


def test_exactly_at_limit_returns_none():
    # Strictly greater than the limit blocks; exactly at it is allowed.
    detector = output_length_guard(max_bytes=10)
    assert detector(_event(args={"text": "x" * 10})) is None


def test_non_output_action_returns_none():
    detector = output_length_guard(max_bytes=10)
    assert detector(_event(action="http_post", args={"text": "x" * 5000})) is None


def test_empty_args_returns_none():
    detector = output_length_guard(max_bytes=10)
    assert detector(_event(args={})) is None


# --- block path -------------------------------------------------------------


def test_oversized_output_blocks():
    detector = output_length_guard(max_bytes=10)
    decision = detector(_event(args={"text": "x" * 11}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "bytes over limit" in decision.reason


def test_oversized_data_key_blocks():
    detector = output_length_guard(max_bytes=10)
    decision = detector(_event(args={"data": "x" * 100}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_sizes_sum_across_content_keys():
    # 6 + 6 = 12 bytes across two keys, over a limit of 10.
    detector = output_length_guard(max_bytes=10)
    decision = detector(_event(args={"text": "x" * 6, "body": "y" * 6}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_multibyte_counts_as_utf8_bytes():
    # "é" is 2 bytes in utf-8, so 6 chars are 12 bytes, over a limit of 10.
    detector = output_length_guard(max_bytes=10)
    decision = detector(_event(args={"content": "é" * 6}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_every_output_action_is_guarded():
    detector = output_length_guard(max_bytes=10)
    for action in OUTPUT_ACTIONS:
        decision = detector(_event(action=action, args={"text": "x" * 50}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = output_length_guard(max_bytes=10)
    event = SensorEvent(action="respond", args=cast(Any, "x" * 5000))
    assert detector(event) is None


def test_non_str_content_values_are_skipped():
    detector = output_length_guard(max_bytes=10)
    event = _event(
        args={"text": 12345, "content": None, "body": {"deep": ["x"] * 50}}
    )
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_oversized_and_allows_small():
    engine = PolicyEngine(rules=[output_length_guard(max_bytes=10)])

    blocked = engine.evaluate(
        SensorEvent(action="respond", args={"text": "x" * 11})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="respond", args={"text": "tiny"})
    )
    assert allowed.verdict is Verdict.ALLOW
