"""data_volume_egress_guard: block path (oversized payload), allow path (small
payload and non-egress), odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.data_volume_egress_guard import (
    EGRESS_ACTIONS,
    POLICY_ID,
    data_volume_egress_guard,
)


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_small_payload_returns_none():
    detector = data_volume_egress_guard(max_bytes=1000)
    assert detector(_event(args={"body": "hello", "data": "world"})) is None


def test_default_threshold_allows_ordinary_payload():
    detector = data_volume_egress_guard()
    assert detector(_event(args={"body": "x" * 99_999})) is None


def test_exactly_at_limit_returns_none():
    # Strictly greater than the limit blocks; exactly at it is allowed.
    detector = data_volume_egress_guard(max_bytes=10)
    assert detector(_event(args={"body": "x" * 10})) is None


def test_non_egress_action_returns_none():
    detector = data_volume_egress_guard(max_bytes=10)
    assert detector(_event(action="read_file", args={"body": "x" * 5000})) is None


def test_empty_args_returns_none():
    detector = data_volume_egress_guard(max_bytes=10)
    assert detector(_event(args={})) is None


# --- block path -------------------------------------------------------------


def test_oversized_payload_blocks():
    detector = data_volume_egress_guard(max_bytes=10)
    decision = detector(_event(args={"body": "x" * 11}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "bytes over limit" in decision.reason


def test_oversized_data_key_blocks():
    detector = data_volume_egress_guard(max_bytes=10)
    decision = detector(_event(args={"data": "x" * 100}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_sizes_sum_across_content_keys():
    # 6 + 6 = 12 bytes across two keys, over a limit of 10.
    detector = data_volume_egress_guard(max_bytes=10)
    decision = detector(_event(args={"body": "x" * 6, "payload": "y" * 6}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_multibyte_counts_as_utf8_bytes():
    # "é" is 2 bytes in utf-8, so 6 chars are 12 bytes, over a limit of 10.
    detector = data_volume_egress_guard(max_bytes=10)
    decision = detector(_event(args={"text": "é" * 6}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_every_egress_action_is_guarded():
    detector = data_volume_egress_guard(max_bytes=10)
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"body": "x" * 50}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = data_volume_egress_guard(max_bytes=10)
    event = SensorEvent(action="http_post", args=cast(Any, "x" * 5000))
    assert detector(event) is None


def test_non_str_content_values_are_skipped():
    detector = data_volume_egress_guard(max_bytes=10)
    event = _event(args={"body": 12345, "data": None, "payload": {"deep": ["x"] * 50}})
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_oversized_and_allows_small():
    engine = PolicyEngine(rules=[data_volume_egress_guard(max_bytes=10)])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"body": "x" * 11})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"body": "tiny"})
    )
    assert allowed.verdict is Verdict.ALLOW
