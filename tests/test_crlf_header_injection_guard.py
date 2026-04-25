"""crlf_header_injection_guard: allow path, block path, non-str safety, and
engine integration for encoded/literal CRLF header and log injection."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.crlf_header_injection_guard import (
    PATTERN,
    POLICY_ID,
    crlf_header_injection_guard,
)

MALICIOUS_TEXT = "text/html%0d%0aSet-Cookie: admin=1"
BENIGN_TEXT = "application/json"


def _event(action="set_header", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_benign_value_returns_none():
    detector = crlf_header_injection_guard()
    event = SensorEvent(action="set_header", args={"value": BENIGN_TEXT})
    assert detector(event) is None


def test_empty_args_returns_none():
    detector = crlf_header_injection_guard()
    assert detector(_event(args={})) is None


def test_mentioning_crlf_in_prose_is_not_a_match():
    # Describing the technique is not the technique: no encoding or escape here.
    detector = crlf_header_injection_guard()
    event = _event(args={"value": "strip CRLF sequences from user input"})
    assert detector(event) is None


def test_lone_percent_encoding_is_not_a_match():
    # A bare percent sign must not be mistaken for a CRLF encoding.
    detector = crlf_header_injection_guard()
    event = _event(args={"value": "50%0f coverage"})
    assert detector(event) is None


# --- block path -------------------------------------------------------------


def test_encoded_crlf_injection_blocks():
    detector = crlf_header_injection_guard()
    event = SensorEvent(action="set_header", args={"value": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "crlf_injection"


def test_reason_names_the_offending_arg():
    detector = crlf_header_injection_guard()
    decision = detector(_event(args={"value": MALICIOUS_TEXT}))
    assert decision is not None
    assert decision.reason == "crlf_injection: value"


def test_offending_arg_name_is_reported_for_non_value_field():
    detector = crlf_header_injection_guard()
    decision = detector(
        _event(args={"note": "ok", "redirect": "/x%0d%0aLocation: https://evil"})
    )
    assert decision is not None
    assert decision.reason == "crlf_injection: redirect"


def test_all_encoded_and_literal_variants_block():
    detector = crlf_header_injection_guard()
    for payload in (
        "a%0d%0aX-Injected: 1",
        "a%0aX-Injected: 1",
        "a%0dX-Injected: 1",
        "a\\r\\nX-Injected: 1",
        "a\\n\\rX-Injected: 1",
    ):
        decision = detector(_event(args={"value": payload}))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == POLICY_ID


def test_pattern_is_compiled_and_discriminates():
    assert PATTERN.search(MALICIOUS_TEXT) is not None
    assert PATTERN.search(BENIGN_TEXT) is None


# --- non-str safety ---------------------------------------------------------


def test_non_str_values_are_skipped_and_do_not_crash():
    # int / None / nested containers must neither crash nor be stringified into
    # a match; nested payloads are out of scope (top-level strings only).
    detector = crlf_header_injection_guard()
    event = _event(
        args={
            "count": 42,
            "flag": None,
            "nested": {"value": "%0d%0aSet-Cookie: admin=1"},
            "items": ["%0d%0a"],
        }
    )
    assert detector(event) is None


def test_non_str_value_before_a_match_is_skipped():
    detector = crlf_header_injection_guard()
    event = _event(args={"count": 3, "value": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "crlf_injection: value"


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = crlf_header_injection_guard()
    # Deliberately malformed: args is not a mapping, so the rule must bail.
    event = SensorEvent(action="set_header", args=cast(Any, "%0d%0aSet-Cookie: 1"))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[crlf_header_injection_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="set_header", args={"value": MALICIOUS_TEXT})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    benign = engine.evaluate(
        SensorEvent(action="set_header", args={"value": BENIGN_TEXT})
    )
    assert benign.verdict is Verdict.ALLOW
