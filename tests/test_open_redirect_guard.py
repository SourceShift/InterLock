"""open_redirect_guard: allow path, block path, non-str safety, and engine
integration for off-site open-redirect parameters."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.open_redirect_guard import (
    PATTERN,
    POLICY_ID,
    open_redirect_guard,
)

MALICIOUS = "/login?next=https://evil.example/phish"
BENIGN = "/dashboard"


def _event(action="build_link", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_benign_path_returns_none():
    detector = open_redirect_guard()
    event = SensorEvent(action="build_link", args={"path": BENIGN})
    assert detector(event) is None


def test_empty_args_returns_none():
    detector = open_redirect_guard()
    assert detector(_event(args={})) is None


def test_relative_redirect_is_not_a_match():
    # A same-site relative redirect is legitimate; only off-site targets block.
    detector = open_redirect_guard()
    event = _event(args={"path": "/login?next=/dashboard"})
    assert detector(event) is None


def test_redirect_param_without_absolute_target_is_not_a_match():
    detector = open_redirect_guard()
    event = _event(args={"path": "/search?url=results"})
    assert detector(event) is None


# --- block path -------------------------------------------------------------


def test_offsite_redirect_blocks():
    detector = open_redirect_guard()
    event = SensorEvent(action="build_link", args={"path": MALICIOUS})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "open_redirect"


def test_reason_names_the_offending_arg():
    detector = open_redirect_guard()
    decision = detector(_event(args={"path": MALICIOUS}))
    assert decision is not None
    assert decision.reason == "open_redirect: path"


def test_offending_arg_name_reported_for_non_path_field():
    detector = open_redirect_guard()
    decision = detector(
        _event(args={"ok": "/home", "redirect": "?return=//evil.example"})
    )
    assert decision is not None
    assert decision.reason == "open_redirect: redirect"


def test_plain_encoded_and_parameterized_variants_block():
    detector = open_redirect_guard()
    for payload in (
        "/login?next=https://evil.example/phish",
        "/login?redirect=http://evil.example",
        "/login?return=//evil.example",
        "/login?url=https%3a%2f%2fevil.example",
        "/x?dest=https%3A//evil.example",
        "/x?continue=https://evil.example",
    ):
        decision = detector(_event(args={"path": payload}))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == POLICY_ID


def test_pattern_is_compiled_and_discriminates():
    assert PATTERN.search(MALICIOUS) is not None
    assert PATTERN.search(BENIGN) is None


# --- non-str safety ---------------------------------------------------------


def test_non_str_values_are_skipped_and_do_not_crash():
    # int / None / nested containers must neither crash nor be stringified into
    # a match; nested payloads are out of scope (top-level strings only).
    detector = open_redirect_guard()
    event = _event(
        args={
            "count": 42,
            "flag": None,
            "nested": {"path": MALICIOUS},
            "items": [MALICIOUS],
        }
    )
    assert detector(event) is None


def test_non_str_value_before_a_match_is_skipped():
    detector = open_redirect_guard()
    decision = detector(_event(args={"count": 3, "path": MALICIOUS}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "open_redirect: path"


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = open_redirect_guard()
    # Deliberately malformed: args is not a mapping, so the rule must bail.
    event = SensorEvent(action="build_link", args=cast(Any, MALICIOUS))
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[open_redirect_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="build_link", args={"path": MALICIOUS})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    benign = engine.evaluate(
        SensorEvent(action="build_link", args={"path": BENIGN})
    )
    assert benign.verdict is Verdict.ALLOW
