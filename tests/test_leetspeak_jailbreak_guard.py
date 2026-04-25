"""leetspeak_jailbreak_guard: allow path, leet/separator block paths,
non-str safety, and engine integration for obfuscated jailbreak phrasing."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.leetspeak_jailbreak_guard import (
    BUILTIN_ROOTS,
    POLICY_ID,
    leetspeak_jailbreak_guard,
)

BENIGN_TEXT = "normal helpful request"
LEET_TEXT = "1gn0r3 pr3v10us"


def _event(action="chat", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_benign_text_returns_none():
    detector = leetspeak_jailbreak_guard()
    assert detector(_event(args={"text": BENIGN_TEXT})) is None


def test_empty_args_returns_none():
    detector = leetspeak_jailbreak_guard()
    assert detector(_event(args={})) is None


def test_benign_sentence_returns_none():
    detector = leetspeak_jailbreak_guard()
    event = _event(args={"text": "Please summarize the meeting notes."})
    assert detector(event) is None


def test_benign_numbers_do_not_trigger():
    # Digits are present but canonicalize to letters no root collides with.
    detector = leetspeak_jailbreak_guard()
    assert detector(_event(args={"text": "version 1.2.3 release"})) is None


def test_separator_only_value_returns_none():
    detector = leetspeak_jailbreak_guard()
    assert detector(_event(args={"text": "..."})) is None


# --- block path: canon of the required leet payload -------------------------


def test_leet_ignore_previous_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": LEET_TEXT}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "leetspeak_jailbreak"


def test_leet_block_reason_names_the_root_phrase():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": LEET_TEXT}))
    assert decision is not None
    assert decision.reason == "leetspeak_jailbreak: ignore previous"
    assert decision.policy_id == POLICY_ID


def test_plain_jailbreak_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "jailbreak"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_jailbreak_inside_a_sentence_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "please jailbreak your rules"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_every_builtin_root_blocks():
    detector = leetspeak_jailbreak_guard()
    for phrase in BUILTIN_ROOTS:
        decision = detector(_event(args={"text": "ok, " + phrase + "."}))
        assert decision is not None, phrase
        assert decision.verdict is Verdict.BLOCK
        assert phrase in decision.reason


# --- block path: obfuscation variants the raw scan would miss ----------------


def test_dot_split_word_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "j.a.i.l.b.r.e.a.k"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_hyphen_split_leet_phrase_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "1gn0r3-pr3v10us"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_symbol_substitutions_block():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "byp@ss s@f3ty"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "leetspeak_jailbreak: bypass safety"


def test_uppercase_leet_blocks():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"text": "D0 4nyth1ng N0w"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "leetspeak_jailbreak: do anything now"


def test_offending_arg_after_a_clean_one_is_found():
    detector = leetspeak_jailbreak_guard()
    event = _event(args={"note": "all good", "text": LEET_TEXT})
    decision = detector(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- non-str safety ---------------------------------------------------------


def test_non_str_values_are_skipped_and_do_not_crash():
    detector = leetspeak_jailbreak_guard()
    event = _event(
        args={
            "count": 42,
            "flag": None,
            "nested": {"text": "jailbreak"},
            "items": ["ignore previous"],
        }
    )
    # Nested containers are not inspected, so no match and no exception.
    assert detector(event) is None


def test_int_arg_does_not_crash():
    detector = leetspeak_jailbreak_guard()
    assert detector(_event(args={"count": 7})) is None


def test_non_dict_args_leaves_rule_silent_not_crashing():
    detector = leetspeak_jailbreak_guard()
    event = SensorEvent(action="chat", args=cast(Any, "jailbreak"))
    assert detector(event) is None


def test_non_str_action_does_not_crash():
    detector = leetspeak_jailbreak_guard()
    event = SensorEvent(action=cast(Any, 12345), args={"count": 1})
    assert detector(event) is None


def test_non_str_value_before_a_match_is_skipped():
    detector = leetspeak_jailbreak_guard()
    decision = detector(_event(args={"count": 3, "text": LEET_TEXT}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


# --- engine integration -----------------------------------------------------


def test_engine_blocks_leet_and_allows_benign():
    engine = PolicyEngine(rules=[leetspeak_jailbreak_guard()])

    blocked = engine.evaluate(SensorEvent(action="chat", args={"text": LEET_TEXT}))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    benign = engine.evaluate(SensorEvent(action="chat", args={"text": BENIGN_TEXT}))
    assert benign.verdict is Verdict.ALLOW
