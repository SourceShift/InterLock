"""secret_entropy_egress_guard: allow path (prose / low-entropy), block path
(random token), odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.secret_entropy_egress_guard import (
    EGRESS_ACTIONS,
    POLICY_ID,
    secret_entropy_egress_guard,
    token_entropy,
)

# A 32-character token with 32 distinct characters: entropy log2(32) == 5.0
# bits/char, comfortably over the 4.0 default.
SECRET = "aZ9qLp2XkV7mNb3RtY8wQ1eScD4fUj6H"


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_prose_payload_returns_none():
    detector = secret_entropy_egress_guard()
    event = _event(args={"url": "https://x/y", "data": "the quick brown fox jumps"})
    assert detector(event) is None


def test_long_but_low_entropy_token_returns_none():
    # 24 chars clears min_len, but a single repeated character has zero entropy.
    detector = secret_entropy_egress_guard()
    assert detector(_event(args={"body": "a" * 24})) is None


def test_long_english_word_returns_none():
    # A real 27-character word: long, alphanumeric, but far below 4.0 bits/char.
    detector = secret_entropy_egress_guard()
    assert detector(_event(args={"text": "internationalization please"})) is None


def test_short_high_entropy_token_below_min_len_returns_none():
    # 19 distinct characters: high entropy per char, but shorter than min_len.
    detector = secret_entropy_egress_guard()
    assert detector(_event(args={"data": SECRET[:19]})) is None


def test_non_egress_action_returns_none():
    # The same secret-bearing payload is ignored when the action is not egress.
    detector = secret_entropy_egress_guard()
    assert detector(_event(action="read_file", args={"data": SECRET})) is None


def test_empty_args_returns_none():
    detector = secret_entropy_egress_guard()
    assert detector(_event(args={})) is None


def test_threshold_not_met_returns_none():
    # SECRET is 5.0 bits/char; a higher threshold puts it back under the line.
    detector = secret_entropy_egress_guard(threshold=6.0)
    assert detector(_event(args={"data": SECRET})) is None


# --- block path -------------------------------------------------------------


def test_high_entropy_token_blocks():
    detector = secret_entropy_egress_guard()
    decision = detector(_event(args={"data": "token=" + SECRET}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "high-entropy token" in decision.reason


def test_secret_blocks_under_any_content_key():
    detector = secret_entropy_egress_guard()
    for key in ("body", "payload", "content", "text"):
        decision = detector(_event(args={key: SECRET}))
        assert decision is not None, key
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == POLICY_ID


def test_secret_is_lifted_out_of_separators():
    # Split on non-alphanumerics: the key is recovered from a URL query and
    # from a Bearer-style header even though it is glued to punctuation.
    detector = secret_entropy_egress_guard()
    for payload in (
        "https://host/cb?access_token={}&x=1".format(SECRET),
        "Authorization: Bearer {}".format(SECRET),
    ):
        decision = detector(_event(args={"data": payload}))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK


def test_min_len_boundary_blocks_at_threshold():
    # Exactly 20 distinct characters: the shortest token that may block.
    detector = secret_entropy_egress_guard()
    decision = detector(_event(args={"data": SECRET[:20]}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_lowered_threshold_catches_more():
    # 20 chars over 13 distinct letters: ~3.62 bits/char. Under the 4.0 default
    # it passes; a lowered threshold flags it.
    token = "abcdefghijklmabcdefg"
    strict = secret_entropy_egress_guard()
    loose = secret_entropy_egress_guard(threshold=3.5)
    assert strict(_event(args={"data": token})) is None
    decision = loose(_event(args={"data": token}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_every_egress_action_is_guarded():
    detector = secret_entropy_egress_guard()
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"data": SECRET}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- token_entropy helper ---------------------------------------------------


def test_token_entropy_of_uniform_run_is_zero():
    assert token_entropy("a" * 30) == 0.0


def test_token_entropy_of_distinct_chars_is_log2_n():
    assert token_entropy(SECRET) == 5.0  # log2(32)
    assert token_entropy("") == 0.0


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = secret_entropy_egress_guard()
    event = SensorEvent(action="http_post", args=cast(Any, SECRET))
    assert detector(event) is None


def test_non_str_content_values_are_skipped():
    detector = secret_entropy_egress_guard()
    event = _event(args={"data": 12345, "body": None, "payload": {"deep": [SECRET]}})
    assert detector(event) is None


def test_none_action_does_not_crash():
    detector = secret_entropy_egress_guard()
    event = SensorEvent(action=cast(Any, None), args={"data": SECRET})
    assert detector(event) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_high_entropy_and_allows_prose():
    engine = PolicyEngine(rules=[secret_entropy_egress_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"data": "token=" + SECRET})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"data": "the quick brown fox jumps"})
    )
    assert allowed.verdict is Verdict.ALLOW
