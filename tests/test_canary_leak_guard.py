"""canary_leak_guard: allow path (clean egress), block path (canary in
payload), non-egress short-circuit, odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.canary_leak_guard import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    POLICY_ID,
    canary_leak_guard,
)

CANARY = "CANARY-abc123"


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allow path -------------------------------------------------------------


def test_clean_egress_returns_none():
    # Same egress action as the block case; only the payload differs, so a None
    # here is genuinely "no canary", not a non-egress short-circuit.
    detector = canary_leak_guard({CANARY})
    event = _event(args={"url": "https://x", "data": "normal report"})
    assert detector(event) is None


def test_no_canaries_planted_returns_none():
    # An empty canary set has nothing to leak, so even a suspicious payload is
    # passed through rather than blocked.
    detector = canary_leak_guard([])
    assert detector(_event(args={"data": "anything at all"})) is None


def test_empty_string_canary_is_ignored():
    # "" is a substring of every string; it must be filtered or egress is fully
    # blocked. The real canary alongside it is what does the blocking.
    detector = canary_leak_guard({"", CANARY})
    assert detector(_event(args={"data": "normal report"})) is None


def test_partial_canary_does_not_block():
    # A prefix of the canary is not the canary: detection is exact identity.
    detector = canary_leak_guard({CANARY})
    assert detector(_event(args={"data": "CANARY-abc"})) is None


def test_empty_args_returns_none():
    detector = canary_leak_guard({CANARY})
    assert detector(_event(args={})) is None


# --- block path -------------------------------------------------------------


def test_canary_in_data_blocks():
    detector = canary_leak_guard({CANARY})
    decision = detector(_event(args={"data": "here it is: " + CANARY}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "canary" in decision.reason


def test_bare_canary_blocks():
    detector = canary_leak_guard({CANARY})
    decision = detector(_event(args={"body": CANARY}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_canary_blocks_under_any_content_key():
    detector = canary_leak_guard({CANARY})
    for key in CONTENT_KEYS:
        decision = detector(_event(args={key: CANARY}))
        assert decision is not None, key
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == POLICY_ID


def test_canary_blocks_on_any_egress_action():
    detector = canary_leak_guard({CANARY})
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"data": CANARY}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


def test_any_of_several_canaries_blocks():
    detector = canary_leak_guard({"CANARY-one", "CANARY-two"})
    decision = detector(_event(args={"payload": "leaked CANARY-two here"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- non-egress short-circuit -----------------------------------------------


def test_non_egress_action_with_canary_returns_none():
    # The canary is only a leak when it leaves; an internal read is not egress.
    detector = canary_leak_guard({CANARY})
    event = _event(action="read_file", args={"data": CANARY})
    assert detector(event) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = canary_leak_guard({CANARY})
    event = SensorEvent(action="http_post", args=cast(Any, CANARY))
    assert detector(event) is None


def test_non_str_content_values_are_skipped():
    detector = canary_leak_guard({CANARY})
    event = _event(args={"data": 12345, "body": None, "payload": {"deep": [CANARY]}})
    assert detector(event) is None


def test_none_action_does_not_crash():
    detector = canary_leak_guard({CANARY})
    event = SensorEvent(action=cast(Any, None), args={"data": CANARY})
    assert detector(event) is None


def test_none_canaries_does_not_crash():
    # A caller passing None instead of an iterable must not break the factory.
    detector = canary_leak_guard(cast(Any, None))
    assert detector(_event(args={"data": CANARY})) is None


def test_non_str_canaries_are_skipped():
    detector = canary_leak_guard(cast(Any, [CANARY, 42, None]))
    decision = detector(_event(args={"data": CANARY}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_leak_and_allows_clean():
    engine = PolicyEngine(rules=[canary_leak_guard({CANARY})])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"data": "exfil " + CANARY})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"data": "normal report"})
    )
    assert allowed.verdict is Verdict.ALLOW
