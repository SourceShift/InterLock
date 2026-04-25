"""US/E.164 phone redaction guard: mask phone numbers out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the shape-only pattern across common
formats, non-string and nested input that must be skipped rather than crashed
on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.us_phone_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    us_phone_redactor,
)

# The spec's example number, in its parenthesised form.
PHONE = "(415) 555-0142"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_phone_and_returns_modify():
    decision = us_phone_redactor()(
        _event(url="https://api.x/y", data="call me at {} tomorrow".format(PHONE))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert PHONE not in decision.modified_args["data"]
    assert "call me at" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = us_phone_redactor()(
        _event(url="https://api.x/y", data="call me at " + PHONE)
    )
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_phone_is_never_masked():
    # No content key changed, so there is nothing to redact - a number that only
    # appears in the destination is left to the egress allowlist.
    guard = us_phone_redactor()
    assert guard(_event(url="https://api.x/{}".format(PHONE.replace(" ", "")),
                        data="clean body")) is None


def test_common_formats_all_masked():
    # Same number written six ways: +1 with dashes, bare dashes, dots, spaces,
    # E.164, and the parenthesised form.
    for raw in (
        "+1-415-555-0142",
        "415-555-0142",
        "415.555.0142",
        "415 555 0142",
        "+14155550142",
        "(415) 555-0142",
    ):
        decision = us_phone_redactor()(_event(data="phone {}".format(raw)))
        assert decision is not None, raw
        assert decision.verdict is Verdict.MODIFY, raw
        assert raw not in decision.modified_args["data"], raw
        assert MARKER in decision.modified_args["data"], raw


def test_multiple_numbers_in_one_field_all_masked():
    decision = us_phone_redactor()(
        _event(body="a {} b {}+1-800-555-0199".format(PHONE, PHONE))
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 3
    assert "415" not in out


def test_several_content_keys_changed_at_once():
    decision = us_phone_redactor()(_event(data="d " + PHONE, text="t " + PHONE))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = us_phone_redactor()(_event(**{key: "phone " + PHONE}))
        assert decision is not None, key
        assert decision.modified_args == {key: "phone " + MARKER}, key


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = us_phone_redactor()(_event(action=action, data=PHONE))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = us_phone_redactor()
    assert guard(_event(url="https://api.x/y", data="call me tomorrow")) is None


def test_non_egress_action_carrying_a_phone_is_ignored():
    guard = us_phone_redactor()
    assert guard(_event(action="read_file", data=PHONE)) is None
    assert guard(_event(action="think", msg=PHONE)) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = us_phone_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": PHONE})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert us_phone_redactor()(SensorEvent(action="http_post", args=PHONE)) is None
    assert us_phone_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_digits_embedded_in_a_longer_run_are_not_a_phone():
    # A 15-digit id contains 10-digit substrings, but the digit lookarounds keep
    # the pattern from slicing one out as a false positive.
    guard = us_phone_redactor()
    assert guard(_event(data="order 123456789012345 shipped")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "phone_redact"
    assert MARKER == "[REDACTED PHONE]"
    assert PATTERN.search("x {} y".format(PHONE)) is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[us_phone_redactor()])

    dirty = _event(url="https://api.x/y", data="call me at {} tomorrow".format(PHONE))
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert PHONE not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="call me tomorrow")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
