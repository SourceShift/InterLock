"""US SSN redaction guard: mask Social Security Numbers out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the shapes it must catch and the
near-misses it must leave alone, non-string and nested input that must be
skipped rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.ssn_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    ssn_redactor,
)

# A real-looking SSN: distinctive enough that a substring assertion on it cannot
# be satisfied by the marker itself.
SECRET = "123-45-6789"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_ssn_and_returns_modify():
    decision = ssn_redactor()(
        _event(url="https://api.x/y", data="the applicant SSN is {} on file".format(SECRET))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert SECRET not in decision.modified_args["data"]
    # Surrounding prose is preserved, only the number is masked.
    assert decision.modified_args["data"] == "the applicant SSN is {} on file".format(MARKER)


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = ssn_redactor()(_event(url="https://api.x/y", data="ssn " + SECRET))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_an_ssn_is_never_masked():
    # No content key changed, so there is nothing to redact - an SSN that only
    # appears in the destination is left to the egress allowlist.
    guard = ssn_redactor()
    assert guard(
        _event(url="https://api.x/{}".format(SECRET), data="clean body")
    ) is None


def test_multiple_ssns_in_one_field_all_masked():
    decision = ssn_redactor()(
        _event(body="first 111-22-3333 and second 987-65-4321")
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert "111-22-3333" not in out
    assert "987-65-4321" not in out


def test_unvalidated_shapes_are_still_masked():
    # No area-number rules: 000, 666, and 900-999 are structurally SSNs and are
    # masked anyway, because a false positive costs only the marker.
    guard = ssn_redactor()
    for ssn in ("000-00-0000", "666-12-3456", "999-99-9999"):
        decision = guard(_event(data="id: {}".format(ssn)))
        assert decision is not None, ssn
        assert ssn not in decision.modified_args["data"], ssn
        assert decision.modified_args["data"] == "id: {}".format(MARKER), ssn


def test_several_content_keys_changed_at_once():
    decision = ssn_redactor()(_event(data="d " + SECRET, text="t " + SECRET))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = ssn_redactor()(_event(**{key: "ssn " + SECRET}))
        assert decision is not None, key
        assert decision.modified_args == {key: "ssn " + MARKER}, key


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = ssn_redactor()(_event(action=action, data=SECRET))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = ssn_redactor()
    assert guard(_event(url="https://api.x/y", data="the applicant record is on file")) is None


def test_non_egress_action_carrying_an_ssn_is_ignored():
    guard = ssn_redactor()
    assert guard(_event(action="read_file", data=SECRET)) is None
    assert guard(_event(action="think", msg=SECRET)) is None


def test_near_miss_digit_shapes_are_left_alone():
    # Wrong grouping, wrong digit counts, or embedded in a longer token: none
    # of these is a ###-##-#### SSN, so nothing is masked.
    guard = ssn_redactor()
    for text in (
        "call 123-456-7890 now",          # phone grouping
        "code 123456789 rejected",        # no hyphens
        "ref 12345-6789 filed",           # 5-4 grouping
        "id 123-45-67890 on file",        # trailing extra digit
        "id 1123-45-67890 on file",       # leading extra digit
    ):
        assert guard(_event(data=text)) is None, text


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = ssn_redactor()
    assert guard(_event(data=None, body=42, payload={"ssn": SECRET})) is None
    assert guard(_event(text=None)) is None
    assert guard(_event(value=["nested", SECRET])) is None


def test_int_value_that_is_an_ssn_without_hyphens_is_not_stringified():
    # An int has no hyphens to match; it is skipped rather than coerced.
    assert ssn_redactor()(_event(data=123456789)) is None


def test_non_dict_args_get_no_opinion():
    assert ssn_redactor()(SensorEvent(action="http_post", args=SECRET)) is None
    assert ssn_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_missing_and_unexpected_attributes_never_raise():
    # An empty event has neither a watched action nor args; odd shapes are
    # skipped, not crashed on.
    assert ssn_redactor()(SensorEvent(action="", args={})) is None
    assert ssn_redactor()(SensorEvent(action="http_post", args={"data": {}})) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "ssn_redact"
    assert MARKER == '[REDACTED SSN]'
    assert PATTERN.search("ssn " + SECRET + " done") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[ssn_redactor()])

    dirty = _event(
        url="https://api.x/y",
        data="the applicant SSN is {} on file".format(SECRET),
    )
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert SECRET not in decision.modified_args["data"]
    assert "url" not in decision.modified_args

    clean = _event(url="https://api.x/y", data="the applicant record is on file")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
