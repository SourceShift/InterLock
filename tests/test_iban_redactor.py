"""IBAN redaction guard: mask checksum-valid bank account numbers out of an
egress payload without blocking the send.

Covers the MODIFY contract (only changed keys returned, the destination
untouched, the surrounding prose preserved), the MOD-97 gate that separates a
real IBAN from a string that merely looks like one, non-string and nested input
that must be skipped rather than crashed on, and end-to-end merge through the
engine.
"""
from types import SimpleNamespace

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.iban_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    iban_redactor,
)

# Canonical German example IBAN; mod-97 == 1, verified by hand.
IBAN = "DE89 3704 0044 0532 0130 00"

# The same account number written without grouping spaces.
IBAN_COMPACT = "DE89370400440532013000"

# A second valid IBAN, different country and length, to prove the check is
# arithmetic rather than a country table.
IBAN_GB = "GB82 WEST 1234 5698 7654 32"

# IBAN with its final check digit corrupted (0 -> 1). Fails MOD-97, and every
# space-delimited prefix of it fails too, so nothing may be masked.
IBAN_BAD = "DE89 3704 0044 0532 0130 01"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_redacts_valid_iban_and_returns_modify():
    decision = iban_redactor()(
        SensorEvent(
            action="http_post",
            args={"url": "https://api.x/y", "data": "pay to {} by friday".format(IBAN)},
        )
    )
    assert decision is not None
    assert decision.modified_args is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert IBAN not in decision.modified_args["data"]
    assert IBAN_COMPACT not in decision.modified_args["data"]
    # The prose the IBAN was embedded in survives the rewrite.
    assert decision.modified_args["data"] == "pay to {} by friday".format(MARKER)


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = iban_redactor()(_event(url="https://api.x/y", data="acct " + IBAN))
    assert decision is not None
    assert decision.modified_args is not None
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_an_iban_is_never_masked():
    # No content key changed, so there is nothing to redact - an IBAN that only
    # appears in the destination is the egress allowlist's concern.
    guard = iban_redactor()
    assert guard(
        _event(url="https://api.x/{}".format(IBAN_COMPACT), data="clean body")
    ) is None


def test_compact_form_is_masked():
    decision = iban_redactor()(_event(data="transfer {} now".format(IBAN_COMPACT)))
    assert decision is not None
    assert decision.modified_args is not None
    assert decision.modified_args["data"] == "transfer {} now".format(MARKER)


def test_second_country_iban_is_masked():
    decision = iban_redactor()(_event(data="ref " + IBAN_GB))
    assert decision is not None
    assert decision.modified_args is not None
    assert decision.modified_args["data"] == "ref " + MARKER


def test_two_ibans_in_one_field_are_both_masked():
    decision = iban_redactor()(_event(body="a {0}; b {1}".format(IBAN, IBAN_GB)))
    assert decision is not None
    assert decision.modified_args is not None
    out = decision.modified_args["body"]
    assert out == "a {0}; b {1}".format(MARKER, MARKER)
    assert IBAN not in out
    assert IBAN_GB not in out


def test_several_content_keys_changed_at_once():
    decision = iban_redactor()(_event(data="d " + IBAN, text="t " + IBAN))
    assert decision is not None
    assert decision.modified_args is not None
    assert set(decision.modified_args) == {"data", "text"}
    assert decision.modified_args["text"] == "t " + MARKER


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = iban_redactor()(_event(**{key: IBAN}))
        assert decision is not None, key
        assert decision.modified_args == {key: MARKER}, key


# --- the MOD-97 gate: shape alone is not enough ----------------------------


def test_iban_with_a_corrupted_check_digit_is_left_intact():
    guard = iban_redactor()
    assert guard(_event(data="pay to {} by friday".format(IBAN_BAD))) is None


def test_shape_without_a_valid_checksum_is_not_masked():
    # Matches the pattern (2 letters, 2 digits, 11+ alphanumerics) but is not a
    # bank account; masking it would corrupt a legitimate payload.
    guard = iban_redactor()
    got = guard(_event(data="ticket AB00 1234 5678 901 logged"))
    assert got is None, getattr(got, "modified_args", None)


def test_lower_case_look_alike_is_not_masked():
    # The pattern is upper-case anchored, so lower-case text is never touched.
    guard = iban_redactor()
    assert guard(_event(data="de89 3704 0044 0532 0130 00")) is None


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = iban_redactor()
    assert guard(_event(url="https://api.x/y", data="pay the invoice by friday")) is None


def test_non_egress_action_carrying_an_iban_is_ignored():
    guard = iban_redactor()
    assert guard(_event(action="read_file", data=IBAN)) is None
    assert guard(_event(action="think", msg=IBAN)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = iban_redactor()(_event(action=action, data=IBAN))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = iban_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": IBAN})) is None
    assert guard(_event(text=None, value=[IBAN])) is None


def test_non_dict_args_get_no_opinion():
    # Malformed events a caller might hand us; both must yield no opinion.
    assert iban_redactor()(SensorEvent(action="http_post", args=IBAN)) is None  # type: ignore[arg-type]
    assert iban_redactor()(SensorEvent(action="http_post", args=None)) is None  # type: ignore[arg-type]


def test_missing_action_is_ignored():
    assert iban_redactor()(SimpleNamespace(args={"data": IBAN})) is None  # type: ignore[arg-type]


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "iban_redact"
    assert MARKER == "[REDACTED IBAN]"
    assert PATTERN.search("x " + IBAN + " y") is not None
    assert PATTERN.search("x " + IBAN_GB + " y") is not None
    assert PATTERN.search("nothing here") is None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[iban_redactor()])

    dirty = SensorEvent(
        action="http_post",
        args={"url": "https://api.x/y", "data": "pay to {} by friday".format(IBAN)},
    )
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args is not None
    assert IBAN not in decision.modified_args["data"]
    assert MARKER in decision.modified_args["data"]
    assert "url" not in decision.modified_args

    clean = SensorEvent(
        action="http_post",
        args={"url": "https://api.x/y", "data": "pay the invoice by friday"},
    )
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
