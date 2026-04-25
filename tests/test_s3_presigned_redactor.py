"""S3 presigned-URL signature redaction: mask the capability out of an egress
payload without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the query-anchored ``X-Amz-Signature``
pattern, non-string and nested input that must be skipped rather than crashed
on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.s3_presigned_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    s3_presigned_redactor,
)

# A plausible URL-encoded S3 signature body (>= 16 chars from [A-Za-z0-9%]).
SIG = "abcdef0123456789abcdef"
DIRTY = "fetch https://b.s3.amazonaws.com/k?X-Amz-Signature={} now".format(SIG)
CLEAN = "fetch the object now"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_signature_and_returns_modify():
    decision = s3_presigned_redactor()(
        _event(url="https://api.x/y", data=DIRTY)
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert SIG not in decision.modified_args["data"]
    # Context around the signature survives - only the capability is lost.
    assert "https://b.s3.amazonaws.com/k" in decision.modified_args["data"]


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = s3_presigned_redactor()(_event(url="https://api.x/y", data=DIRTY))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_the_signature_is_never_masked():
    # No content key changed, so there is nothing to redact - a signature that
    # only appears in the destination is left to the egress allowlist.
    guard = s3_presigned_redactor()
    assert guard(_event(url=DIRTY, data="clean body")) is None


def test_mask_replaces_the_parameter_but_keeps_the_leading_delimiter():
    decision = s3_presigned_redactor()(_event(body=DIRTY))
    assert decision.modified_args["body"] == (
        "fetch https://b.s3.amazonaws.com/k" + MARKER + " now"
    )


def test_ampersand_delimited_signature_is_masked():
    # A presigned URL with several params carries the signature after '&'.
    decision = s3_presigned_redactor()(
        _event(data="/k?X-Amz-Expires=300&X-Amz-Signature={}".format(SIG))
    )
    assert decision.modified_args["data"] == "/k?X-Amz-Expires=300" + MARKER


def test_multiple_signatures_in_one_field_all_masked():
    decision = s3_presigned_redactor()(_event(body="a {} b {}".format(DIRTY, DIRTY)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert SIG not in out


def test_several_content_keys_changed_at_once():
    decision = s3_presigned_redactor()(_event(data="d " + DIRTY, text="t " + DIRTY))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = s3_presigned_redactor()(_event(**{key: DIRTY}))
        assert decision is not None, key
        assert decision.modified_args == {key: decision.modified_args[key]}, key
        assert MARKER in decision.modified_args[key], key
        assert SIG not in decision.modified_args[key], key


def test_signature_at_end_of_string_without_trailing_space():
    # The character class must not consume the boundary; the value ends cleanly.
    decision = s3_presigned_redactor()(_event(data="?X-Amz-Signature=" + SIG))
    assert decision.modified_args["data"] == MARKER


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = s3_presigned_redactor()
    assert guard(_event(url="https://api.x/y", data=CLEAN)) is None


def test_non_egress_action_carrying_the_signature_is_ignored():
    guard = s3_presigned_redactor()
    assert guard(_event(action="read_file", data=DIRTY)) is None
    assert guard(_event(action="think", msg=DIRTY)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = s3_presigned_redactor()(_event(action=action, data=DIRTY))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = s3_presigned_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": DIRTY})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert s3_presigned_redactor()(SensorEvent(action="http_post", args=DIRTY)) is None
    assert s3_presigned_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_unanchored_or_short_signature_gets_no_opinion():
    # No query delimiter, or a value below the sixteen-char floor: not a signature.
    guard = s3_presigned_redactor()
    assert guard(_event(data="X-Amz-Signature=" + SIG)) is None
    assert guard(_event(data="?X-Amz-Signature=short")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "s3_presigned_redact"
    assert MARKER == "[REDACTED PRESIGN]"
    assert PATTERN.search("x" + DIRTY + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[s3_presigned_redactor()])

    dirty = _event(url="https://api.x/y", data=DIRTY)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert SIG not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data=CLEAN)
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
