"""Output secret redaction: mask vendor keys out of tool RESULTS without
blocking the send. Covers the MODIFY contract (only changed keys returned, the
destination untouched), each vendor-shaped key, non-string and nested input that
must be skipped rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.output_secret_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    output_secret_redactor,
)

# One key of each vendor shape the pattern recognises.
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
OPENAI_KEY = "sk-abcdefghij0123456789ABCDEF"
GITHUB_KEY = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_secret_and_returns_modify():
    decision = output_secret_redactor()(
        _event(url="https://api.x/y", data="key is " + AWS_KEY)
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert AWS_KEY not in decision.modified_args["data"]
    assert "key is" in decision.modified_args["data"]  # context preserved


def test_spec_example_redacts_and_hides_raw_secret():
    # The exact scenario from the requirement, end to end.
    decision = output_secret_redactor()(
        _event(
            action="http_post",
            url="https://api.x/y",
            data="the config returned AKIAABCDEFGHIJKLMNOP as the access key",
        )
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert MARKER in decision.modified_args["data"]
    assert "AKIAABCDEFGHIJKLMNOP" not in decision.modified_args["data"]


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = output_secret_redactor()(_event(url="https://api.x/y", data=AWS_KEY))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_secret_is_never_masked():
    # No content key changed, so there is nothing to redact - a secret that only
    # appears in the destination is left to the egress allowlist.
    guard = output_secret_redactor()
    assert guard(_event(url=AWS_KEY, data="clean body")) is None


def test_every_vendor_key_shape_is_masked():
    guard = output_secret_redactor()
    for secret in (AWS_KEY, OPENAI_KEY, GITHUB_KEY):
        decision = guard(_event(data="leaked " + secret))
        assert decision is not None, secret
        assert decision.modified_args == {"data": "leaked " + MARKER}, secret


def test_multiple_secrets_in_one_field_all_masked():
    decision = output_secret_redactor()(
        _event(body="a {} b {}".format(AWS_KEY, GITHUB_KEY))
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert AWS_KEY not in out
    assert GITHUB_KEY not in out


def test_several_content_keys_changed_at_once():
    decision = output_secret_redactor()(_event(data="d " + AWS_KEY, text="t " + GITHUB_KEY))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = output_secret_redactor()(_event(**{key: "out " + AWS_KEY}))
        assert decision is not None, key
        assert decision.modified_args == {key: "out " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = output_secret_redactor()
    assert guard(
        _event(url="https://api.x/y", data="the config returned successfully")
    ) is None


def test_non_egress_action_carrying_a_secret_is_ignored():
    guard = output_secret_redactor()
    assert guard(_event(action="read_file", data=AWS_KEY)) is None
    assert guard(_event(action="think", msg=GITHUB_KEY)) is None
    assert guard(_event(action="fs_read", data=OPENAI_KEY)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = output_secret_redactor()(_event(action=action, data=AWS_KEY))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


def test_no_content_key_present_gets_no_opinion():
    # The secret is only in the destination, so nothing to scan.
    assert output_secret_redactor()(_event(action="respond", url="https://api.x/y")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = output_secret_redactor()
    assert guard(_event(action="output", data=None, body=42, payload={"k": AWS_KEY})) is None
    assert guard(_event(action="output", text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert output_secret_redactor()(SensorEvent(action="respond", args=AWS_KEY)) is None
    assert output_secret_redactor()(SensorEvent(action="respond", args=None)) is None


def test_short_non_key_tokens_are_not_masked():
    # A bare "AKIA" or a short sk- run is not credential-shaped; the pattern
    # must not fire on prose that merely mentions the prefix.
    guard = output_secret_redactor()
    assert guard(_event(data="AKIA is the AWS key prefix")) is None
    assert guard(_event(data="sk-short")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "output_secret_redact"
    assert MARKER == "[REDACTED SECRET]"
    assert PATTERN.search("x " + AWS_KEY + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[output_secret_redactor()])

    dirty = _event(url="https://api.x/y", data="key is " + AWS_KEY)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert MARKER in decision.modified_args["data"]
    assert AWS_KEY not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="the config returned successfully")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
