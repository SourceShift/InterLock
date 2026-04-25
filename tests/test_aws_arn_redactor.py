"""AWS ARN redaction guard: mask resource ARNs out of an egress payload without
blocking the send. Covers the MODIFY contract (only changed keys returned, the
destination untouched), the arn:aws: anchored pattern, non-string and nested
input that must be skipped rather than crashed on, and end-to-end merge through
the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.aws_arn_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    aws_arn_redactor,
)

# A real, account-bearing IAM ARN: the account id and role path are the leak.
ARN = "arn:aws:iam::123456789012:role/prod-admin"

# A second, structurally different ARN (region-bearing, colon-tailed resource).
LAMBDA_ARN = "arn:aws:lambda:eu-west-1:210987654321:function:checkout"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_arn_and_returns_modify():
    decision = aws_arn_redactor()(
        _event(url="https://api.x/y", data="role {} was assumed".format(ARN))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert ARN not in decision.modified_args["data"]
    assert "role" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = aws_arn_redactor()(_event(url="https://api.x/y", data="role " + ARN))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_an_arn_is_never_masked():
    # No content key changed, so there is nothing to redact - an ARN that only
    # appears in the destination is left to the egress allowlist.
    guard = aws_arn_redactor()
    assert guard(_event(url="https://api.x/{}".format(ARN), data="clean body")) is None


def test_multiple_arns_in_one_field_all_masked():
    decision = aws_arn_redactor()(_event(body="a {} b {}".format(ARN, LAMBDA_ARN)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert ARN not in out
    assert LAMBDA_ARN not in out


def test_several_content_keys_changed_at_once():
    decision = aws_arn_redactor()(_event(data="d " + ARN, text="t " + LAMBDA_ARN))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = aws_arn_redactor()(_event(**{key: "role " + ARN}))
        assert decision is not None, key
        assert decision.modified_args == {key: "role " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = aws_arn_redactor()
    assert guard(_event(url="https://api.x/y", data="a role was assumed")) is None


def test_non_egress_action_carrying_an_arn_is_ignored():
    guard = aws_arn_redactor()
    assert guard(_event(action="read_file", data=ARN)) is None
    assert guard(_event(action="think", msg=ARN)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = aws_arn_redactor()(_event(action=action, data=ARN))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = aws_arn_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": ARN})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert aws_arn_redactor()(SensorEvent(action="http_post", args=ARN)) is None
    assert aws_arn_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_arn_shaped_string_without_twelve_digit_account_gets_no_opinion():
    # The account field is the anchor: a five-digit account is not an ARN this
    # rule will rewrite, so a version-like fragment is left alone.
    guard = aws_arn_redactor()
    assert guard(_event(data="arn:aws:iam::12345:role/x was assumed")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "aws_arn_redact"
    assert MARKER == "[REDACTED ARN]"
    assert PATTERN.search("x " + ARN + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[aws_arn_redactor()])

    dirty = _event(url="https://api.x/y", data="role " + ARN + " was assumed")
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert ARN not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="a role was assumed")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
