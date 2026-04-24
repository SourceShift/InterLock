"""PII/secret redaction guard: mask secrets out of an outbound payload without
blocking the send. Covers the MODIFY contract (only changed keys returned), the
pattern set, the Luhn gate that keeps ordinary long numbers intact, list
payloads, custom markers/patterns, and end-to-end merge through the engine."""
import interlock
from interlock import SensorEvent, Verdict, enforce_tool_call
from interlock.detectors.data_egress import (
    PII_REDACTION_POLICY_ID,
    _luhn_ok,
    pii_redaction_guard,
)

# A real Stripe-style test card (Luhn-valid) and a 16-digit non-card id.
VALID_CARD = "4111 1111 1111 1111"
NON_CARD_ID = "1234567890123456"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD\n"
    "-----END RSA PRIVATE KEY-----"
)


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_email_and_returns_modify():
    guard = pii_redaction_guard()
    decision = guard(_event(data="reach me at alice@corp.com"))
    assert decision is not None
    assert decision.verdict == Verdict.MODIFY
    assert decision.policy_id == PII_REDACTION_POLICY_ID
    assert decision.modified_args["data"] == "reach me at [REDACTED EMAIL]"


def test_modify_returns_only_the_changed_field():
    # The destination must survive untouched, or the (now-safe) send breaks.
    guard = pii_redaction_guard()
    decision = guard(_event(url="https://api.internal/ingest", body="ssn 123-45-6789"))
    assert set(decision.modified_args) == {"body"}
    assert "url" not in decision.modified_args


def test_multiple_secrets_in_one_field_all_masked():
    guard = pii_redaction_guard()
    decision = guard(_event(
        data="mail bob@corp.com token sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    ))
    out = decision.modified_args["data"]
    assert "[REDACTED EMAIL]" in out
    assert "[REDACTED OPENAI_KEY]" in out
    assert "bob@corp.com" not in out


# --- precision: the Luhn gate -----------------------------------------------


def test_luhn_accepts_a_card_and_rejects_a_plain_id():
    assert _luhn_ok(VALID_CARD) is True
    assert _luhn_ok(NON_CARD_ID) is False


def test_valid_card_masked_but_ordinary_long_number_kept():
    guard = pii_redaction_guard()
    decision = guard(_event(data="pay {} ref {}".format(VALID_CARD, NON_CARD_ID)))
    out = decision.modified_args["data"]
    assert "[REDACTED CREDIT_CARD]" in out
    assert NON_CARD_ID in out  # not clobbered: Luhn said it is not a card


def test_a_long_id_alone_is_no_opinion():
    guard = pii_redaction_guard()
    assert guard(_event(data="order {}".format(NON_CARD_ID))) is None


# --- structural secrets -----------------------------------------------------


def test_private_key_block_masked_across_newlines():
    guard = pii_redaction_guard()
    decision = guard(_event(body="here is the key\n" + PRIVATE_KEY))
    out = decision.modified_args["body"]
    assert "[REDACTED PRIVATE_KEY]" in out
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_aws_and_slack_and_github_tokens_masked():
    guard = pii_redaction_guard()
    payload = (
        "aws AKIAABCDEFGHIJKLMNOP "
        "gh ghp_0123456789012345678901234567890123AB "
        "slack xoxb-1234567890-abcdEFGH"
    )
    out = guard(_event(data=payload)).modified_args["data"]
    assert "AKIA" not in out
    assert "ghp_" not in out
    assert "xoxb-" not in out


# --- scoping: actions, keys, clean payloads ---------------------------------


def test_clean_payload_gets_no_opinion():
    guard = pii_redaction_guard()
    assert guard(_event(data="just a normal progress update")) is None


def test_non_egress_action_is_ignored():
    # A read carrying an email is not an egress; redaction stays out of it.
    guard = pii_redaction_guard()
    assert guard(_event(action="read_file", data="alice@corp.com")) is None


def test_only_content_keys_are_scanned():
    # An email in the destination key is not a content field, so no MODIFY.
    guard = pii_redaction_guard()
    assert guard(_event(to="alice@corp.com")) is None


def test_non_dict_args_get_no_opinion():
    guard = pii_redaction_guard()
    assert guard(SensorEvent(action="http_post", args="alice@corp.com")) is None


# --- list payloads ----------------------------------------------------------


def test_list_payload_masked_element_wise():
    guard = pii_redaction_guard()
    decision = guard(_event(attachments=["ssn 123-45-6789", "nothing to see"]))
    assert decision.modified_args["attachments"] == [
        "ssn [REDACTED SSN]",
        "nothing to see",
    ]


def test_clean_list_gets_no_opinion():
    guard = pii_redaction_guard()
    assert guard(_event(attachments=["one", "two"])) is None


# --- customisation ----------------------------------------------------------


def test_custom_marker_is_used():
    guard = pii_redaction_guard(marker="<<{kind}>>")
    out = guard(_event(data="mail alice@corp.com")).modified_args["data"]
    assert out == "mail <<EMAIL>>"


def test_custom_patterns_extend_the_defaults():
    import re

    house = (("EMPLOYEE_ID", re.compile(r"\bEMP-\d{5}\b"), None),)
    guard = pii_redaction_guard(patterns=house)
    out = guard(_event(data="user EMP-01234 logged in")).modified_args["data"]
    assert out == "user [REDACTED EMPLOYEE_ID] logged in"


# --- end to end through the engine ------------------------------------------


def test_engine_merges_the_redacted_field_into_the_call():
    # install the guard, then run a tool call through enforce_tool_call and show
    # the arguments the tool actually receives have the secret stripped.
    interlock.install(rules=[pii_redaction_guard()])
    safe = enforce_tool_call(
        "http_post",
        {"url": "https://api.internal/x", "data": "key sk-ABCDEFGHIJKLMNOPQRSTUV"},
    )
    assert safe["url"] == "https://api.internal/x"  # untouched
    assert safe["data"] == "key [REDACTED OPENAI_KEY]"  # merged in
