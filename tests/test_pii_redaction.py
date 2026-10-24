"""PII/secret redaction guard: mask secrets out of an outbound payload without
blocking the send. Covers the MODIFY contract (only changed keys returned), the
pattern set, the Luhn gate that keeps ordinary long numbers intact, list
payloads, custom markers/patterns, and end-to-end merge through the engine."""
from collections import namedtuple

import pytest

import interlock
from interlock import SensorEvent, Verdict, enforce_tool_call
from interlock.detectors.data_egress import (
    DEFAULT_PII_PATTERNS,
    PII_REDACTION_POLICY_ID,
    _luhn_ok,
    network_egress_guard,
    pii_redaction_guard,
)
from interlock.detectors.tool_output_secret_redactor import PATTERNS as RESULT_PATTERNS
from interlock.masking import Masker, MaskRule, card_number

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


# --- network egress destinations (the shared canonical parser) --------------


def _egress_guard(allowed=("api.acme.com",), **kwargs):
    return network_egress_guard(list(allowed), **kwargs)


def test_network_egress_allows_the_allowlisted_host():
    guard = _egress_guard()
    assert guard(_event("http_post", url="https://api.acme.com/x")) is None


def test_network_egress_backslash_differential_blocks():
    # urlparse names api.acme.com; the runtime reaches evil.example.
    guard = _egress_guard()
    decision = guard(_event("http_post", url=r"https://evil.example\@api.acme.com/x"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "url"


def test_network_egress_benign_backslash_counterpart_is_allowed():
    guard = _egress_guard()
    assert guard(_event("http_post", url=r"https://api.acme.com\@evil.example/x")) is None


def test_network_egress_denies_an_extra_cc_recipient():
    guard = _egress_guard()
    decision = guard(
        _event("http_post", url="https://api.acme.com/x", cc="b@evil.example")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "cc"


def test_network_egress_denies_an_extra_bcc_recipient():
    guard = _egress_guard()
    decision = guard(
        _event("send_email", to="a@api.acme.com", bcc="b@evil.example")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "bcc"


def test_network_egress_denies_a_proxy_destination():
    guard = _egress_guard()
    decision = guard(
        _event("http_post", url="https://api.acme.com/x", proxy="http://evil.example:8080")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "proxy"


def test_network_egress_denies_any_bad_entry_in_a_url_list():
    guard = _egress_guard()
    decision = guard(
        _event(
            "http_post",
            url="https://api.acme.com/x",
            url_list=["https://api.acme.com/a", "https://evil.example/b"],
        )
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "url_list"


def test_network_egress_denies_urls_scalar_or_list():
    guard = _egress_guard()
    assert guard(_event("http_post", urls="https://evil.example/x")) is not None
    assert guard(
        _event("http_post", urls=["https://api.acme.com/a", "https://evil.example/b"])
    ) is not None
    assert guard(_event("http_post", urls=["https://api.acme.com/a"])) is None


def test_network_egress_denies_endpoints():
    guard = _egress_guard()
    decision = guard(_event("http_post", endpoints="https://evil.example/x"))
    assert decision is not None
    assert decision.attributed_to == "endpoints"


def test_network_egress_action_matching_is_case_insensitive():
    guard = _egress_guard()
    assert guard(_event("HTTP_POST", url="https://evil.example/x")) is not None
    assert guard(_event("HTTP_POST", url="https://api.acme.com/x")) is None


def test_network_egress_covers_http_patch_by_default():
    guard = _egress_guard()
    assert guard(_event("http_patch", url="https://evil.example/x")) is not None


def test_network_egress_custom_action_name_keeps_working():
    guard = _egress_guard(egress_actions=["Fetch_URL"])
    assert guard(_event("fetch_url", url="https://evil.example/x")) is not None
    assert guard(_event("FETCH_URL", url="https://api.acme.com/x")) is None
    # Only the named action is in scope; a near-miss is left alone.
    assert guard(_event("fetch_urls", url="https://evil.example/x")) is None


def test_network_egress_denies_an_action_with_no_destination():
    guard = _egress_guard()
    decision = guard(_event("http_post", note="nothing to vet here"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_network_egress_non_string_action_gets_no_opinion():
    guard = _egress_guard()
    assert guard(SensorEvent(action=3, args={"url": "https://evil.example/x"})) is None  # type: ignore[arg-type]


# --- nested payloads (A19) ---------------------------------------------------


def _nested(value, levels):
    for _ in range(levels):
        value = {"nested": value}
    return value


def test_nested_dict_payload_is_masked_with_keys_intact():
    guard = pii_redaction_guard()
    decision = guard(_event(body={"card": VALID_CARD, "note": "ok"}))
    assert decision is not None and decision.verdict is Verdict.MODIFY
    body = decision.modified_args["body"]
    assert body["card"] == "[REDACTED CREDIT_CARD]"
    assert body["note"] == "ok"
    assert set(body) == {"card", "note"}


def test_list_of_dicts_payload_is_masked():
    guard = pii_redaction_guard()
    decision = guard(_event(attachments=[{"card": VALID_CARD}, {"note": "ok"}]))
    out = decision.modified_args["attachments"]
    assert out[0]["card"] == "[REDACTED CREDIT_CARD]"
    assert out[1]["note"] == "ok"


def test_tuple_payload_stays_a_tuple():
    guard = pii_redaction_guard()
    decision = guard(_event(attachments=({"card": VALID_CARD}, "clean")))
    out = decision.modified_args["attachments"]
    assert isinstance(out, tuple)
    assert out[0]["card"] == "[REDACTED CREDIT_CARD]"
    assert out[1] == "clean"


def test_a_namedtuple_payload_is_redacted_without_raising():
    Point = namedtuple("Point", "card note")
    guard = pii_redaction_guard()
    decision = guard(_event(body=[Point(VALID_CARD, "ok")]))
    out = decision.modified_args["body"]
    # A tuple subclass cannot take an iterable in its constructor, so it is
    # rebuilt as a list rather than raising out of the guard.
    assert out[0][0] == "[REDACTED CREDIT_CARD]"
    assert out[0][1] == "ok"


def test_depth_bound_leaves_deeper_values_untouched():
    guard = pii_redaction_guard()
    # The content value is depth 0; five dicts put the card at depth 5.
    assert guard(_event(body=_nested(VALID_CARD, 5))) is not None
    # Six dicts put it at depth 6, which is past the bound: no MODIFY at all.
    assert guard(_event(body=_nested(VALID_CARD, 6))) is None


def test_clean_nested_payload_gets_no_opinion():
    guard = pii_redaction_guard()
    assert guard(_event(body={"card": NON_CARD_ID, "note": "ok"})) is None


# --- a card number followed by a tail (A19) ---------------------------------


def test_card_number_accepts_a_tail_but_a_plain_id_is_not_a_card():
    assert card_number("4111 1111 1111 1111 123") is True
    assert _luhn_ok("4111 1111 1111 1111 123") is True
    assert card_number(NON_CARD_ID) is False


@pytest.mark.parametrize("card_with_tail", [
    "4111 1111 1111 1111 123",
    "4111111111111111 123",
])
def test_card_followed_by_a_cvv_is_masked_whole(card_with_tail):
    guard = pii_redaction_guard()
    out = guard(_event(data="pay " + card_with_tail + " now")).modified_args["data"]
    assert out == "pay [REDACTED CREDIT_CARD] now"


def test_masker_entity_masks_a_card_and_its_cvv_tail():
    masked, counts = Masker([MaskRule(entities=["CREDIT_CARD"])]).mask_text(
        "pay 4111 1111 1111 1111 123 now"
    )
    assert masked == "pay [REDACTED:CREDIT_CARD] now"
    assert counts == {"CREDIT_CARD": 1}


# --- current vendor key prefixes (A19) --------------------------------------


@pytest.mark.parametrize("token", [
    "sk-proj-" + "a" * 24,
    "sk-ant-api03-" + "b" * 24,
    "github_pat_" + "c" * 30,
    "gho_" + "d" * 20,
])
def test_current_vendor_key_prefixes_are_masked(token):
    guard = pii_redaction_guard()
    decision = guard(_event(data="token " + token))
    assert decision is not None
    assert token not in decision.modified_args["data"]


@pytest.mark.parametrize("token", ["sk-short", "ghp_" + "e" * 10])
def test_short_key_lookalikes_are_not_masked(token):
    guard = pii_redaction_guard()
    assert guard(_event(data="token " + token)) is None


def test_the_three_key_prefix_tables_agree():
    egress_kinds = {kind: regex for kind, regex, _ in DEFAULT_PII_PATTERNS}
    result_kinds = {kind: regex for kind, regex, _ in RESULT_PATTERNS}
    # (egress kind, masking kind, an accepted value)
    cases = (
        ("OPENAI_KEY", "API_KEY", "sk-proj-" + "f" * 24),
        ("GITHUB_TOKEN", "GITHUB_TOKEN", "github_pat_" + "g" * 30),
    )
    for egress_kind, masking_kind, token in cases:
        assert egress_kinds[egress_kind].search(token), egress_kind
        assert result_kinds[masking_kind].search(token), masking_kind
        assert Masker().find(token, [masking_kind]), masking_kind
