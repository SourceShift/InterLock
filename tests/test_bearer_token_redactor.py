"""Authorization Bearer redaction: mask the credential out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the Bearer-anchored pattern, non-string
and nested input that must be skipped rather than crashed on, and end-to-end
merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.bearer_token_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    bearer_token_redactor,
)

# A structurally plausible opaque bearer credential (>= 16 b64token chars).
TOKEN = "ABCDEFabcdef0123456789xyzXYZ"
AUTH = "Authorization: Bearer " + TOKEN


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_bearer_and_returns_modify():
    decision = bearer_token_redactor()(
        _event(url="https://api.x/y", data="header {} token".format(AUTH))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert TOKEN not in decision.modified_args["data"]
    # Context around the credential survives - only the secret is lost.
    assert "header Authorization:" in decision.modified_args["data"]
    assert "token" in decision.modified_args["data"]


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = bearer_token_redactor()(_event(url="https://api.x/y", data=AUTH))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_credential_is_never_masked():
    # No content key changed, so there is nothing to redact - a credential that
    # only appears in the destination is left to the egress allowlist.
    guard = bearer_token_redactor()
    assert guard(_event(url="https://api.x/" + AUTH, data="clean body")) is None


def test_mask_replaces_scheme_and_token_but_not_the_scheme_word_alone():
    decision = bearer_token_redactor()(_event(body=AUTH))
    assert decision.modified_args["body"] == "Authorization: " + MARKER


def test_multiple_credentials_in_one_field_all_masked():
    decision = bearer_token_redactor()(_event(body="a {} b {}".format(AUTH, AUTH)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert TOKEN not in out


def test_several_content_keys_changed_at_once():
    decision = bearer_token_redactor()(_event(data="d " + AUTH, text="t " + AUTH))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = bearer_token_redactor()(_event(**{key: AUTH}))
        assert decision is not None, key
        assert decision.modified_args == {key: "Authorization: " + MARKER}, key


def test_token_at_end_of_string_without_trailing_space():
    # The character class must not consume the boundary; the token ends cleanly.
    decision = bearer_token_redactor()(_event(data=AUTH))
    assert decision.modified_args["data"].endswith(MARKER)


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = bearer_token_redactor()
    assert guard(_event(url="https://api.x/y", data="header set correctly token")) is None


def test_non_egress_action_carrying_a_credential_is_ignored():
    guard = bearer_token_redactor()
    assert guard(_event(action="read_file", data=AUTH)) is None
    assert guard(_event(action="think", msg=AUTH)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = bearer_token_redactor()(_event(action=action, data=AUTH))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = bearer_token_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": AUTH})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert bearer_token_redactor()(SensorEvent(action="http_post", args=AUTH)) is None
    assert bearer_token_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_scheme_without_a_long_enough_token_gets_no_opinion():
    # "Bearer" in prose, or followed by a short placeholder: not a credential.
    guard = bearer_token_redactor()
    assert guard(_event(data="the scheme is Bearer, not Basic")) is None
    assert guard(_event(data="Authorization: Bearer short")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "bearer_token_redact"
    assert MARKER == "[REDACTED BEARER]"
    assert PATTERN.search("x " + AUTH + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[bearer_token_redactor()])

    dirty = _event(url="https://api.x/y", data="header {} token".format(AUTH))
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert TOKEN not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="header set correctly token")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
