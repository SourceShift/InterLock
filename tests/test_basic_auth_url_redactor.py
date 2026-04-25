"""Basic-auth-in-URL redaction: mask ``user:password@`` out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the credential-shaped pattern (a URL with
no password does not match), non-string and nested input that must be skipped
rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.basic_auth_url_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    basic_auth_url_redactor,
)

# A URL with an inline username and password in its authority.
CRED_URL = "https://user:p4ss@internal.example/repo"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_redacts_basic_auth_url_and_returns_modify():
    dirty = _event(
        url="https://api.x/y",
        data="mirror from {} daily".format(CRED_URL),
    )
    decision = basic_auth_url_redactor()(dirty)
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert "p4ss" not in decision.modified_args["data"]
    assert CRED_URL not in decision.modified_args["data"]
    assert "mirror from" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = basic_auth_url_redactor()(_event(url="https://api.x/y", data=CRED_URL))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_cred_url_is_never_masked():
    # No content key changed, so there is nothing to redact - a credential URL
    # that only appears in the destination is left to the egress allowlist.
    guard = basic_auth_url_redactor()
    assert guard(_event(url=CRED_URL, data="clean body")) is None


def test_username_and_password_are_both_removed():
    decision = basic_auth_url_redactor()(_event(body=CRED_URL))
    out = decision.modified_args["body"]
    assert "user" not in out
    assert "p4ss" not in out
    # ``[^\s]+`` consumes the whole URL, so the host and path go with it.
    assert out == MARKER


def test_multiple_cred_urls_in_one_field_all_masked():
    other = "http://admin:hunter2@git.example.net/org/proj.git"
    decision = basic_auth_url_redactor()(
        _event(body="a {} b {}".format(CRED_URL, other))
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert "p4ss" not in out
    assert "hunter2" not in out


def test_several_content_keys_changed_at_once():
    decision = basic_auth_url_redactor()(
        _event(data="d " + CRED_URL, text="t " + CRED_URL)
    )
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = basic_auth_url_redactor()(_event(**{key: "u " + CRED_URL}))
        assert decision is not None, key
        assert decision.modified_args == {key: "u " + MARKER}, key


def test_both_http_and_https_schemes_are_masked():
    guard = basic_auth_url_redactor()
    for url in (
        "https://user:p4ss@internal.example/repo",
        "http://user:p4ss@internal.example/repo",
        "https://user:p4ss@10.0.0.5:8443/path?x=1",
    ):
        decision = guard(_event(data=url))
        assert decision is not None, url
        assert decision.modified_args == {"data": MARKER}, url


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = basic_auth_url_redactor()(_event(action=action, data=CRED_URL))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    clean = _event(
        url="https://api.x/y",
        data="mirror from the internal repo daily",
    )
    assert basic_auth_url_redactor()(clean) is None


def test_url_without_credentials_gets_no_opinion():
    # No ":password@" segment: nothing credential-shaped to mask.
    guard = basic_auth_url_redactor()
    assert guard(_event(data="see https://internal.example/repo for details")) is None
    assert guard(_event(data="https://user@internal.example/repo")) is None


def test_non_egress_action_carrying_the_secret_is_ignored():
    guard = basic_auth_url_redactor()
    assert guard(_event(action="read_file", data=CRED_URL)) is None
    assert guard(_event(action="think", msg=CRED_URL)) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = basic_auth_url_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": CRED_URL})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert basic_auth_url_redactor()(SensorEvent(action="http_post", args=CRED_URL)) is None
    assert basic_auth_url_redactor()(SensorEvent(action="http_post", args=None)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "basic_auth_url_redact"
    assert MARKER == "[REDACTED URL_CREDS]"
    assert PATTERN.search("x " + CRED_URL + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[basic_auth_url_redactor()])

    dirty = _event(url="https://api.x/y", data="mirror from {} daily".format(CRED_URL))
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert "p4ss" not in decision.modified_args["data"]
    assert MARKER in decision.modified_args["data"]

    clean = _event(
        url="https://api.x/y", data="mirror from the internal repo daily"
    )
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
