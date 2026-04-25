"""Generated-output email redaction: mask addresses out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the addresses it must catch and the
near-misses it must leave alone, non-string and nested input that must be
skipped rather than crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.output_email_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    output_email_redactor,
)

# A real-looking address: distinctive enough that a substring assertion on it
# cannot be satisfied by the marker itself.
SECRET = "root@corp.example"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_redacts_generated_email_and_returns_modify():
    decision = output_email_redactor()(
        _event(
            action="http_post",
            url="https://api.x/y",
            data="you can contact the admin at {} anytime".format(SECRET),
        )
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert SECRET not in decision.modified_args["data"]


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = output_email_redactor()(
        _event(url="https://api.x/y", data="contact {} now".format(SECRET))
    )
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_prose_around_the_address_is_preserved():
    decision = output_email_redactor()(
        _event(data="reach me at {} for details".format(SECRET))
    )
    assert decision.modified_args["data"] == "reach me at {} for details".format(MARKER)


def test_multiple_addresses_in_one_field_all_masked():
    decision = output_email_redactor()(
        _event(body="write to alice@x.io or bob@y.co today")
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert "alice@x.io" not in out
    assert "bob@y.co" not in out


def test_several_content_keys_changed_at_once():
    decision = output_email_redactor()(
        _event(data="d {}".format(SECRET), text="t other@corp.example")
    )
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = output_email_redactor()(_event(**{key: "out {}".format(SECRET)}))
        assert decision is not None, key
        assert decision.modified_args == {key: "out {}".format(MARKER)}, key


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = output_email_redactor()(_event(action=action, data=SECRET))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = output_email_redactor()
    assert guard(
        _event(
            action="http_post",
            url="https://api.x/y",
            data="you can contact the admin via the portal anytime",
        )
    ) is None


def test_non_egress_action_carrying_the_secret_is_ignored():
    guard = output_email_redactor()
    assert guard(_event(action="read_file", data=SECRET)) is None
    assert guard(_event(action="think", msg="ping {}".format(SECRET))) is None
    assert guard(_event(action="fs_read", content=SECRET)) is None


def test_no_content_key_present_gets_no_opinion():
    # The address is only in the destination, so there is nothing to scan.
    assert output_email_redactor()(
        _event(action="respond", url="https://api.x/y")
    ) is None


def test_destination_key_carrying_the_secret_is_never_masked():
    # No content key changed, so there is nothing to redact - an address that
    # only appears in the destination is left to the egress allowlist.
    guard = output_email_redactor()
    assert guard(_event(action="respond", url=SECRET, data="clean body")) is None


def test_bare_at_sign_prose_is_not_masked():
    # Not address-shaped: no dotted TLD tail, so the pattern must not fire.
    guard = output_email_redactor()
    assert guard(_event(data="user@localhost is not an email here")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = output_email_redactor()
    assert guard(_event(action="output", data=None, body=42, payload={"k": SECRET})) is None
    assert guard(_event(action="output", text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert output_email_redactor()(SensorEvent(action="respond", args=SECRET)) is None
    assert output_email_redactor()(SensorEvent(action="respond", args=None)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "output_email_redact"
    assert MARKER == "[REDACTED EMAIL]"
    assert PATTERN.search("x {} y".format(SECRET)) is not None


# --- end to end through the engine ------------------------------------------


def test_engine_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[output_email_redactor()])

    dirty = _event(
        url="https://api.x/y",
        data="you can contact the admin at {} anytime".format(SECRET),
    )
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert MARKER in decision.modified_args["data"]
    assert SECRET not in decision.modified_args["data"]
    assert "url" not in decision.modified_args

    clean = _event(
        url="https://api.x/y",
        data="you can contact the admin via the portal anytime",
    )
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
