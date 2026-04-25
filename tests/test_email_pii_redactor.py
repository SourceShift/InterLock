"""Email address redaction guard: mask addresses out of an egress payload without
blocking the send. Covers the MODIFY contract (only changed keys returned, the
destination untouched), the addresses it must catch and the near-misses it must
leave alone, non-string and nested input that must be skipped rather than
crashed on, and end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.email_pii_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    email_pii_redactor,
)

# A real-looking address: distinctive enough that a substring assertion on it
# cannot be satisfied by the marker itself.
SECRET = "jane.doe@corp.example"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_email_and_returns_modify():
    decision = email_pii_redactor()(
        _event(url="https://api.x/y", data="reach me at {} for details".format(SECRET))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert SECRET not in decision.modified_args["data"]
    # Surrounding prose is preserved, only the address is masked.
    assert decision.modified_args["data"] == "reach me at {} for details".format(MARKER)


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = email_pii_redactor()(_event(url="https://api.x/y", data="mail " + SECRET))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_an_email_is_never_masked():
    # No content key changed, so there is nothing to redact - an address that
    # only appears in the destination is left to the egress allowlist.
    guard = email_pii_redactor()
    assert guard(
        _event(url="https://api.x/mailto/{}".format(SECRET), data="clean body")
    ) is None


def test_multiple_addresses_in_one_field_all_masked():
    decision = email_pii_redactor()(
        _event(body="a@b.co and c.d@e.fgh")
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert "a@b.co" not in out
    assert "c.d@e.fgh" not in out


def test_various_address_shapes_are_masked():
    guard = email_pii_redactor()
    for addr in ("plain@example.com", "first.last+tag@sub.example.co.uk",
                 "user_name%x@mail-host.example"):
        decision = guard(_event(data="contact: {}".format(addr)))
        assert decision is not None, addr
        assert addr not in decision.modified_args["data"], addr
        assert decision.modified_args["data"] == "contact: {}".format(MARKER), addr


def test_several_content_keys_changed_at_once():
    decision = email_pii_redactor()(_event(data="d " + SECRET, text="t " + SECRET))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = email_pii_redactor()(_event(**{key: "mail " + SECRET}))
        assert decision is not None, key
        assert decision.modified_args == {key: "mail " + MARKER}, key


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = email_pii_redactor()(_event(action=action, data=SECRET))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = email_pii_redactor()
    assert guard(_event(url="https://api.x/y", data="reach me on the intranet for details")) is None


def test_non_egress_action_carrying_an_email_is_ignored():
    guard = email_pii_redactor()
    assert guard(_event(action="read_file", data=SECRET)) is None
    assert guard(_event(action="think", msg=SECRET)) is None


def test_at_sign_without_a_tld_is_left_alone():
    # A bare ``user@host`` has no dotted domain tail, so it is not an address.
    guard = email_pii_redactor()
    assert guard(_event(data="connect as user@localhost")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = email_pii_redactor()
    assert guard(_event(data=None, body=42, payload={"to": SECRET})) is None
    assert guard(_event(text=None)) is None
    assert guard(_event(value=["nested", SECRET])) is None


def test_non_dict_args_get_no_opinion():
    assert email_pii_redactor()(SensorEvent(action="http_post", args=SECRET)) is None
    assert email_pii_redactor()(SensorEvent(action="http_post", args=None)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "email_redact"
    assert MARKER == "[REDACTED EMAIL]"
    assert PATTERN.search("mail " + SECRET + " done") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[email_pii_redactor()])

    dirty = _event(url="https://api.x/y", data="reach me at {} for details".format(SECRET))
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert SECRET not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="reach me on the intranet for details")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
