"""JWT redaction guard: mask bearer tokens out of an egress payload without
blocking the send. Covers the MODIFY contract (only changed keys returned, the
destination untouched), the eyJ-anchored pattern, non-string and nested input
that must be skipped rather than crashed on, and end-to-end merge through the
engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.jwt_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    jwt_redactor,
)

# A real, structurally valid JWT (header.payload.signature, all base64url).
JWT = (
    "eyJhbGciOiJIUzI1NiJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N"
)


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_jwt_and_returns_modify():
    decision = jwt_redactor()(
        _event(url="https://api.x/y", data="auth token {}".format(JWT))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert JWT not in decision.modified_args["data"]
    assert "auth token" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = jwt_redactor()(_event(url="https://api.x/y", data="tok " + JWT))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_jwt_is_never_masked():
    # No content key changed, so there is nothing to redact - a JWT that only
    # appears in the destination is left to the egress allowlist.
    guard = jwt_redactor()
    assert guard(_event(url="https://api.x/{}".format(JWT), data="clean body")) is None


def test_multiple_jwts_in_one_field_all_masked():
    decision = jwt_redactor()(_event(body="a {} b {}".format(JWT, JWT)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert JWT not in out


def test_several_content_keys_changed_at_once():
    decision = jwt_redactor()(_event(data="d " + JWT, text="t " + JWT))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = jwt_redactor()(_event(**{key: "token " + JWT}))
        assert decision is not None, key
        assert decision.modified_args == {key: "token " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = jwt_redactor()
    assert guard(_event(url="https://api.x/y", data="the meeting is at noon")) is None


def test_non_egress_action_carrying_a_jwt_is_ignored():
    guard = jwt_redactor()
    assert guard(_event(action="read_file", data=JWT)) is None
    assert guard(_event(action="think", msg=JWT)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = jwt_redactor()(_event(action=action, data=JWT))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = jwt_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": JWT})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert jwt_redactor()(SensorEvent(action="http_post", args=JWT)) is None
    assert jwt_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_str_value_without_a_jwt_gets_no_opinion():
    # "eyJ..." in prose but not three dot-joined segments: not a token.
    guard = jwt_redactor()
    assert guard(_event(data="the key eyJhbGciOiJIUzI1NiJ9 alone")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "jwt_redact"
    assert MARKER == "[REDACTED JWT]"
    assert PATTERN.search("x " + JWT + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[jwt_redactor()])

    dirty = _event(url="https://api.x/y", data="auth token " + JWT)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert JWT not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="the meeting is at noon")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
