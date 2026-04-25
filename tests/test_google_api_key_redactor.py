"""Google API key redaction guard: mask ``AIza``-prefixed keys out of an egress
payload without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the fixed-length pattern, non-string and
nested input that must be skipped rather than crashed on, and end-to-end
evaluation through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.google_api_key_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    google_api_key_redactor,
)

# A real, structurally valid Google API key: the "AIza" prefix plus 35 base64url
# characters.
KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_key_and_returns_modify():
    decision = google_api_key_redactor()(
        _event(url="https://api.x/y", data="maps key {} enabled".format(KEY))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert KEY not in decision.modified_args["data"]
    assert "maps key" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = google_api_key_redactor()(_event(url="https://api.x/y", data=KEY))
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_key_is_never_masked():
    # No content key changed, so there is nothing to redact - a key appearing
    # only in the destination is left to the egress allowlist.
    guard = google_api_key_redactor()
    assert guard(
        _event(url="https://api.x/{}".format(KEY), data="clean body")
    ) is None


def test_multiple_keys_in_one_field_all_masked():
    decision = google_api_key_redactor()(_event(body="a {} b {}".format(KEY, KEY)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert KEY not in out


def test_several_content_keys_changed_at_once():
    decision = google_api_key_redactor()(_event(data="d " + KEY, text="t " + KEY))
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = google_api_key_redactor()(_event(**{key: "key " + KEY}))
        assert decision is not None, key
        assert decision.modified_args == {key: "key " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = google_api_key_redactor()
    assert guard(_event(url="https://api.x/y", data="maps is enabled")) is None


def test_non_egress_action_carrying_a_key_is_ignored():
    guard = google_api_key_redactor()
    assert guard(_event(action="read_file", data=KEY)) is None
    assert guard(_event(action="think", msg=KEY)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = google_api_key_redactor()(_event(action=action, data=KEY))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = google_api_key_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": KEY})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert google_api_key_redactor()(SensorEvent(action="http_post", args=KEY)) is None
    assert google_api_key_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_lookalike_shorter_than_a_real_key_is_not_a_match():
    # "AIza" with fewer than 35 body characters is prose, not a key.
    guard = google_api_key_redactor()
    assert guard(_event(data="the prefix AIzaSyAbc alone")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "google_key_redact"
    assert MARKER == "[REDACTED GOOGLE_KEY]"
    assert PATTERN.search("x " + KEY + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[google_api_key_redactor()])

    dirty = _event(url="https://api.x/y", data="maps key " + KEY)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert KEY not in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="maps is enabled")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
