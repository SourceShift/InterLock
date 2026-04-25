"""Slack webhook redaction guard: mask webhook URLs out of an egress payload
without blocking the send. Covers the MODIFY contract (only changed keys
returned, the destination untouched), the secret that must be caught, non-string
and nested input that must be skipped rather than crashed on, and end-to-end
merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.slack_webhook_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    slack_webhook_redactor,
)

# A realistic incoming-webhook URL: the path is the bearer capability.
SECRET = (
    "https://hooks.slack.com/services/"
    "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
)


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_slack_webhook_and_returns_modify():
    decision = slack_webhook_redactor()(
        _event(url="https://api.x/y", data="post to " + SECRET)
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert SECRET not in decision.modified_args["data"]
    # Surrounding prose is preserved, only the URL is masked.
    assert decision.modified_args["data"] == "post to " + MARKER


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = slack_webhook_redactor()(
        _event(url="https://api.x/y", data="post to " + SECRET)
    )
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_webhook_is_never_masked():
    # No content key changed, so there is nothing to redact - a webhook that
    # only appears in the destination is left to the egress allowlist.
    guard = slack_webhook_redactor()
    assert guard(_event(url=SECRET, data="clean body")) is None


def test_multiple_webhooks_in_one_field_all_masked():
    decision = slack_webhook_redactor()(
        _event(body="{} and {}".format(SECRET, SECRET))
    )
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert SECRET not in out


def test_several_content_keys_changed_at_once():
    decision = slack_webhook_redactor()(
        _event(data="d " + SECRET, text="t " + SECRET)
    )
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = slack_webhook_redactor()(_event(**{key: "post " + SECRET}))
        assert decision is not None, key
        assert decision.modified_args == {key: "post " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = slack_webhook_redactor()
    assert guard(_event(url="https://api.x/y", data="post to the team channel")) is None


def test_non_egress_action_carrying_a_webhook_is_ignored():
    guard = slack_webhook_redactor()
    assert guard(_event(action="read_file", data=SECRET)) is None
    assert guard(_event(action="think", msg=SECRET)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = slack_webhook_redactor()(_event(action=action, data=SECRET))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = slack_webhook_redactor()
    assert guard(_event(data=None, body=42, payload={"url": SECRET})) is None
    assert guard(_event(text=None)) is None
    assert guard(_event(value=["nested", SECRET])) is None


def test_non_dict_args_get_no_opinion():
    assert slack_webhook_redactor()(SensorEvent(action="http_post", args=SECRET)) is None
    assert slack_webhook_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_non_webhook_slack_url_is_left_alone():
    # A Slack URL that is not an incoming webhook carries no capability here.
    guard = slack_webhook_redactor()
    assert guard(_event(data="docs at https://api.slack.com/methods/chat.postMessage")) is None


def test_short_service_path_is_not_masked():
    # Under the 20-char capability run is not a plausible webhook secret.
    guard = slack_webhook_redactor()
    assert guard(_event(data="https://hooks.slack.com/services/short")) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "slack_webhook_redact"
    assert MARKER == "[REDACTED SLACK_WEBHOOK]"
    assert PATTERN.search("send " + SECRET + " now") is not None
    assert PATTERN.search("https://hooks.slack.com/services/short") is None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[slack_webhook_redactor()])

    dirty = _event(url="https://api.x/y", data="post to " + SECRET)
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert SECRET not in decision.modified_args["data"]
    assert MARKER in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="post to the team channel")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
