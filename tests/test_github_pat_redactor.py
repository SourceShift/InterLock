"""GitHub token redaction guard: mask personal/OAuth access tokens out of an
egress payload without blocking the send. Covers the MODIFY contract (only
changed keys returned, the destination untouched), the gh*_ anchored pattern,
non-string and non-dict input that must be skipped rather than crashed on, and
end-to-end merge through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.github_pat_redactor import (
    CONTENT_KEYS,
    EGRESS_ACTIONS,
    MARKER,
    PATTERN,
    POLICY_ID,
    github_pat_redactor,
)

# A classic personal access token: gh + p + underscore + 36-char body.
TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


# --- the modify contract ----------------------------------------------------


def test_masks_token_and_returns_modify():
    decision = github_pat_redactor()(
        _event(url="https://api.x/y", data="clone with {} now".format(TOKEN))
    )
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert MARKER in decision.modified_args["data"]
    assert TOKEN not in decision.modified_args["data"]
    assert "clone" in decision.modified_args["data"]  # context preserved


def test_modify_returns_only_the_changed_content_key():
    # The destination must survive untouched, or the (now-safe) send breaks.
    decision = github_pat_redactor()(
        _event(url="https://api.x/y", data="token " + TOKEN)
    )
    assert set(decision.modified_args) == {"data"}
    assert "url" not in decision.modified_args


def test_destination_key_carrying_a_token_is_never_masked():
    # No content key changed, so there is nothing to redact - a token that only
    # appears in the destination is left to the egress allowlist.
    guard = github_pat_redactor()
    assert guard(
        _event(url="https://api.x/{}".format(TOKEN), data="clean body")
    ) is None


def test_every_prefix_variant_is_masked():
    for prefix in ("ghp", "gho", "ghu", "ghs", "ghr"):
        token = "{}_{}".format(
            prefix, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )
        decision = github_pat_redactor()(_event(data="token " + token))
        assert decision is not None, prefix
        assert decision.modified_args == {"data": "token " + MARKER}, prefix


def test_multiple_tokens_in_one_field_all_masked():
    other = "ghs_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
    decision = github_pat_redactor()(_event(body="a {} b {}".format(TOKEN, other)))
    out = decision.modified_args["body"]
    assert out.count(MARKER) == 2
    assert TOKEN not in out
    assert other not in out


def test_several_content_keys_changed_at_once():
    other = "gho_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
    decision = github_pat_redactor()(
        _event(data="d " + TOKEN, text="t " + other)
    )
    assert set(decision.modified_args) == {"data", "text"}


def test_every_declared_content_key_is_scanned():
    for key in CONTENT_KEYS:
        decision = github_pat_redactor()(_event(**{key: "token " + TOKEN}))
        assert decision is not None, key
        assert decision.modified_args == {key: "token " + MARKER}, key


# --- no-opinion paths -------------------------------------------------------


def test_clean_payload_gets_no_opinion():
    guard = github_pat_redactor()
    assert guard(_event(url="https://api.x/y", data="clone the repo now")) is None


def test_non_egress_action_carrying_a_token_is_ignored():
    guard = github_pat_redactor()
    assert guard(_event(action="clone_repo", data=TOKEN)) is None
    assert guard(_event(action="think", msg=TOKEN)) is None


def test_every_declared_egress_action_is_watched():
    for action in EGRESS_ACTIONS:
        decision = github_pat_redactor()(_event(action=action, data=TOKEN))
        assert decision is not None, action
        assert decision.verdict is Verdict.MODIFY, action


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_content_values_are_skipped():
    guard = github_pat_redactor()
    assert guard(_event(data=None, body=42, payload={"nested": TOKEN})) is None
    assert guard(_event(text=None)) is None


def test_non_dict_args_get_no_opinion():
    assert github_pat_redactor()(SensorEvent(action="http_post", args=TOKEN)) is None
    assert github_pat_redactor()(SensorEvent(action="http_post", args=None)) is None


def test_short_body_is_not_a_token():
    # The exact thirty-six-character body is the anchor: a short gh*_ fragment
    # is not a token this rule will rewrite.
    guard = github_pat_redactor()
    assert guard(_event(data="ghp_short")) is None


def test_token_glued_to_a_word_is_not_matched():
    # The leading word boundary keeps an embedded fragment from matching.
    guard = github_pat_redactor()
    assert guard(_event(data="nota" + TOKEN)) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "github_pat_redact"
    assert MARKER == "[REDACTED GH_TOKEN]"
    assert PATTERN.search("x " + TOKEN + " y") is not None


# --- end to end through the engine ------------------------------------------


def test_engine_returns_modify_for_dirty_and_allow_for_clean():
    engine = PolicyEngine(rules=[github_pat_redactor()])

    dirty = _event(url="https://api.x/y", data="clone with " + TOKEN + " now")
    decision = engine.evaluate(dirty)
    assert decision.verdict is Verdict.MODIFY
    assert TOKEN not in decision.modified_args["data"]
    assert MARKER in decision.modified_args["data"]

    clean = _event(url="https://api.x/y", data="clone the repo now")
    assert engine.evaluate(clean).verdict is Verdict.ALLOW
