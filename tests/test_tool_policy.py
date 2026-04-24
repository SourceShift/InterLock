"""Tool-call capability policy: allowlist permit/deny, fail-closed defaults,
the inverse denylist, malformed-config handling, and engine integration."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.tool_policy import (
    ALLOWLIST_POLICY_ID,
    DENYLIST_POLICY_ID,
    tool_allowlist,
    tool_denylist,
)


def _event(action="read_file", args=None):
    return SensorEvent(action=action, args=args or {})


# --- allowlist: permit path -------------------------------------------------


def test_allowlist_permits_a_listed_action():
    guard = tool_allowlist(["read_file", "list_dir"])
    assert guard(_event(action="read_file")) is None


def test_allowlist_permit_is_membership_not_default():
    # In one guard, a listed action passes and an unlisted one does not: proves
    # the None came from the set, not from a rule that never blocks.
    guard = tool_allowlist(["read_file"])
    assert guard(_event(action="read_file")) is None
    assert guard(_event(action="other")) is not None


def test_allowlist_adding_a_name_flips_block_to_permit():
    strict = tool_allowlist(["read_file"])
    widened = tool_allowlist(["read_file", "write_file"])
    event = _event(action="write_file")
    assert strict(event) is not None
    assert widened(event) is None


# --- allowlist: deny path ---------------------------------------------------


def test_allowlist_denies_an_unlisted_action():
    guard = tool_allowlist(["read_file"])
    decision = guard(_event(action="delete_everything"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "tool_allowlist"
    assert decision.policy_id == ALLOWLIST_POLICY_ID


def test_allowlist_deny_uses_the_default_reason():
    guard = tool_allowlist(["read_file"])
    decision = guard(_event(action="ssh_exec"))
    assert decision is not None
    assert decision.reason == "tool not on allowlist"


def test_allowlist_deny_honours_a_custom_reason():
    guard = tool_allowlist(["read_file"], reason="capability not granted")
    decision = guard(_event(action="ssh_exec"))
    assert decision is not None
    assert decision.reason == "capability not granted"


def test_allowlist_blocks_an_unknown_tool_fail_closed():
    # A tool nobody enumerated is denied: the failure mode of least privilege.
    guard = tool_allowlist(["read_file"])
    assert guard(_event(action="never_heard_of_it")) is not None


# --- allowlist: empty is deny-all (fail-closed sanity) ----------------------


def test_empty_allowlist_denies_everything():
    guard = tool_allowlist([])
    for action in ("read_file", "list_dir", "deploy", ""):
        decision = guard(_event(action=action))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_empty_allowlist_blocks_what_a_populated_one_permits():
    # Non-vacuous contrast: the same action is permitted by a populated list and
    # denied by an empty one, so "denies everything" is a property of the set.
    event = _event(action="read_file")
    assert tool_allowlist(["read_file"])(event) is None
    assert tool_allowlist([])(event) is not None


# --- denylist: inverse policy ----------------------------------------------


def test_denylist_blocks_a_named_action():
    guard = tool_denylist(["shell", "exec"])
    decision = guard(_event(action="shell"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "tool_denylist"
    assert decision.policy_id == DENYLIST_POLICY_ID
    assert decision.reason == "tool denied by policy"


def test_denylist_permits_an_unnamed_action():
    guard = tool_denylist(["shell"])
    assert guard(_event(action="read_file")) is None


def test_denylist_honours_a_custom_reason():
    guard = tool_denylist(["shell"], reason="shell disabled by ops")
    decision = guard(_event(action="shell"))
    assert decision is not None
    assert decision.reason == "shell disabled by ops"


def test_denylist_and_allowlist_disagree_on_an_unknown_tool():
    # The core asymmetry: an unknown tool is denied by the allowlist and
    # permitted by the denylist.
    event = _event(action="unknown_tool")
    assert tool_allowlist(["read_file"])(event) is not None
    assert tool_denylist(["shell"])(event) is None


# --- config robustness ------------------------------------------------------


def test_allowlist_accepts_a_bare_string_without_char_splitting():
    guard = tool_allowlist("deploy")
    assert guard(_event(action="deploy")) is None
    assert guard(_event(action="d")) is not None  # not split into characters


def test_denylist_accepts_a_bare_string_without_char_splitting():
    guard = tool_denylist("shell")
    assert guard(_event(action="shell")) is not None
    assert guard(_event(action="s")) is None


def test_non_str_entries_are_skipped_not_admitted():
    guard = tool_allowlist(["read_file", None, 3, ["nested"]])  # type: ignore[list-item]
    assert guard(_event(action="read_file")) is None
    # A non-str action can never equal a str entry, so it is denied.
    assert guard(_event(action=None)) is not None  # type: ignore[arg-type]
    assert guard(_event(action=3)) is not None  # type: ignore[arg-type]


def test_none_config_is_safe():
    # No names given: the allowlist denies all, the denylist denies none.
    assert tool_allowlist(None)(_event(action="read_file")) is not None  # type: ignore[arg-type]
    assert tool_denylist(None)(_event(action="read_file")) is None  # type: ignore[arg-type]


def test_action_match_is_exact_and_case_sensitive():
    # Least privilege: 'READ_FILE' is not the permitted 'read_file', so it is
    # denied. Folding case would widen the list to spellings nobody approved.
    guard = tool_allowlist(["read_file"])
    assert guard(_event(action="read_file")) is None
    assert guard(_event(action="READ_FILE")) is not None


def test_non_string_action_is_blocked_by_allowlist_and_ignored_by_denylist():
    allow = tool_allowlist(["read_file"])
    deny = tool_denylist(["shell"])
    assert allow(_event(action=None)) is not None  # type: ignore[arg-type]
    assert deny(_event(action=None)) is None  # type: ignore[arg-type]


# --- engine integration -----------------------------------------------------


def test_engine_allowlist_permits_listed_and_blocks_unlisted():
    engine = PolicyEngine(rules=[tool_allowlist(["read_file", "list_dir"])])

    allowed = engine.evaluate(_event(action="read_file"))
    assert allowed.verdict is Verdict.ALLOW

    blocked = engine.evaluate(_event(action="delete_file"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == "tool_allowlist"


def test_engine_denylist_blocks_named_and_allows_others():
    engine = PolicyEngine(rules=[tool_denylist(["shell"])])

    blocked = engine.evaluate(_event(action="shell"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == "tool_denylist"

    allowed = engine.evaluate(_event(action="read_file"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_empty_allowlist_blocks_all_traffic():
    engine = PolicyEngine(rules=[tool_allowlist([])])
    for action in ("read_file", "list_dir", "deploy"):
        decision = engine.evaluate(_event(action=action))
        assert decision.verdict is Verdict.BLOCK
        assert decision.policy_id == "tool_allowlist"
