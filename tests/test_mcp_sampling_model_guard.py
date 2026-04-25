"""MCP sampling model allowlist: allow/block paths, the fail-closed default for a
missing or malformed model, malformed-input handling, and engine integration."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_sampling_model_guard import (
    POLICY_ID,
    mcp_sampling_model_guard,
)


def _sampling(model=None, args=None):
    if args is None:
        args = {} if model is None else {"model": model}
    return SensorEvent(action="mcp.sampling", args=args)


# --- allow: server samples from an allowlisted model ------------------------


def test_allow_sampling_with_allowlisted_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    assert guard(_sampling("gpt-safe")) is None


def test_allow_is_membership_not_absence_of_opinion():
    # In one guard an approved model passes and an unapproved one does not:
    # proves the None came from the allowlist, not a rule that never blocks.
    guard = mcp_sampling_model_guard({"gpt-safe"})
    assert guard(_sampling("gpt-safe")) is None
    assert guard(_sampling("unapproved-x")) is not None


def test_adding_a_model_flips_block_to_permit():
    strict = mcp_sampling_model_guard({"gpt-safe"})
    widened = mcp_sampling_model_guard({"gpt-safe", "claude-safe"})
    event = _sampling("claude-safe")
    assert strict(event) is not None
    assert widened(event) is None


def test_model_match_is_exact():
    # A look-alike model id is a different routing target, not the approved one.
    guard = mcp_sampling_model_guard({"gpt-safe"})
    assert guard(_sampling("gpt-safe")) is None
    for lookalike in ("gpt-safe-2", "gpt-saf", " gpt-safe", "GPT-SAFE", "gpt.safe"):
        assert guard(_sampling(lookalike)) is not None


def test_bare_string_config_is_wrapped_not_char_split():
    guard = mcp_sampling_model_guard("gpt-safe")
    assert guard(_sampling("gpt-safe")) is None
    assert guard(_sampling("g")) is not None  # not split into single characters


def test_non_str_allowlist_entries_are_skipped_not_admitted():
    guard = mcp_sampling_model_guard(
        ["gpt-safe", None, 3, ["claude-safe"]]  # type: ignore[list-item]
    )
    assert guard(_sampling("gpt-safe")) is None
    assert guard(_sampling("claude-safe")) is not None


# --- block: server samples from an unlisted model ---------------------------


def test_block_sampling_with_unlisted_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    decision = guard(_sampling("unapproved-x"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.policy_id == "mcp_sampling_model"


def test_block_reason_names_the_offending_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    decision = guard(_sampling("unapproved-x"))
    assert decision is not None
    assert decision.reason == "mcp_sampling_model_guard: model unapproved-x not allowed"


# --- out of scope: non-sampling actions -------------------------------------


def test_non_sampling_action_returns_none_even_for_unlisted_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    for action in ("mcp.connect", "mcp.call", "llm.complete", "github.create_issue"):
        event = SensorEvent(action=action, args={"model": "unapproved-x"})
        assert guard(event) is None


def test_non_string_action_is_ignored():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    assert guard(SensorEvent(action=None, args={"model": "unapproved-x"})) is None  # type: ignore[arg-type]
    assert guard(SensorEvent(action=3, args={"model": "unapproved-x"})) is None  # type: ignore[arg-type]


# --- fail-closed: sampling with no usable model -----------------------------


def test_fail_closed_on_missing_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    decision = guard(_sampling(args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_fail_closed_reason_marks_the_missing_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    decision = guard(_sampling(args={}))
    assert decision is not None
    assert decision.reason == "mcp_sampling_model_guard: model <missing> not allowed"


def test_fail_closed_on_non_string_model():
    guard = mcp_sampling_model_guard({"gpt-safe"})
    for model in (None, 3, ["gpt-safe"], {"m": "gpt-safe"}):
        decision = guard(_sampling(args={"model": model}))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_empty_allowlist():
    guard = mcp_sampling_model_guard(set())
    decision = guard(_sampling("gpt-safe"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_none_allowlist_admits_nothing():
    guard = mcp_sampling_model_guard(None)  # type: ignore[arg-type]
    decision = guard(_sampling("gpt-safe"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- malformed input: skip, never raise -------------------------------------


def test_non_mapping_args_are_blocked_not_crashed():
    # A sampling event whose args cannot be read cannot prove its model, so it
    # is denied rather than raising out of the rule.
    guard = mcp_sampling_model_guard({"gpt-safe"})
    for args in (None, 3, ["gpt-safe"], "gpt-safe"):
        decision = guard(_sampling(args=args))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_non_iterable_allowlist_degrades_to_empty():
    # A config that is not iterable must not raise at construction; it yields an
    # empty permit set, which denies every sampling request.
    guard = mcp_sampling_model_guard(3)  # type: ignore[arg-type]
    decision = guard(_sampling("gpt-safe"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_unlisted_and_allows_listed_sampling():
    engine = PolicyEngine(rules=[mcp_sampling_model_guard({"gpt-safe"})])

    blocked = engine.evaluate(_sampling("unapproved-x"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(_sampling("gpt-safe"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fails_closed_on_model_less_sampling():
    engine = PolicyEngine(rules=[mcp_sampling_model_guard({"gpt-safe"})])
    decision = engine.evaluate(_sampling(args={}))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
