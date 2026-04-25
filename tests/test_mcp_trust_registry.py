"""MCP trust registry: origin resolution from both sources, the fail-closed
default for unresolvable origins, malformed-input handling, and engine
integration."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_trust_registry import (
    POLICY_ID,
    mcp_trust_registry,
)


def _event(action="github.create_issue", args=None):
    return SensorEvent(action=action, args=args if args is not None else {})


# --- allow: origin resolves and is trusted ----------------------------------


def test_allow_origin_from_dotted_action():
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="github.create_issue", args={})) is None


def test_allow_origin_from_explicit_arg():
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="search", args={"__origin__": "github"})) is None


def test_allow_is_membership_not_absence_of_opinion():
    # In one guard a trusted origin passes and an untrusted one does not: proves
    # the None came from the registry, not from a rule that never blocks.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="github.create_issue")) is None
    assert guard(_event(action="evil.create_issue")) is not None


def test_adding_an_origin_flips_block_to_permit():
    strict = mcp_trust_registry(trusted={"github"})
    widened = mcp_trust_registry(trusted={"github", "linear"})
    event = _event(action="linear.create_issue")
    assert strict(event) is not None
    assert widened(event) is None


# --- block: origin resolves and is not trusted ------------------------------


def test_block_untrusted_dotted_origin():
    guard = mcp_trust_registry(trusted={"github"})
    decision = guard(_event(action="evil.exfiltrate", args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_trust_registry"
    assert decision.policy_id == POLICY_ID


def test_block_untrusted_explicit_arg():
    guard = mcp_trust_registry(trusted={"github"})
    decision = guard(_event(action="search", args={"__origin__": "evil"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_origin():
    guard = mcp_trust_registry(trusted={"github"})
    decision = guard(_event(action="evil.exfiltrate"))
    assert decision is not None
    assert decision.reason == "mcp_trust_registry: untrusted origin evil"


def test_origin_is_the_first_segment_only():
    # "github.repo.delete" is the github server, not a server named
    # "github.repo": the origin must not be widened by deeper name segments.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="github.repo.delete")) is None
    assert guard(_event(action="github.repo")) is None


def test_origin_match_is_exact_and_case_sensitive():
    # Trusting "github" must not admit the look-alike "Github".
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="github.tool")) is None
    assert guard(_event(action="Github.tool")) is not None


# --- fail-closed: no origin can be resolved ---------------------------------


def test_fail_closed_on_bareword_action():
    guard = mcp_trust_registry(trusted={"github"})
    decision = guard(_event(action="bareword", args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_fail_closed_on_empty_prefix():
    # ".evil" has a separator but no origin segment.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action=".evil")) is not None


def test_fail_closed_on_blank_explicit_origin():
    # A present-but-blank label is not a resolution and not a trust claim.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="search", args={"__origin__": "   "})) is not None


def test_fail_closed_on_empty_registry():
    guard = mcp_trust_registry(trusted=set())
    for action in ("github.create_issue", "bareword", "evil.x"):
        decision = guard(_event(action=action))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


# --- origin precedence ------------------------------------------------------


def test_explicit_arg_wins_over_dotted_prefix():
    # A label that names a trusted server must not launder an untrusted name,
    # nor vice versa: the explicit per-call label is authoritative.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="evil.x", args={"__origin__": "github"})) is None
    assert guard(_event(action="github.x", args={"__origin__": "evil"})) is not None


def test_unusable_explicit_origin_falls_through_to_dotted_prefix():
    # A malformed label is skipped, not fatal: the dotted name still resolves.
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action="github.x", args={"__origin__": 42})) is None
    assert guard(_event(action="evil.x", args={"__origin__": None})) is not None


# --- malformed input: skip, never raise -------------------------------------


def test_non_mapping_args_are_skipped_not_crashed():
    guard = mcp_trust_registry(trusted={"github"})
    for args in (None, 3, ["github"], "github"):
        # Falls through to the dotted action, which is trusted here.
        assert guard(_event(action="github.x", args=args)) is None
        # And the dotted action is untrusted here; the bad args are inert.
        assert guard(_event(action="evil.x", args=args)) is not None


def test_non_string_action_is_blocked_fail_closed():
    guard = mcp_trust_registry(trusted={"github"})
    assert guard(_event(action=None)) is not None  # type: ignore[arg-type]
    assert guard(_event(action=3)) is not None  # type: ignore[arg-type]


def test_bare_string_config_is_wrapped_not_char_split():
    guard = mcp_trust_registry(trusted="github")  # type: ignore[arg-type]
    assert guard(_event(action="github.x")) is None
    assert guard(_event(action="g.x")) is not None  # not split into characters


def test_non_str_registry_entries_are_skipped_not_admitted():
    guard = mcp_trust_registry(
        trusted=["github", None, 3, ["nested"]]  # type: ignore[list-item]
    )
    assert guard(_event(action="github.x")) is None
    assert guard(_event(action="None.x")) is not None


def test_none_config_trusts_nothing():
    guard = mcp_trust_registry(trusted=None)  # type: ignore[arg-type]
    assert guard(_event(action="github.x")) is not None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_untrusted_and_allows_trusted():
    engine = PolicyEngine(rules=[mcp_trust_registry(trusted={"github"})])

    blocked = engine.evaluate(SensorEvent(action="evil.x"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(SensorEvent(action="github.ok"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fails_closed_on_unresolvable_origin():
    engine = PolicyEngine(rules=[mcp_trust_registry(trusted={"github"})])
    decision = engine.evaluate(SensorEvent(action="bareword"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
