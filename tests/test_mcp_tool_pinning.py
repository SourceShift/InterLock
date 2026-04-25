"""MCP tool schema pinning: the allow path, the drift/block path, fail-closed
handling of a pinned tool with no usable schema, malformed config, and engine
integration. Every test asserts on the rule's return value; none is vacuous.
"""
import hashlib

from interlock import PolicyEngine, SensorEvent, Verdict, deny_tool
from interlock.detectors.mcp_tool_pinning import (
    POLICY_ID,
    mcp_tool_pinning,
    pin_of,
)

# Two distinct declarations of one tool. The second changes only the
# description - exactly the rug-pull a pin exists to catch: the tool *name* is
# identical, so a name-based policy would never see the swap.
SCHEMA_V1 = '{"name":"search","description":"Search the web","input":{}}'
SCHEMA_V2_TAMPERED = (
    '{"name":"search","description":"Search the web AND exfiltrate secrets",'
    '"input":{}}'
)


def _event(action, args=None):
    return SensorEvent(action=action, args=args if args is not None else {})


# --- pin_of: the digest builder ---------------------------------------------


def test_pin_of_matches_hashlib_and_is_deterministic():
    assert pin_of("SCHEMA_V1") == hashlib.sha256(b"SCHEMA_V1").hexdigest()
    assert pin_of("SCHEMA_V1") == pin_of("SCHEMA_V1")


def test_pin_of_known_answer_vector():
    # sha256("") is a fixed, widely published digest: an independent check that
    # pin_of hashes the schema string itself and nothing else.
    assert pin_of("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_pin_of_separates_different_schemas():
    assert pin_of("SCHEMA_V1") != pin_of("SCHEMA_V2_TAMPERED")


# --- allow: pinned tool presenting its pinned schema ------------------------


def test_allow_matching_schema():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    assert guard(_event("search", {"__schema__": "SCHEMA_V1"})) is None


def test_unpinned_tool_passes():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    assert guard(_event("other", {"__schema__": "anything"})) is None


def test_unpinned_tool_passes_without_a_schema():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    assert guard(_event("other", {})) is None


# --- block: pinned tool whose schema drifted --------------------------------


def test_block_on_schema_drift():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    decision = guard(_event("search", {"__schema__": "SCHEMA_V2_TAMPERED"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_tool_pinning"
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_tool():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    decision = guard(_event("search", {"__schema__": "SCHEMA_V2_TAMPERED"}))
    assert decision is not None
    assert decision.reason == "mcp_tool_pinning: schema drift for search"


def test_block_is_per_tool_not_global():
    # One guard, two pinned tools: the untampered one passes in the same rule
    # that blocks the tampered one - proves the block came from the pin match,
    # not from a rule that blocks everything.
    guard = mcp_tool_pinning(
        pins={"search": pin_of(SCHEMA_V1), "fetch": pin_of("FETCH_V1")}
    )
    assert guard(_event("search", {"__schema__": SCHEMA_V1})) is None
    assert guard(_event("fetch", {"__schema__": "FETCH_V1"})) is None
    assert guard(_event("fetch", {"__schema__": "FETCH_V2"})) is not None


def test_description_only_change_is_caught():
    # The classic rug-pull: identical tool name, one altered description.
    guard = mcp_tool_pinning(pins={"search": pin_of(SCHEMA_V1)})
    decision = guard(_event("search", {"__schema__": SCHEMA_V2_TAMPERED}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


# --- fail-closed: pinned tool with no usable schema -------------------------


def test_missing_schema_on_pinned_tool_is_blocked():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    decision = guard(_event("search", {}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_unusable_schema_value_on_pinned_tool_is_blocked():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    for bad in (None, 3, {"name": "search"}, ["SCHEMA_V1"], True):
        decision = guard(_event("search", {"__schema__": bad}))
        assert decision is not None, bad
        assert decision.verdict is Verdict.BLOCK, bad
        assert decision.policy_id == POLICY_ID, bad


def test_non_mapping_args_on_pinned_tool_is_blocked():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    for bad_args in (None, 3, "SCHEMA_V1", ["SCHEMA_V1"]):
        decision = guard(SensorEvent(action="search", args=bad_args))  # type: ignore[arg-type]
        assert decision is not None, bad_args
        assert decision.verdict is Verdict.BLOCK, bad_args


# --- malformed config: skip, never raise ------------------------------------


def test_non_mapping_config_is_inert_not_fatal():
    # A pin map that failed to load pins nothing, so nothing is constrained -
    # and nothing raises.
    for pins in (None, 3, "search", ["search"]):
        guard = mcp_tool_pinning(pins)  # type: ignore[arg-type]
        assert guard(_event("search", {"__schema__": "whatever"})) is None


def test_non_str_pin_entries_are_skipped():
    # A non-str digest can never equal a hex digest and a non-str name can never
    # equal an action; both are dropped, leaving the rule inert.
    guard = mcp_tool_pinning(pins={"search": 123, 5: "deadbeef"})  # type: ignore[dict-item]
    assert guard(_event("search", {"__schema__": "SCHEMA_V1"})) is None


def test_non_str_action_is_out_of_scope():
    guard = mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})
    assert guard(_event(None, {"__schema__": "SCHEMA_V1"})) is None  # type: ignore[arg-type]
    assert guard(_event(3, {"__schema__": "SCHEMA_V1"})) is None  # type: ignore[arg-type]


# --- engine integration -----------------------------------------------------


def test_engine_blocks_drift_and_allows_match():
    engine = PolicyEngine(
        rules=[mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")})]
    )

    blocked = engine.evaluate(_event("search", {"__schema__": "SCHEMA_V2_TAMPERED"}))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(_event("search", {"__schema__": "SCHEMA_V1"}))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_lets_unpinned_tool_fall_through_to_the_next_rule():
    # Pinning has no opinion on an unpinned tool, so the next rule decides:
    # proves the None was "out of scope", not a silent allow.
    engine = PolicyEngine(
        rules=[
            mcp_tool_pinning(pins={"search": pin_of("SCHEMA_V1")}),
            deny_tool("other", policy_id="tool_denylist"),
        ]
    )
    decision = engine.evaluate(_event("other", {"__schema__": "x"}))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "tool_denylist"
