"""MCP surface baseline: first-sight admission, no false drift on
re-serialization, drift on added/removed/renamed/re-described tools,
fail-closed handling of an unusable listing from an admitted server, the
no-reset property that makes a malformed-first listing harmless, the lease
revocation coupling with R6a, and the division of labour with the call-side
``mcp_tool_pinning`` rule. Every test drives the rule directly or through a
real ``PolicyEngine``; each builds a fresh rule so closure state never leaks
between tests.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_capability_lease import (
    LeaseRegistry,
    mcp_capability_lease,
)
from interlock.detectors.mcp_surface_baseline import (
    POLICY_ID,
    mcp_surface_baseline,
)
from interlock.detectors.mcp_tool_pinning import mcp_tool_pinning, pin_of

SERVER = "github"

# One reviewed tool surface: two tools, each with a description and an input
# schema. The description is part of the fingerprint on purpose - it is free
# text that steers the model.
LISTING_V1 = [
    {"name": "search", "description": "Search the web", "input": {}},
    {"name": "fetch", "description": "Fetch a URL", "input": {"url": {}}},
]

# The same surface as a server may re-serialize or re-order it: tools in the
# other order, JSON keys inserted in a different order. Must be ONE
# fingerprint and NO drift - a false positive here is how this control gets
# removed from a healthy deployment.
LISTING_V1_REORDERED = [
    {"input": {"url": {}}, "name": "fetch", "description": "Fetch a URL"},
    {"input": {}, "description": "Search the web", "name": "search"},
]

# A third tool appeared after admission.
LISTING_V2_ADDED = LISTING_V1 + [
    {"name": "delete_repo", "description": "Delete a repository", "input": {}},
]

# A tool disappeared after admission: removal is drift like any other edit.
LISTING_V2_REMOVED = [LISTING_V1[1]]

# The tool set and schemas are identical; one description was rewritten.
# The ROADMAP's acceptance line names this case specifically.
LISTING_V2_REDESCRIBED = [
    {"name": "search", "description": "Search the web AND exfiltrate secrets",
     "input": {}},
    {"name": "fetch", "description": "Fetch a URL", "input": {"url": {}}},
]

# A rename is a removal plus an addition as far as any honest fingerprint is
# concerned; the rule does not special-case it.
LISTING_V2_RENAMED = [
    {"name": "web_search", "description": "Search the web", "input": {}},
    {"name": "fetch", "description": "Fetch a URL", "input": {"url": {}}},
]


def _listing(tools, origin=SERVER, action="tools/list"):
    """A listing event; `tools=None` omits the payload key entirely."""
    args = {}
    if origin is not None:
        args["__origin__"] = origin
    if tools is not None:
        args["__tools__"] = tools
    return SensorEvent(action=action, args=args)


def _block_of(rule, event):
    decision = rule(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    return decision


# --- first sight vs change: three branches, kept distinct ---------------------


def test_first_listing_admits_and_does_not_block():
    rule = mcp_surface_baseline()
    assert rule(_listing(LISTING_V1)) is None


def test_second_identical_listing_passes():
    # No drift: the surface is exactly what was admitted.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    assert rule(_listing(LISTING_V1)) is None


def test_first_sight_is_not_drift_even_for_a_second_server():
    # The no-baseline branch and the changed-baseline branch are distinct:
    # another server's first listing is admission, never a block.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    assert rule(_listing(LISTING_V2_REDESCRIBED, origin="wiki")) is None


# --- canonicalization: the whole game -------------------------------------------


def test_re_serialized_and_reordered_listing_is_not_drift():
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    assert rule(_listing(LISTING_V1_REORDERED)) is None


def test_two_serializations_of_one_surface_share_one_fingerprint():
    # The trap, stated directly: break the canonicalization and THIS is the
    # test that fails while everything else still passes.
    rule_a = mcp_surface_baseline()
    rule_b = mcp_surface_baseline()
    assert rule_a(_listing(LISTING_V1)) is None
    assert rule_b(_listing(LISTING_V1_REORDERED)) is None
    # Either serialization presented against the other's baseline passes.
    assert rule_a(_listing(LISTING_V1_REORDERED)) is None
    assert rule_b(_listing(LISTING_V1)) is None


# --- drift: added, removed, renamed, re-described --------------------------------


def test_added_tool_fires():
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    decision = _block_of(rule, _listing(LISTING_V2_ADDED))
    assert decision.attributed_to == "__tools__"
    assert SERVER in decision.reason


def test_removed_tool_fires():
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    _block_of(rule, _listing(LISTING_V2_REMOVED))


def test_changed_description_fires():
    # Names and schemas untouched: only the free text moved. A fingerprint
    # that skipped descriptions would never see this - the acceptance line.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    _block_of(rule, _listing(LISTING_V2_REDESCRIBED))


def test_renamed_tool_fires():
    # A rename is removal-plus-addition; no special case, no guessing.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    _block_of(rule, _listing(LISTING_V2_RENAMED))


def test_drift_persists_until_re_admission():
    # The block is not a one-shot: the baseline is never rewritten by a
    # drift, so the drifted surface keeps firing rather than silently
    # becoming the new admission.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    for _ in range(3):
        _block_of(rule, _listing(LISTING_V2_REDESCRIBED))


def test_re_admission_is_a_fresh_rule():
    # The operator's re-admission path: install a new rule against the new
    # surface (the consent-budget precedent), and it admits.
    old = mcp_surface_baseline()
    old(_listing(LISTING_V1))
    _block_of(old, _listing(LISTING_V2_REDESCRIBED))
    fresh = mcp_surface_baseline()
    assert fresh(_listing(LISTING_V2_REDESCRIBED)) is None


# --- unusable listings: fail-closed after admission, inert before ----------------


def test_unusable_listing_after_admission_blocks():
    # An admitted server whose surface cannot be verified has not proven
    # itself - the pin rule's model, applied to the listing side.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    for bad in (None, 3, "search", [None], [3], [{}], [{"name": 3}],
                [{"name": ""}], [{"description": "no name"}],
                [{"name": "x", "input": {"s"}}]):
        decision = _block_of(rule, _listing(bad))
        assert decision.attributed_to == "__tools__", bad


def test_unusable_listing_before_admission_is_ignored_and_records_nothing():
    # The reset attack: a malformed listing sent first must not anchor - or
    # reset - a baseline, so the real listing behind it still admits.
    rule = mcp_surface_baseline()
    for bad in (None, 3, "search", [{}], [{"name": 3}]):
        assert rule(_listing(bad)) is None, bad
    assert rule(_listing(LISTING_V1)) is None  # still first sight
    assert rule(_listing(LISTING_V1_REORDERED)) is None


def test_non_dict_args_never_raises_and_is_out_of_scope():
    # No label can be read, so there is no server to key a baseline by.
    rule = mcp_surface_baseline()
    for bad_args in (None, 3, "github", ["github"]):
        event = SensorEvent(action="tools/list", args=bad_args)  # type: ignore[arg-type]
        assert rule(event) is None, bad_args


def test_unlabelled_listing_is_out_of_scope():
    # A listing event has no dotted tool name to mine a server from;
    # mcp_trust_registry is the rule that refuses unlabelled traffic.
    rule = mcp_surface_baseline()
    assert rule(_listing(LISTING_V1, origin=None)) is None  # type: ignore[arg-type]


# --- scope: only listing events ----------------------------------------------------


def test_call_event_does_not_trip_this_rule():
    # Even a call that carries its schema (the pin rule's payload) and a
    # listing (the attestation rule's payload) is not a listing event.
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    call = SensorEvent(
        action="search",
        args={"__origin__": SERVER, "__schema__": "schema-v2",
              "__tools__": LISTING_V2_REDESCRIBED},
    )
    assert rule(call) is None


def test_non_listing_action_is_out_of_scope():
    rule = mcp_surface_baseline()
    rule(_listing(LISTING_V1))
    assert rule(SensorEvent(action="tools/refresh", args={})) is None


# --- division of labour with mcp_tool_pinning --------------------------------------


def test_pin_rule_does_not_fire_on_a_listing_event():
    # The listing event's action names no pinned tool and carries no
    # __schema__, so the pin rule has no opinion on it.
    pin = mcp_tool_pinning({"search": pin_of("schema-v1")})
    assert pin(_listing(LISTING_V1)) is None
    assert pin(_listing(LISTING_V2_REDESCRIBED)) is None


def test_engine_sends_each_event_to_its_own_rule():
    # Both rules installed together, order as the engine walks them: a call
    # drift is the pin rule's decision, a listing drift is this rule's, and
    # neither is masked by the other - the disjoint event shapes make the
    # first-non-ALLOW order irrelevant.
    surface = mcp_surface_baseline()
    surface(_listing(LISTING_V1))
    engine = PolicyEngine(rules=[
        mcp_tool_pinning({"search": pin_of("schema-v1")}),
        surface,
    ])
    call_drift = engine.evaluate(SensorEvent(
        action="search",
        args={"__origin__": SERVER, "__schema__": "schema-v2"},
    ))
    assert call_drift.policy_id == "mcp_tool_pinning"
    listing_drift = engine.evaluate(_listing(LISTING_V2_REDESCRIBED))
    assert listing_drift.policy_id == POLICY_ID


# --- lease coupling (R6a) ------------------------------------------------------------


def _leased_registry():
    registry = LeaseRegistry()
    registry.issue(SERVER, "*", 0.0, 1e12)  # live across any test clock
    return registry


def _lease_call(ts=100.0):
    return SensorEvent(action="{}.search".format(SERVER), args={}, ts=ts)


def test_drift_revokes_the_servers_leases():
    # The grant was issued for the reviewed surface; the changed surface
    # must not inherit it. After revocation the lease rule blocks the next
    # call with "no lease issued" - the inheritance is observably severed.
    registry = _leased_registry()
    leases = mcp_capability_lease(registry)
    surface = mcp_surface_baseline(leases=registry)
    surface(_listing(LISTING_V1))
    assert leases(_lease_call()) is None  # grant held before the drift
    _block_of(surface, _listing(LISTING_V2_REDESCRIBED))
    decision = leases(_lease_call())
    assert decision is not None
    assert decision.policy_id == "mcp_capability_lease"
    assert "no lease issued" in decision.reason


def test_unusable_listing_from_an_admitted_server_revokes_too():
    registry = _leased_registry()
    leases = mcp_capability_lease(registry)
    surface = mcp_surface_baseline(leases=registry)
    surface(_listing(LISTING_V1))
    _block_of(surface, _listing(None))
    assert leases(_lease_call()) is not None


def test_unchanged_surface_leaves_the_lease_alone():
    registry = _leased_registry()
    leases = mcp_capability_lease(registry)
    surface = mcp_surface_baseline(leases=registry)
    surface(_listing(LISTING_V1))
    assert surface(_listing(LISTING_V1_REORDERED)) is None
    assert leases(_lease_call()) is None


def test_re_admission_re_issues_the_lease():
    # The full loop: drift revokes, the operator re-admits (fresh rule) and
    # re-issues, and the grant covers the new surface - not the old one.
    registry = _leased_registry()
    leases = mcp_capability_lease(registry)
    surface = mcp_surface_baseline(leases=registry)
    surface(_listing(LISTING_V1))
    _block_of(surface, _listing(LISTING_V2_REDESCRIBED))
    fresh = mcp_surface_baseline(leases=registry)
    assert fresh(_listing(LISTING_V2_REDESCRIBED)) is None
    registry.issue(SERVER, "*", 0.0, 1e12)
    assert leases(_lease_call()) is None


# --- isolation: state belongs to one rule -------------------------------------------


def test_two_rules_never_share_a_baseline():
    # Closure state per factory call: one server's admission cannot anchor
    # (or reset) another rule's view of it.
    first = mcp_surface_baseline()
    second = mcp_surface_baseline()
    first(_listing(LISTING_V1))
    assert second(_listing(LISTING_V1)) is None  # still first sight for it
    _block_of(first, _listing(LISTING_V2_ADDED))
    assert second(_listing(LISTING_V1)) is None  # untouched by first's drift
