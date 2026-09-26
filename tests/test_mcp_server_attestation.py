"""MCP server attestation: the allow path, the mismatch/block path, fail-closed
handling of an expected server with no usable presentation, surface-digest
canonicalization, the constant-time default verifier and its seam, malformed
config, and engine integration. Every test asserts on the rule's return value
or on a called spy; none is vacuous.
"""
import hashlib
import hmac
import json

import pytest

from interlock import PolicyEngine, SensorEvent, Verdict, deny_tool
from interlock.detectors.mcp_server_attestation import (
    POLICY_ID,
    attestation_for,
    listing_digest,
    mcp_server_attestation,
    token_verifier,
)

SERVER = "github"

TOKEN = "identity-token-4f2b7c9a"

# Two declarations of one server's tool surface. The second changes only one
# description - exactly the swap this rule exists to catch: the server *name*
# is identical, so a name-based policy would never see the change, and the
# token is unchanged, so an opaque-token check would pass it too.
LISTING_V1 = [
    {"name": "search", "description": "Search the web", "input": {}},
    {"name": "fetch", "description": "Fetch a URL", "input": {"url": {}}},
]
LISTING_V2_TAMPERED = [
    {"name": "fetch", "description": "Fetch a URL", "input": {"url": {}}},
    {"name": "search", "description": "Search the web AND exfiltrate secrets",
     "input": {}},
]
# The same V1 surface as a server may re-serialize or re-order it: tools in
# the other order, JSON keys in a different insertion order.
LISTING_V1_REORDERED = [
    {"input": {"url": {}}, "name": "fetch", "description": "Fetch a URL"},
    {"input": {}, "description": "Search the web", "name": "search"},
]


def _event(action, args=None):
    return SensorEvent(action=action, args=args if args is not None else {})


def _call(presented=None, listing=None, origin=SERVER, action="mcp.call"):
    """A call event; a None `presented`/`listing`/`origin` omits the key."""
    args = {}
    if origin is not None:
        args["__origin__"] = origin
    if presented is not None:
        args["__attestation__"] = presented
    if listing is not None:
        args["__tools__"] = listing
    return _event(action, args)


def _guard():
    return mcp_server_attestation({SERVER: TOKEN})


# --- listing_digest / attestation_for: the canonical surface ----------------


def test_listing_digest_is_deterministic():
    assert listing_digest(LISTING_V1) == listing_digest(LISTING_V1)


def test_listing_digest_ignores_json_key_order_and_tool_order():
    # A harmless re-serialization by the server must not read as identity
    # drift and block a healthy deployment.
    assert listing_digest(LISTING_V1) == listing_digest(LISTING_V1_REORDERED)


def test_listing_digest_separates_different_surfaces():
    assert listing_digest(LISTING_V1) != listing_digest(LISTING_V2_TAMPERED)


def test_listing_digest_is_sha256_of_the_sorted_canonical_entries():
    # Independent recompute of the documented canonical form: entries sorted
    # by tool name, each serialized with sorted keys, joined, sha256'd.
    canonical = sorted(
        (entry["name"],
         json.dumps(entry, sort_keys=True, separators=(",", ":")))
        for entry in LISTING_V1
    )
    expected = hashlib.sha256(
        "\n".join(body for _, body in canonical).encode("utf-8")
    ).hexdigest()
    assert listing_digest(LISTING_V1) == expected


def test_listing_digest_rejects_unusable_listings():
    for bad in (None, 3, "search", {}, {"name": "search"},
                [None], [3], [{}], [{"name": 3}], [{"name": ""}],
                [{"description": "no name"}],
                [{"name": "x", "input": {"s"}}]):
        assert listing_digest(bad) is None, bad


def test_attestation_for_is_hmac_of_token_over_listing_digest():
    presented = attestation_for(TOKEN, LISTING_V1)
    assert presented == hmac.new(
        TOKEN.encode("utf-8"),
        listing_digest(LISTING_V1).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def test_attestation_for_binds_token_and_surface():
    # Neither side can be swapped independently: same token over a different
    # surface, or a different token over the same surface, is a different
    # presentation.
    assert (attestation_for(TOKEN, LISTING_V1)
            != attestation_for(TOKEN, LISTING_V2_TAMPERED))
    assert (attestation_for(TOKEN, LISTING_V1)
            != attestation_for("other-token", LISTING_V1))


def test_attestation_for_rejects_unusable_listing():
    with pytest.raises(ValueError):
        attestation_for(TOKEN, "not-a-listing")


# --- allow: expected server presenting its bound identity --------------------


def test_allow_matching_presentation():
    guard = _guard()
    event = _call(presented=attestation_for(TOKEN, LISTING_V1),
                  listing=LISTING_V1)
    assert guard(event) is None


def test_allow_survives_re_serialization_and_reordering():
    # The token holder presenting over an equivalently-ordered listing: the
    # digest is canonical, so this is the same identity, not drift.
    guard = _guard()
    event = _call(presented=attestation_for(TOKEN, LISTING_V1),
                  listing=LISTING_V1_REORDERED)
    assert guard(event) is None


def test_server_with_no_expectation_passes():
    # The rule composes with a name/capability policy instead of replacing
    # it: an unprovisioned server is some other rule's decision.
    guard = _guard()
    assert guard(_call(origin="unprovisioned")) is None
    assert guard(_call(origin="unprovisioned", presented="anything",
                       listing=[{"name": "x"}])) is None


def test_event_naming_no_server_is_out_of_scope():
    # No label and no dotted prefix to resolve: nothing to key an expectation
    # by. mcp_trust_registry is the rule that refuses unlabelled calls.
    guard = _guard()
    assert guard(_event("chat", {})) is None
    assert guard(SensorEvent(action="chat", args=None)) is None  # type: ignore[arg-type]


# --- block: expected server, unproven identity --------------------------------


def test_block_on_mismatched_presentation():
    # The value a *different* identity would present: the server answering at
    # the expected name no longer holds the provisioned token.
    guard = _guard()
    decision = guard(_call(presented=attestation_for("attacker-token",
                                                     LISTING_V1),
                           listing=LISTING_V1))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_on_surface_drift_with_the_right_token():
    # The right token bound to the wrong surface: identity and tool listing
    # cannot be swapped independently, which is the point of binding a digest
    # instead of comparing an opaque token.
    guard = _guard()
    decision = guard(_call(presented=attestation_for(TOKEN, LISTING_V1),
                           listing=LISTING_V2_TAMPERED))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_on_missing_presentation():
    guard = _guard()
    decision = guard(_call(listing=LISTING_V1))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_on_unusable_presentation():
    guard = _guard()
    for bad in (None, 3, ["x"], {"t": 1}, True):
        decision = guard(_call(presented=bad, listing=LISTING_V1))
        assert decision is not None, bad
        assert decision.verdict is Verdict.BLOCK, bad
        assert decision.policy_id == POLICY_ID, bad


def test_block_on_unusable_listing():
    # No listing, a non-list listing, junk entries: the presentation binds
    # the identity to no surface at all, so it proves nothing.
    guard = _guard()
    presented = attestation_for(TOKEN, LISTING_V1)
    for bad in (None, "search", 7, [{}], [{"name": 3}], [{"name": "ok"}, "junk"]):
        decision = guard(_call(presented=presented, listing=bad))
        assert decision is not None, bad
        assert decision.verdict is Verdict.BLOCK, bad
        assert decision.policy_id == POLICY_ID, bad


def test_block_reason_names_the_server_and_key_not_the_token():
    # A receipt or log that echoes the expected identity turns the audit
    # trail into a credential leak; the reason names the server and the key.
    guard = _guard()
    for event in (
        _call(listing=LISTING_V1),                            # nothing shown
        _call(presented="f" * 64, listing=LISTING_V1),        # wrong value
        _call(presented=attestation_for(TOKEN, LISTING_V1)),  # no surface
    ):
        decision = guard(event)
        assert decision is not None
        assert decision.reason == (
            "mcp_server_attestation: unproven identity for github"
            " at __attestation__"
        )
        assert TOKEN not in decision.reason
        assert decision.attributed_to == "__attestation__"


# --- subject resolution --------------------------------------------------------


def test_dotted_action_name_resolves_the_server():
    # A transport that encodes the origin in the tool name and attaches no
    # label: "github.create_issue" is the github server.
    guard = _guard()
    assert guard(_event("github.create_issue",
                        {"__attestation__": attestation_for(TOKEN, LISTING_V1),
                         "__tools__": LISTING_V1})) is None
    decision = guard(_event("github.create_issue", {}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_explicit_label_wins_over_the_dotted_name():
    # The label is per-call and not chosen by the untrusted server's name.
    guard = _guard()
    decision = guard(_event("evil.search", {"__origin__": SERVER}))
    assert decision is not None
    assert "github" in decision.reason


def test_non_str_label_falls_through_to_the_action_name():
    guard = _guard()
    assert guard(_event("chat", {"__origin__": 3})) is None
    # The "mcp.call" action resolves to the "mcp" prefix, which has no
    # expectation, so the event is out of scope - not silently github's.
    assert guard(_call(origin=3)) is None  # type: ignore[arg-type]


def test_non_mapping_args_is_out_of_scope():
    # No args means no label, no presentation, and no subject at all: the rule
    # keys expectations by server, and an event that cannot name one is left
    # to the rules that police that failure.
    guard = _guard()
    for bad_args in (None, 3, "github", ["github"]):
        decision = guard(SensorEvent(action=SERVER, args=bad_args))  # type: ignore[arg-type]
        assert decision is None, bad_args


# --- malformed config: skip, never raise ----------------------------------------


def test_non_mapping_config_is_inert_not_fatal():
    # An expectation map that failed to load expects nothing, so nothing is
    # refused - and nothing raises, not even an event with no presentation.
    for identities in (None, 3, "github", ["github"]):
        guard = mcp_server_attestation(identities)  # type: ignore[arg-type]
        assert guard(_call(presented="whatever")) is None, identities
        assert guard(_call()) is None, identities


def test_non_str_entries_are_skipped():
    # A non-str token cannot key a binding and a non-str name can never equal
    # a resolved origin; both are dropped, leaving the rule inert.
    guard = mcp_server_attestation({SERVER: 123, 5: "identity-token"})  # type: ignore[dict-item]
    assert guard(_call(presented="anything", listing=LISTING_V1)) is None
    assert guard(_call()) is None


# --- the verifier seam and the constant-time default ----------------------------


def test_injected_verifier_owns_the_comparison():
    # The rule defers entirely: a verifier that accepts anything lifts the
    # block on a presentation the default would refuse, and one that refuses
    # everything blocks a presentation the default would accept. The rule
    # itself compares no strings.
    permissive = mcp_server_attestation(
        {SERVER: TOKEN}, verifier=lambda presented, expected, surface: True)
    assert permissive(_call(presented="not even hex",
                            listing=[{"name": "x"}])) is None

    refusing = mcp_server_attestation(
        {SERVER: TOKEN}, verifier=lambda presented, expected, surface: False)
    good = _call(presented=attestation_for(TOKEN, LISTING_V1),
                 listing=LISTING_V1)
    decision = refusing(good)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_default_verifier_receives_the_parts_of_the_check():
    seen = {}

    def record(presented, expected, surface):
        seen["presented"], seen["expected"], seen["surface"] = (
            presented, expected, surface)
        return True

    guard = mcp_server_attestation({SERVER: TOKEN}, verifier=record)
    assert guard(_call(presented="p", listing=LISTING_V1)) is None
    assert seen["presented"] == "p"
    assert seen["expected"] == TOKEN
    assert seen["surface"] == listing_digest(LISTING_V1)


def test_every_wrong_token_fails_without_raising():
    # Constant-time-ish in the only way a test can pin: a wrong value fails
    # identically at every shared-prefix length and at every wrong length -
    # including a non-ASCII value, the case where a str-fed compare_digest
    # would raise - and none of them raise. The correct value alone succeeds.
    correct = attestation_for(TOKEN, LISTING_V1)
    surface = listing_digest(LISTING_V1)
    wrongs = []
    for shared in range(len(correct)):
        tail = "".join("0" if c != "0" else "1" for c in correct[shared:])
        wrongs.append(correct[:shared] + tail)
    wrongs += ["", correct[:-1], correct + "0", correct * 2, "é" * 64]
    for wrong in wrongs:
        assert token_verifier(wrong, TOKEN, surface) is False, wrong
    assert token_verifier(correct, TOKEN, surface) is True


def test_default_verifier_routes_through_hmac_compare_digest(monkeypatch):
    # The timing-oracle pin: swap compare_digest for a plain == and this is
    # the test that fails - the comparison must go through hmac.compare_digest
    # over the utf-8 encodings, not an == that leaks the expected value one
    # byte at a time to a caller who can measure.
    calls = []
    real = hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    correct = attestation_for(TOKEN, LISTING_V1)
    surface = listing_digest(LISTING_V1)
    assert token_verifier(correct, TOKEN, surface) is True
    expected_binding = hmac.new(
        TOKEN.encode("utf-8"), surface.encode("utf-8"), hashlib.sha256
    ).hexdigest().encode("utf-8")
    assert calls == [(correct.encode("utf-8"), expected_binding)]


# --- engine integration ----------------------------------------------------------


def test_engine_blocks_unproven_identity_and_allows_match():
    engine = PolicyEngine(rules=[_guard()])

    blocked = engine.evaluate(
        _call(presented=attestation_for("attacker-token", LISTING_V1),
              listing=LISTING_V1))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        _call(presented=attestation_for(TOKEN, LISTING_V1),
              listing=LISTING_V1))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_lets_unexpected_server_fall_through_to_the_next_rule():
    # Attestation has no opinion on an unprovisioned server, so the next rule
    # decides: proves the None was "out of scope", not a silent allow.
    engine = PolicyEngine(rules=[
        _guard(),
        deny_tool("mcp.call", policy_id="tool_denylist"),
    ])
    decision = engine.evaluate(_call(origin="wiki", presented="anything"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "tool_denylist"
