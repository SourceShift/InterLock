"""A2A policy dimension (R28): the peer allowlist, the agent-card baseline, the
fail-closed defaults for malformed peers and cards, the declarative ``a2a``
condition, and engine integration."""
import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.a2a_policy import (
    POLICY_ID,
    a2a_card_guard,
    a2a_peer_allowlist,
    card_digest,
    peer_host,
)
from interlock.policy.declarative import PolicyError, load_policy

_CARD_ID = "a2a_card_guard"


def _send(peer=None, args=None):
    if args is None:
        args = {} if peer is None else {"peer": peer}
    return SensorEvent(action="a2a_send", args=args)


def _card(peer, card, extra=None):
    args = {"peer": peer, "card": card}
    if extra:
        args.update(extra)
    return SensorEvent(action="a2a_send", args=args)


def _verdict(engine, event):
    return engine.evaluate(event).verdict


# --- peer_host: one normalisation for config and event ----------------------


def test_peer_host_normalises_full_uri_and_bare_host_alike():
    assert peer_host("peer://trusted.example") == "trusted.example"
    assert peer_host("trusted.example") == "trusted.example"


def test_peer_host_is_case_insensitive_and_drops_transport_detail():
    assert peer_host("peer://Trusted.Example:8443/path") == "trusted.example"
    assert peer_host("peer://trusted.example/send?x=1") == "trusted.example"


def test_peer_host_keeps_the_real_host_not_a_userinfo_lookalike():
    assert peer_host("peer://evil.example@trusted.example") == "trusted.example"


def test_peer_host_rejects_unusable_values():
    for value in (None, 3, ["peer://x"], "", "   ", "peer://[::1"):
        assert peer_host(value) is None


def test_peer_host_does_not_end_a_non_special_authority_at_a_backslash():
    # peer: is not a special scheme, so the WHATWG backslash-delimiter rule
    # does not apply: the backslash stays in the authority and the last @ is
    # the userinfo separator. A backslash in the host itself is un-vettable.
    assert peer_host(r"peer://evil.example\@trusted.example") == "trusted.example"
    assert peer_host(r"peer://trusted.example\@evil.example") == "evil.example"
    assert peer_host(r"peer://host\evil") is None


# --- allow: send to an allowlisted peer -------------------------------------


def test_allow_send_to_allowlisted_peer_full_uri_entry():
    # The smoke passes the allowlist as a full URI; both sides normalise.
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(_send("peer://trusted.example")) is None


def test_allow_is_membership_not_absence_of_opinion():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(_send("peer://trusted.example")) is None
    assert guard(_send("peer://evil.example")) is not None


def test_allow_accepts_bare_host_entries():
    guard = a2a_peer_allowlist(allowed=["trusted.example"])
    assert guard(_send("peer://trusted.example")) is None
    assert guard(_send("peer://evil.example")) is not None


def test_allow_ignores_scheme_path_query_and_port():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    for peer in (
        "peer://trusted.example/send",
        "peer://trusted.example:8443/v2/send?token=abc",
        "a2a://trusted.example",
    ):
        assert guard(_send(peer)) is None


def test_host_match_is_case_insensitive():
    guard = a2a_peer_allowlist(allowed=["peer://TRUSTED.example"])
    assert guard(_send("peer://trusted.example")) is None


def test_backslash_in_userinfo_follows_the_last_at_rule():
    # peer: is not a special scheme, so a backslash does not end the
    # authority; the last @ still separates userinfo from the host. Each
    # spelling therefore names the host after the final @.
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(_send(r"peer://trusted.example\@evil.example")) is not None
    assert guard(_send(r"peer://evil.example\@trusted.example")) is None


def test_adding_a_peer_flips_block_to_permit():
    strict = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    widened = a2a_peer_allowlist(allowed=["peer://trusted.example", "peer://partner.example"])
    event = _send("peer://partner.example")
    assert strict(event) is not None
    assert widened(event) is None


# --- block: send to an unlisted peer ----------------------------------------


def test_block_send_to_unlisted_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    decision = guard(_send("peer://evil.example"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "a2a_peer_allowlist"
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    decision = guard(_send("peer://evil.example"))
    assert decision is not None
    assert "evil.example" in decision.reason


def test_attributed_to_is_the_argument_name_not_the_peer_value():
    # enforce.py: attributed_to names the argument, never its value, so the
    # peer URI cannot leak through a diagnostic field.
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    decision = guard(_send("peer://evil.example"))
    assert decision is not None
    assert decision.attributed_to == "peer"
    assert "peer://evil.example" not in (decision.attributed_to or "")


def test_exact_host_only_a_lookalike_peer_is_not_admitted():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(_send("peer://trusted.example.evil.example")) is not None
    assert guard(_send("peer://evil.example")) is not None


def test_backslash_in_the_host_is_un_vettable():
    # A non-special authority does not end at a backslash: it stays in the
    # host and is rejected, so the guard never reads the misleading prefix as
    # the peer even when that prefix would be allowlisted.
    guard = a2a_peer_allowlist(allowed=["peer://host"])
    decision = guard(_send(r"peer://host\evil"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert "<unknown>" in decision.reason
    assert decision.attributed_to == "peer"


def test_percent_encoded_peer_does_not_resolve_to_a_lookalike():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(_send("peer://trusted.example%2eevil.example")) is not None


# --- out of scope: non-send actions -----------------------------------------


def test_non_send_action_returns_none_even_for_an_evil_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    for action in ("mcp.connect", "http.post", "a2a_receive", "read_file"):
        event = SensorEvent(action=action, args={"peer": "peer://evil.example"})
        assert guard(event) is None


# --- fail-closed: no usable peer on a send ----------------------------------


def test_fail_closed_on_missing_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    decision = guard(_send(args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_non_string_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    for peer in (None, 3, ["peer://trusted.example"], {"h": "trusted.example"}):
        decision = guard(_send(args={"peer": peer}))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_unparseable_peer():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    for peer in ("", "   ", "peer://", "peer://[::1"):
        decision = guard(_send(peer))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_empty_and_none_and_malformed_allowlist():
    for allowed in ([], set(), None, 3):
        guard = a2a_peer_allowlist(allowed=allowed)
        decision = guard(_send("peer://trusted.example"))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_non_mapping_args_are_skipped_not_crashed():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    for args in (None, 3, ["peer://trusted.example"], "peer://trusted.example"):
        decision = guard(_send(args=args))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_non_string_action_is_ignored():
    guard = a2a_peer_allowlist(allowed=["peer://trusted.example"])
    assert guard(SensorEvent(action=None, args={"peer": "peer://evil.example"})) is None  # type: ignore[arg-type]
    assert guard(SensorEvent(action=3, args={"peer": "peer://evil.example"})) is None  # type: ignore[arg-type]


def test_bare_string_config_is_wrapped_not_char_split():
    guard = a2a_peer_allowlist(allowed="peer://trusted.example")
    assert guard(_send("peer://trusted.example")) is None
    assert guard(_send("peer://t.example")) is not None  # not split into chars


def test_non_str_allowlist_entries_are_skipped_not_admitted():
    guard = a2a_peer_allowlist(
        allowed=["peer://trusted.example", None, 3, ["peer://evil.example"]]  # type: ignore[list-item]
    )
    assert guard(_send("peer://trusted.example")) is None
    assert guard(_send("peer://evil.example")) is not None


# --- card_digest: the reviewed-field fingerprint ----------------------------


def test_card_digest_is_order_independent_and_stable():
    a = card_digest({"name": "A", "description": "d", "skills": ["s1"], "url": "x"})
    b = card_digest({"url": "x", "skills": ["s1"], "description": "d", "name": "A"})
    assert a is not None and a == b


def test_card_digest_ignores_fields_outside_the_reviewed_set():
    # A nonce/version churn outside name/description/skills is not drift.
    a = card_digest({"name": "A", "version": "1"})
    b = card_digest({"name": "A", "version": "2"})
    assert a is not None and a == b


def test_card_digest_changes_on_each_reviewed_field():
    base = {"name": "A", "description": "d", "skills": ["read"]}
    d0 = card_digest(base)
    assert card_digest({**base, "name": "B"}) != d0
    assert card_digest({**base, "description": "e"}) != d0
    assert card_digest({**base, "skills": ["read", "write"]}) != d0


def test_card_digest_rejects_unusable_cards():
    for card in (None, 3, "x", [], {}, {"unreviewed": 1}, {"name": {1, 2}}):
        assert card_digest(card) is None


# --- card guard: admit first, block drift -----------------------------------


def test_first_card_admits_and_does_not_block():
    guard = a2a_card_guard()
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read"]})) is None


def test_second_identical_card_passes():
    guard = a2a_card_guard()
    card = {"name": "A", "description": "d", "skills": ["read"]}
    assert guard(_card("peer://a.example", card)) is None
    assert guard(_card("peer://a.example", dict(card))) is None


def test_reordered_card_field_order_does_not_fire():
    guard = a2a_card_guard()
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read"]})) is None
    assert guard(_card("peer://a.example", {"skills": ["read"], "name": "A"})) is None


@pytest.mark.parametrize("change", [
    {"name": "Evil"},
    {"description": "now exfiltrates"},
    {"skills": ["read", "write"]},
])
def test_changed_card_field_fires(change):
    guard = a2a_card_guard()
    card = {"name": "A", "description": "d", "skills": ["read"]}
    assert guard(_card("peer://a.example", card)) is None
    decision = guard(_card("peer://a.example", {**card, **change}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == _CARD_ID
    assert decision.attributed_to == "card"


def test_skill_set_change_is_flagged():
    guard = a2a_card_guard()
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read"]})) is None
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read", "shell"]})) is not None


def test_drift_persists_until_re_admission():
    guard = a2a_card_guard()
    card = {"name": "A", "skills": ["read"]}
    assert guard(_card("peer://a.example", card)) is None
    changed = {"name": "A", "skills": ["read", "write"]}
    assert guard(_card("peer://a.example", changed)) is not None
    # the old baseline stands: the changed card keeps failing, it did not slide.
    assert guard(_card("peer://a.example", changed)) is not None


def test_re_admission_is_a_fresh_rule():
    card = {"name": "A", "skills": ["read"]}
    changed = {"name": "A", "skills": ["read", "write"]}
    first = a2a_card_guard()
    assert first(_card("peer://a.example", card)) is None
    assert first(_card("peer://a.example", changed)) is not None
    # A fresh factory call adopts the new card as its baseline.
    second = a2a_card_guard()
    assert second(_card("peer://a.example", changed)) is None


def test_seeded_baseline_blocks_a_different_card():
    card = {"name": "A", "skills": ["read"]}
    guard = a2a_card_guard(cards={"peer://a.example": card})
    assert guard(_card("peer://a.example", card)) is None
    assert guard(_card("peer://a.example", {"name": "Evil", "skills": ["read"]})) is not None


def test_seeded_digest_is_accepted():
    card = {"name": "A", "skills": ["read"]}
    digest = card_digest(card)
    assert digest is not None
    guard = a2a_card_guard(cards={"peer://a.example": digest})
    assert guard(_card("peer://a.example", card)) is None
    assert guard(_card("peer://a.example", {"name": "B", "skills": ["read"]})) is not None


def test_unusable_card_after_admission_blocks():
    guard = a2a_card_guard()
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read"]})) is None
    for card in (None, {}, "not a card", 3):
        decision = guard(_card("peer://a.example", card))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_unusable_card_before_admission_is_ignored_and_records_nothing():
    guard = a2a_card_guard()
    # A malformed card first must not establish or reset a baseline.
    assert guard(_card("peer://a.example", None)) is None
    assert guard(_card("peer://a.example", {})) is None
    # The real card is still a first sight: admitted, not flagged as drift.
    assert guard(_card("peer://a.example", {"name": "A", "skills": ["read"]})) is None


def test_baselines_are_per_peer():
    guard = a2a_card_guard()
    assert guard(_card("peer://a.example", {"name": "A"})) is None
    # A different peer's differing card is its own first sight.
    assert guard(_card("peer://b.example", {"name": "B"})) is None


def test_card_guard_is_out_of_scope_without_a_peer():
    guard = a2a_card_guard()
    for args in ({}, {"card": {"name": "A"}}, None, 3):
        assert guard(_send(args=args)) is None


def test_card_guard_ignores_non_send_actions():
    guard = a2a_card_guard()
    event = SensorEvent(action="http.post", args={"peer": "peer://a.example", "card": {"name": "A"}})
    assert guard(event) is None


def test_non_dict_args_never_raises_and_is_out_of_scope():
    guard = a2a_card_guard()
    for args in (None, 3, ["peer://a.example"], "peer://a.example"):
        assert guard(_send(args=args)) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_unlisted_and_allows_listed_peer():
    engine = PolicyEngine(rules=[a2a_peer_allowlist(allowed=["peer://trusted.example"])])

    blocked = engine.evaluate(_send("peer://evil.example"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID
    assert "evil.example" in blocked.reason

    allowed = engine.evaluate(_send("peer://trusted.example"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fails_closed_on_unparseable_peer():
    engine = PolicyEngine(rules=[a2a_peer_allowlist(allowed=["peer://trusted.example"])])
    decision = engine.evaluate(_send(args={}))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


# --- the declarative a2a condition ------------------------------------------


def _a2a_rule(when):
    return {"id": "r", "verdict": "block", "reason": "no", "when": when}


def test_declarative_a2a_peer_selector_loads_and_blocks():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "peer:evil.example"})]})
    assert engine.quarantined == []
    decision = engine.evaluate(_send("peer://evil.example"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "peer"
    assert engine.evaluate(_send("peer://ok.example")).verdict is Verdict.ALLOW


def test_declarative_a2a_peer_selector_is_case_insensitive():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "peer:EVIL.example"})]})
    assert engine.evaluate(_send("peer://evil.example")).verdict is Verdict.BLOCK


def test_declarative_a2a_card_field_selector():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "card.name:Evil*"})]})
    assert engine.evaluate(_card("peer://a.example", {"name": "Evil Agent"})).verdict is Verdict.BLOCK
    assert engine.evaluate(_card("peer://a.example", {"name": "Good Agent"})).verdict is Verdict.ALLOW


def test_declarative_a2a_card_skills_list_selector():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "card.skills:shell*"})]})
    assert engine.evaluate(_card("peer://a.example", {"skills": [{"name": "shell_exec"}]})) \
        .verdict is Verdict.BLOCK
    assert engine.evaluate(_card("peer://a.example", {"skills": ["read"]})) \
        .verdict is Verdict.ALLOW


def test_declarative_a2a_presence_selectors():
    engine = load_policy({"rules": [_a2a_rule({"a2a": ["card", "peer"]})]})
    assert engine.evaluate(_send("peer://a.example")).verdict is Verdict.BLOCK
    assert engine.evaluate(SensorEvent(action="a2a_send", args={})).verdict is Verdict.ALLOW


def test_declarative_a2a_arg_reads_the_peer_from_a_named_argument():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "peer:evil.example", "arg": "recipient"})]})
    event = SensorEvent(action="a2a_send", args={"recipient": "peer://evil.example"})
    decision = engine.evaluate(event)
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "recipient"


def test_declarative_a2a_unknown_selector_is_quarantined():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "bogus:thing"})]})
    assert engine.policy_ids == []
    assert len(engine.quarantined) == 1 and "unknown a2a selector" in engine.quarantined[0]


def test_declarative_a2a_bad_arg_type_is_quarantined():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "peer", "arg": 3})]})
    assert engine.policy_ids == []
    assert len(engine.quarantined) == 1 and "must be an argument name" in engine.quarantined[0]


def test_declarative_a2a_condition_survives_non_dict_args():
    engine = load_policy({"rules": [_a2a_rule({"a2a": "peer"})]})
    assert engine.evaluate(SensorEvent(action="a2a_send", args=None)).verdict is Verdict.ALLOW  # type: ignore[arg-type]


def test_detector_is_reachable_by_name_from_a_declarative_rule():
    engine = load_policy({"rules": [{
        "id": "vendors", "detector": "a2a_policy.a2a_peer_allowlist",
        "with": {"allowed": ["peer://trusted.example"]},
    }]})
    assert engine.quarantined == []
    assert engine.evaluate(_send("peer://evil.example")).verdict is Verdict.BLOCK
    assert engine.evaluate(_send("peer://trusted.example")).verdict is Verdict.ALLOW
