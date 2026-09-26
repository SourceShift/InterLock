"""MCP capability lease: the live-grant silence, the expiry denial and its
reason, the never-issued denial and its different reason, the boundary at
``expires_at``, renewal, ordering against later rules, registry ownership,
and wall-clock independence. Every verdict is driven by explicit ``ts``
values - no test sleeps, and none could pass if the rule read the clock,
because the lease windows used here lie far from the real wall clock.
"""
import ast
import importlib
import inspect
import threading

import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_capability_lease import (
    ANY_CAPABILITY,
    POLICY_ID,
    Lease,
    LeaseRegistry,
    mcp_capability_lease,
)
from interlock.detectors.mcp_server_allowlist import mcp_server_allowlist


def _event(action, ts, args=None):
    return SensorEvent(action=action, args=args if args is not None else {}, ts=ts)


# --- the lease value ---------------------------------------------------------


def test_lease_is_an_immutable_value():
    lease = Lease("github", "mcp.call", 100.0, 200.0)
    with pytest.raises(Exception):  # frozen: fields cannot be reassigned
        lease.expires_at = 400.0
    assert lease.expires_at == 200.0


def test_dead_on_arrival_lease_is_refused():
    with pytest.raises(ValueError):  # zero-length window: never live
        Lease("github", "mcp.call", 100.0, 100.0)
    with pytest.raises(ValueError):  # inverted window
        Lease("github", "mcp.call", 200.0, 100.0)


def test_lease_covers_the_documented_half_open_interval():
    lease = Lease("github", "mcp.call", 100.0, 200.0)
    assert lease.covers(100.0)  # at issued_at: live
    assert lease.covers(199.9)  # one tick before expiry: live
    assert not lease.covers(200.0)  # exactly at expires_at: DEAD
    assert not lease.covers(200.1)  # after: dead
    assert not lease.covers(99.9)  # before the grant started: dead


# --- live path: a holding grant is silence, never Decision.allow() -----------


def test_live_lease_returns_none_not_allow():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    decision = rule(_event("mcp.call", 150.0, {"__origin__": "github"}))
    assert decision is None  # None, so the rules after it still run


def test_wildcard_lease_covers_every_action_on_the_subject():
    registry = LeaseRegistry()
    registry.issue("github", ANY_CAPABILITY, 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    assert rule(_event("github.create_issue", 150.0)) is None
    assert rule(_event("github.repo.delete", 150.0)) is None


def test_exact_lease_covers_only_its_action():
    registry = LeaseRegistry()
    registry.issue("github", "github.create_issue", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    assert rule(_event("github.create_issue", 150.0)) is None
    denied = rule(_event("github.push", 150.0))
    assert denied is not None and denied.verdict is Verdict.BLOCK


# --- expiry: the boundary and the reason -------------------------------------


def test_one_tick_before_expiry_passes_at_expiry_denies():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    assert rule(_event("mcp.call", 199.9, {"__origin__": "github"})) is None
    decision = rule(_event("mcp.call", 200.0, {"__origin__": "github"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_expired_lease_denies_naming_the_expiry():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    decision = rule(_event("mcp.call", 250.0, {"__origin__": "github"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.policy_id == "mcp_capability_lease"
    assert decision.reason == (
        "mcp_capability_lease: lease for github/mcp.call expired at 200.0"
    )
    assert decision.attributed_to == "__origin__"


def test_every_call_after_expiry_is_also_denied():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    for ts in (200.0, 250.0, 1000.0):
        decision = rule(_event("mcp.call", ts, {"__origin__": "github"}))
        assert decision is not None, ts
        assert decision.verdict is Verdict.BLOCK, ts


def test_lease_not_yet_in_force_denies_naming_the_start():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 300.0, 400.0)
    rule = mcp_capability_lease(registry)
    decision = rule(_event("mcp.call", 250.0, {"__origin__": "github"}))
    assert decision is not None
    assert decision.reason == (
        "mcp_capability_lease: lease for github/mcp.call not in force until 300.0"
    )


# --- no lease at all ----------------------------------------------------------


def test_call_with_no_lease_at_all_is_denied():
    rule = mcp_capability_lease(LeaseRegistry())  # nothing ever issued
    decision = rule(_event("mcp.call", 150.0, {"__origin__": "github"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == (
        "mcp_capability_lease: no lease issued for github/mcp.call"
    )


def test_never_issued_and_expired_reasons_differ():
    granted = LeaseRegistry()
    granted.issue("github", "mcp.call", 100.0, 200.0)
    never = mcp_capability_lease(LeaseRegistry())(
        _event("mcp.call", 150.0, {"__origin__": "github"})
    )
    expired = mcp_capability_lease(granted)(
        _event("mcp.call", 250.0, {"__origin__": "github"})
    )
    assert never is not None and expired is not None
    assert "no lease issued" in never.reason
    assert "expired at 200.0" in expired.reason
    assert never.reason != expired.reason


# --- renewal -------------------------------------------------------------------


def test_renewal_re_arms_an_expired_lease():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    assert rule(_event("mcp.call", 250.0, {"__origin__": "github"})) is not None
    registry.renew("github", "mcp.call", 250.0, 400.0)
    assert rule(_event("mcp.call", 250.0, {"__origin__": "github"})) is None
    # The renewed lease is a fresh window: it expires again at its own end.
    again = rule(_event("mcp.call", 400.0, {"__origin__": "github"}))
    assert again is not None
    assert "expired at 400.0" in again.reason


def test_renewal_of_a_live_lease_extends_its_window():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    registry.renew("github", "mcp.call", 150.0, 500.0)
    assert rule(_event("mcp.call", 450.0, {"__origin__": "github"})) is None


def test_renewing_a_never_issued_lease_is_refused():
    registry = LeaseRegistry()
    with pytest.raises(KeyError):
        registry.renew("github", "mcp.call", 0.0, 100.0)


# --- subject resolution and attribution ---------------------------------------


def test_origin_label_wins_over_the_dotted_prefix():
    registry = LeaseRegistry()
    registry.issue("corp", "github.create_issue", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    # The action says github, the label says corp: the explicit label wins,
    # so the corp lease covers the call.
    assert rule(
        _event("github.create_issue", 150.0, {"__origin__": "corp"})
    ) is None
    denied = rule(_event("github.create_issue", 150.0))  # no label -> github
    assert denied is not None and denied.verdict is Verdict.BLOCK


def test_bare_action_without_a_subject_is_out_of_scope():
    rule = mcp_capability_lease(LeaseRegistry())
    assert rule(_event("chat", 150.0, {"text": "hi"})) is None
    assert rule(_event("fetch", 150.0)) is None


def test_prefix_resolved_block_attributes_no_argument():
    registry = LeaseRegistry()
    registry.issue("github", "github.push", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    decision = rule(_event("github.push", 250.0))
    assert decision is not None
    assert decision.attributed_to is None  # subject inferred, no arg to name


def test_hostile_args_never_raise():
    rule = mcp_capability_lease(LeaseRegistry())
    for args in (None, 3, ["x"], {"__origin__": 7}, {"__origin__": "  "}):
        event = SensorEvent(action="github.push", args=args, ts=150.0)  # type: ignore[arg-type]
        decision = rule(event)
        # No label to read: falls through to the dotted prefix, where no
        # lease exists - blocked, never raised.
        assert decision is not None, args


def test_non_str_action_with_labelled_subject_is_still_judged():
    registry = LeaseRegistry()
    registry.issue("github", ANY_CAPABILITY, 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    event = SensorEvent(action=3, args={"__origin__": "github"}, ts=150.0)  # type: ignore[arg-type]
    assert rule(event) is None  # the wildcard grant covers whatever this is


# --- registry ownership ---------------------------------------------------------


def test_two_registries_never_share_grants():
    first = LeaseRegistry()
    second = LeaseRegistry()
    first.issue("github", "mcp.call", 100.0, 200.0)
    rule_first = mcp_capability_lease(first)
    rule_second = mcp_capability_lease(second)
    assert rule_first(_event("mcp.call", 150.0, {"__origin__": "github"})) is None
    denied = rule_second(_event("mcp.call", 150.0, {"__origin__": "github"}))
    assert denied is not None
    assert "no lease issued" in denied.reason


def test_one_registry_shared_by_two_rules_is_one_grant_store():
    registry = LeaseRegistry()
    a = mcp_capability_lease(registry)
    b = mcp_capability_lease(registry)
    registry.issue("github", "mcp.call", 100.0, 200.0)
    event = _event("mcp.call", 150.0, {"__origin__": "github"})
    assert a(event) is None and b(event) is None
    # A renewal through the registry is visible to both rules at once.
    registry.renew("github", "mcp.call", 150.0, 160.0)
    later = _event("mcp.call", 170.0, {"__origin__": "github"})
    assert a(later) is not None and b(later) is not None


# --- the rule never reads the wall clock ------------------------------------------


def test_verdicts_flip_on_ts_alone():
    # The window [100, 200) lies far in the past relative to the real clock;
    # a rule that consulted time.time() would deny the live event too.
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    rule = mcp_capability_lease(registry)
    live = _event("mcp.call", 150.0, {"__origin__": "github"})
    dead = _event("mcp.call", 150.0, {"__origin__": "github"})
    dead.ts = 250.0  # identical except the timestamp
    assert rule(live) is None
    denied = rule(dead)
    assert denied is not None and denied.verdict is Verdict.BLOCK


def test_the_module_imports_no_clock():
    module = importlib.import_module("interlock.detectors.mcp_capability_lease")
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(
                alias.name == "time" or alias.name.startswith("time.")
                for alias in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert node.module != "time"


# --- engine integration and ordering ----------------------------------------------


def test_engine_allows_while_live_and_denies_after_expiry():
    registry = LeaseRegistry()
    registry.issue("github", "mcp.call", 100.0, 200.0)
    engine = PolicyEngine(rules=[mcp_capability_lease(registry)])
    first = engine.evaluate(_event("mcp.call", 150.0, {"__origin__": "github"}))
    assert first.verdict is Verdict.ALLOW
    second = engine.evaluate(_event("mcp.call", 250.0, {"__origin__": "github"}))
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
    assert "expired at 200.0" in second.reason


def test_live_lease_stays_silent_so_a_later_rule_still_fires():
    # Ordering proof: with the grant holding, the lease rule returns None
    # and the allowlist behind it does the blocking. An ALLOW Decision here
    # would have swallowed the whole MCP suite.
    registry = LeaseRegistry()
    registry.issue("api", "mcp.connect", 100.0, 200.0)
    engine = PolicyEngine(rules=[
        mcp_capability_lease(registry),
        mcp_server_allowlist(["api.example.com"]),
    ])
    decision = engine.evaluate(_event(
        "mcp.connect", 150.0,
        {"uri": "https://evil.example/x", "__origin__": "api"},
    ))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_server_allowlist"


def test_expired_lease_denies_before_a_later_rule_can():
    # The other direction of ordering: lease first means its expiry - not
    # the allowlist's reason - is what the operator sees.
    registry = LeaseRegistry()
    registry.issue("api", "mcp.connect", 100.0, 200.0)
    engine = PolicyEngine(rules=[
        mcp_capability_lease(registry),
        mcp_server_allowlist(["api.example.com"]),
    ])
    decision = engine.evaluate(_event(
        "mcp.connect", 250.0,
        {"uri": "https://evil.example/x", "__origin__": "api"},
    ))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_capability_lease"
    assert "expired" in decision.reason


# --- concurrency --------------------------------------------------------------------


def test_concurrent_rules_on_one_registry_are_safe():
    registry = LeaseRegistry()
    rule = mcp_capability_lease(registry)
    errors = []

    def worker(i):
        try:
            name = "srv{}".format(i)
            registry.issue(name, ANY_CAPABILITY, 0.0, 10.0)
            for _ in range(50):
                decision = rule(_event("{}.call".format(name), 5.0,
                                       {"__origin__": name}))
                if decision is not None:
                    errors.append(decision.reason)
        except Exception as exc:  # surfaced below; threads swallow nothing
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
