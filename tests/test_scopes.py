"""Hierarchical scope resolution, caching, and enforcement.

Templates are defined locally (not imported from the detectors package) so this
test exercises only the scope machinery and stays stable while detectors change.
"""
from typing import Optional

import pytest

import interlock
from interlock import Blocked, Decision, guard
from interlock.context import span
from interlock.event import SensorEvent
from interlock.policy.scopes import (
    Binding,
    DelegationDepthExceeded,
    DelegationOverGrant,
    ScopedEngine,
    ScopeRegistry,
    ScopeTree,
    Template,
    principal_scope,
)


# --- local templates: small rule factories shaped like real detectors --------
def egress_allowlist(allowed_hosts):
    hosts = frozenset(allowed_hosts)

    def rule(e: SensorEvent) -> Optional[Decision]:
        if e.action in ("http_post", "fetch", "request"):
            host = e.args.get("host") or ""
            if host and host not in hosts:
                return Decision.block("egress to " + host, "egress_allowlist")
        return None

    return rule


def rate_limiter(limit: int):
    state = {"n": 0}

    def rule(e: SensorEvent) -> Optional[Decision]:
        state["n"] += 1
        if state["n"] > limit:
            return Decision.block("rate limit " + str(limit), "rate_limiter")
        return None

    return rule


def keyword_block(words):
    ws = [w.lower() for w in words]

    def rule(e: SensorEvent) -> Optional[Decision]:
        for v in e.args.values():
            if isinstance(v, str):
                lv = v.lower()
                for w in ws:
                    if w in lv:
                        return Decision.block("keyword " + w, "keyword_block")
        return None

    return rule


TEMPLATES = {
    "egress_allowlist": Template(
        "egress_allowlist", egress_allowlist, frozenset({"allowed_hosts"})
    ),
    "rate_limiter": Template("rate_limiter", rate_limiter),
    "keyword_block": Template(
        "keyword_block", keyword_block, frozenset({"words"})
    ),
}


def _seeded_tree() -> ScopeTree:
    t = ScopeTree()
    t.bind(
        ("root",),
        [
            Binding("keyword_block", {"words": ["ignore previous"]}),
            Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}),
        ],
    )
    t.bind(
        ("root", "acme"),
        [
            Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]}),
            Binding("rate_limiter", {"limit": 5}),
        ],
    )
    t.bind(
        ("root", "acme", "agent42"),
        [
            Binding("egress_allowlist", {"allowed_hosts": ["agent42.local"]}),
            Binding("rate_limiter", {"limit": 2}),  # override 5 -> 2
        ],
    )
    return t


# --- resolution semantics ----------------------------------------------------
def test_union_param_accumulates_up_the_chain():
    reg = ScopeRegistry(_seeded_tree(), TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent42"))
    assert set(eff["egress_allowlist"]["allowed_hosts"]) == {
        "api.internal",
        "acme.example",
        "agent42.local",
    }


def test_override_param_takes_most_specific():
    reg = ScopeRegistry(_seeded_tree(), TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent42"))
    assert eff["rate_limiter"]["limit"] == 2


def test_inherited_binding_applies_without_local_binding():
    reg = ScopeRegistry(_seeded_tree(), TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent42"))
    assert set(eff["keyword_block"]["words"]) == {"ignore previous"}


def test_tombstone_removes_inherited_binding():
    t = _seeded_tree()
    t.bind(
        ("root", "acme", "agent99"),
        [Binding("keyword_block", {}, enabled=False)],
    )
    reg = ScopeRegistry(t, TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent99"))
    assert "keyword_block" not in eff
    # the tombstone is scoped to keyword_block; egress still resolves
    assert set(eff["egress_allowlist"]["allowed_hosts"]) == {
        "api.internal",
        "acme.example",
    }


def test_deeper_rebind_overrides_a_tombstone():
    t = _seeded_tree()
    t.bind(("root", "acme"), [Binding("keyword_block", {}, enabled=False)])
    t.bind(
        ("root", "acme", "agent7"),
        [Binding("keyword_block", {"words": ["exfiltrate"]})],
    )
    reg = ScopeRegistry(t, TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent7"))
    assert set(eff["keyword_block"]["words"]) == {"exfiltrate"}


def test_unknown_template_is_ignored():
    t = ScopeTree()
    t.bind(("root",), [Binding("does_not_exist", {"foo": 1})])
    reg = ScopeRegistry(t, TEMPLATES)
    assert reg.resolve(("root",)) == {}
    # compiling a scope with only unknown templates yields an empty engine
    eng = reg.for_scope(("root",))
    assert eng.evaluate(SensorEvent(action="anything")).verdict.name == "ALLOW"


# --- caching and invalidation ------------------------------------------------
def test_cache_hit_returns_the_same_engine_object():
    reg = ScopeRegistry(_seeded_tree(), TEMPLATES)
    leaf = ("root", "acme", "agent42")
    e1 = reg.for_scope(leaf)
    e2 = reg.for_scope(leaf)
    assert e1 is e2
    assert reg.hits == 1 and reg.misses == 1


def test_ancestor_edit_invalidates_descendant():
    t = _seeded_tree()
    reg = ScopeRegistry(t, TEMPLATES)
    leaf = ("root", "acme", "agent42")
    e1 = reg.for_scope(leaf)
    t.bind(("root", "acme"), [Binding("rate_limiter", {"limit": 9})])  # bump ancestor
    e3 = reg.for_scope(leaf)
    assert e3 is not e1


def test_lru_evicts_beyond_maxsize():
    t = ScopeTree()
    t.bind(("root",), [Binding("rate_limiter", {"limit": 1})])
    for i in range(10):
        t.bind(("root", "a%d" % i), [Binding("rate_limiter", {"limit": i + 1})])
    reg = ScopeRegistry(t, TEMPLATES, maxsize=4)
    for i in range(10):
        reg.for_scope(("root", "a%d" % i))
    assert len(reg._cache) == 4


# --- end-to-end enforcement through the guarded runtime ----------------------
def test_resolved_engine_blocks_and_allows_through_guard():
    reg = ScopeRegistry(_seeded_tree(), TEMPLATES)
    interlock.install(engine=reg.for_scope(("root", "acme", "agent42")))

    @guard()
    def http_post(host):
        return "sent"

    assert http_post(host="acme.example") == "sent"  # on the merged allowlist
    with pytest.raises(Blocked):
        http_post(host="evil.com")  # not on any allowlist up the chain


# --- ScopedEngine: per-subject policy resolved at call time ------------------
def _two_org_tree() -> ScopeTree:
    t = ScopeTree()
    t.bind(
        ("root",),
        [
            Binding("keyword_block", {"words": ["ignore previous"]}),
            Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}),
        ],
    )
    t.bind(
        ("root", "acme"),
        [Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]})],
    )
    t.bind(
        ("root", "beta"),
        [Binding("egress_allowlist", {"allowed_hosts": ["beta.example"]})],
    )
    return t


def test_principal_scope_splits_on_slash():
    ev = SensorEvent(action="x", principal="root/acme/agent42")
    assert principal_scope(ev) == ("root", "acme", "agent42")
    assert principal_scope(SensorEvent(action="x")) == ()


def test_scoped_engine_resolves_a_different_policy_per_principal():
    reg = ScopeRegistry(_two_org_tree(), TEMPLATES)
    eng = ScopedEngine(reg)
    to_acme = SensorEvent(
        action="http_post", args={"host": "acme.example"}, principal="root/acme/a1"
    )
    # acme's subject may reach acme.example; a beta subject may not.
    assert eng.evaluate(to_acme).verdict.name == "ALLOW"
    to_beta = SensorEvent(
        action="http_post", args={"host": "acme.example"}, principal="root/beta/b1"
    )
    assert eng.evaluate(to_beta).verdict.name == "BLOCK"


def test_scoped_engine_allows_when_no_scope_and_no_default():
    reg = ScopeRegistry(_two_org_tree(), TEMPLATES)
    eng = ScopedEngine(reg)  # default_scope empty
    ev = SensorEvent(action="http_post", args={"host": "evil.com"})  # no principal
    assert eng.evaluate(ev).verdict.name == "ALLOW"


def test_scoped_engine_default_scope_applies_a_floor_policy():
    reg = ScopeRegistry(_two_org_tree(), TEMPLATES)
    eng = ScopedEngine(reg, default_scope=("root",))
    # unknown subject falls back to root, which only allows api.internal
    ev = SensorEvent(action="http_post", args={"host": "evil.com"}, principal="")
    assert eng.evaluate(ev).verdict.name == "BLOCK"
    ok = SensorEvent(
        action="http_post", args={"host": "api.internal"}, principal=""
    )
    assert eng.evaluate(ok).verdict.name == "ALLOW"


def test_scoped_engine_routes_through_guard_by_principal():
    reg = ScopeRegistry(_two_org_tree(), TEMPLATES)
    interlock.install(engine=ScopedEngine(reg))

    @guard()
    def http_post(host):
        return "sent"

    with span(principal="root/acme/a1"):
        assert http_post(host="acme.example") == "sent"
        with pytest.raises(Blocked):
            http_post(host="beta.example")  # not on acme's allowlist
    with span(principal="root/beta/b1"):
        assert http_post(host="beta.example") == "sent"  # same call, other subject


# --- delegation chains: provenance, per-hop attenuation, depth bound --------
# The acceptance case from the ROADMAP: a child binding delegated from a
# sibling that holds strictly less than what the child claims. ``resolve``
# must raise at resolve time, before any rule runs.


def _delegation_tree() -> ScopeTree:
    """Root grants egress for [api.internal]; a sibling grants [acme.example];
    a child claims [acme.example, extra.example] while delegating from the
    sibling — over-grant."""
    t = ScopeTree()
    t.bind(
        ("root",),
        [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})],
    )
    t.bind(
        ("acme", "payments"),
        [Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]})],
    )
    t.bind(
        ("acme", "payments", "agent42"),
        [
            Binding(
                "egress_allowlist",
                {"allowed_hosts": ["acme.example", "extra.example"]},
                delegated_from=("acme", "payments"),
            )
        ],
    )
    return t


def test_delegation_over_grant_raises_at_resolve_time():
    reg = ScopeRegistry(_delegation_tree(), TEMPLATES)
    with pytest.raises(DelegationOverGrant):
        reg.resolve(("acme", "payments", "agent42"))


def test_delegation_unaffected_when_not_delegated():
    """A non-delegated binding resolves exactly as before."""
    t = ScopeTree()
    t.bind(
        ("root",),
        [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})],
    )
    t.bind(
        ("root", "acme"),
        [Binding("egress_allowlist", {"allowed_hosts": ["acme.example"]})],
    )
    t.bind(
        ("root", "acme", "agent42"),
        [Binding("egress_allowlist", {"allowed_hosts": ["agent42.local"]})],
    )
    reg = ScopeRegistry(t, TEMPLATES)
    eff = reg.resolve(("root", "acme", "agent42"))
    assert set(eff["egress_allowlist"]["allowed_hosts"]) == {
        "api.internal",
        "acme.example",
        "agent42.local",
    }


def test_delegation_subset_at_grant_time_resolves_cleanly():
    """A child that grants a *subset* of its delegator's grant resolves fine."""
    t = ScopeTree()
    t.bind(
        ("acme", "payments"),
        [Binding("egress_allowlist", {"allowed_hosts": ["a.example", "b.example"]})],
    )
    t.bind(
        ("acme", "payments", "agent42"),
        [
            Binding(
                "egress_allowlist",
                {"allowed_hosts": ["a.example"]},
                delegated_from=("acme", "payments"),
            )
        ],
    )
    reg = ScopeRegistry(t, TEMPLATES)
    eff = reg.resolve(("acme", "payments", "agent42"))
    assert set(eff["egress_allowlist"]["allowed_hosts"]) == {"a.example", "b.example"}


def test_delegation_depth_bound_fails_closed():
    """A chain deeper than ``max_delegation_depth`` raises, not recurses.

    Each hop grants a subset of its parent (so the over-grant check is
    satisfied), but the chain is long enough that the recursive delegation
    walk exceeds the bound and fails closed with ``DelegationDepthExceeded``.
    """
    t = ScopeTree()
    prev = ("root",)
    t.bind(prev, [Binding("rate_limiter", {"limit": 1})])
    for i in range(20):
        cur = prev + (f"n{i}",)
        t.bind(
            cur,
            [
                Binding(
                    "rate_limiter",
                    {"limit": 1},
                    delegated_from=prev,
                )
            ],
        )
        prev = cur
    reg = ScopeRegistry(t, TEMPLATES, max_delegation_depth=4)
    with pytest.raises(DelegationDepthExceeded):
        reg.resolve(prev)


def test_sensor_event_carries_parent_principal():
    """The optional parent_principal field records who spawned this principal."""
    ev = SensorEvent(
        action="x", principal="agent42", parent_principal="auditor"
    )
    assert ev.parent_principal == "auditor"
    # And absent by default so every existing caller stays unaffected.
    assert SensorEvent(action="x").parent_principal is None
