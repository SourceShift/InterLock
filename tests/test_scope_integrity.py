"""A scope cannot outlive its grant, exceed its delegator, or be empty.

Four holes in hierarchical scopes are pinned shut here:

- a non-empty scope that resolves to no templates used to compile an empty
  ``PolicyEngine`` and allow everything; it is now a ``scoped_engine.unbound``
  refusal, on both the SDK and sidecar paths;
- the per-scope cache key used to cover only the leaf's own path, so a change
  at a (non-ancestor) delegator left an over-granting engine cached; the stamp
  now covers the whole delegation closure;
- a delegated deny-list used to be checked as if it were an allowlist, so a
  delegate could *narrow* its own restrictions; ``Template.deny_params`` flips
  the subset direction;
- a sidecar scope document could not express delegation or tombstones.

Every assertion here is discriminating: the unbound, delegator-rebind, and
deny-direction cases each fail on the pre-A15 tree.
"""
from __future__ import annotations

from typing import Optional

import pytest

from interlock import Decision, SensorEvent, Verdict
from interlock.policy import Binding, PyScopeTree, ScopedEngine, ScopeRegistry, Template
from interlock.policy.scopes import DelegationOverGrant
from interlock.sidecar.rules import RulesError, build_scoped_engine

try:  # the native crate is optional; the pure-Python tree is always available
    from interlock_scopes import ScopeTree as NativeScopeTree  # type: ignore
except Exception:  # pragma: no cover - exercised on machines without the crate
    NativeScopeTree = None

# Both backends must agree on every invariant below.
BACKENDS = [PyScopeTree] + ([NativeScopeTree] if NativeScopeTree is not None else [])
BACKEND_IDS = ["python"] + (["rust"] if NativeScopeTree is not None else [])


# --- local templates: small rule factories shaped like the real detectors ----


def egress(hosts):
    allowed = frozenset(hosts)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action == "fetch" and event.args.get("host") not in allowed:
            return Decision.block("egress denied", "egress")
        return None

    return rule


def row_cap(max_rows: int):
    def rule(_event: SensorEvent) -> Optional[Decision]:
        return None

    return rule


def denied_tools(denied):
    blocked = frozenset(denied)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action in blocked:
            return Decision.block("tool denied", "denied_tools")
        return None

    return rule


TEMPLATES = {
    "egress": Template("egress", egress, frozenset({"hosts"})),
    "row_cap": Template("row_cap", row_cap),
    "denied_tools": Template(
        "denied_tools", denied_tools, deny_params=frozenset({"denied"})
    ),
}


def _fetch(host: str, principal: str) -> SensorEvent:
    return SensorEvent(action="fetch", args={"host": host}, principal=principal)


# --- deliverable 1: an unbound scope refuses --------------------------------


def test_an_unbound_scope_blocks_by_default():
    tree = PyScopeTree()
    tree.bind(("org", "acme"), [Binding("egress", {"hosts": ["api.acme.com"]})])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES))

    decision = engine.evaluate(_fetch("api.acme.com", "org/globex/agent"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.unbound"
    assert "globex" in decision.reason


def test_allow_unbound_restores_the_old_allow():
    tree = PyScopeTree()
    tree.bind(("org", "acme"), [Binding("egress", {"hosts": ["api.acme.com"]})])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES), allow_unbound=True)
    assert engine.evaluate(_fetch("api.acme.com", "org/globex/agent")).verdict is Verdict.ALLOW


def test_allow_unscoped_does_not_also_allow_an_unbound_scope():
    # The two knobs are deliberately separate: opting into empty *paths* must
    # not silently opt into typo'd principals.
    tree = PyScopeTree()
    tree.bind(("org", "acme"), [Binding("egress", {"hosts": ["api.acme.com"]})])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES), allow_unscoped=True)
    decision = engine.evaluate(_fetch("api.acme.com", "org/globex/agent"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.unbound"


def test_an_empty_path_still_blocks_as_unscoped():
    tree = PyScopeTree()
    tree.bind(("org",), [Binding("egress", {"hosts": ["api.acme.com"]})])
    registry = ScopeRegistry(tree, TEMPLATES)

    unscoped = ScopedEngine(registry).evaluate(SensorEvent(action="fetch"))
    assert unscoped.verdict is Verdict.BLOCK
    assert unscoped.policy_id == "scoped_engine.unscoped"

    # allow_unbound covers unresolved non-empty scopes, not the empty path.
    still_unscoped = ScopedEngine(registry, allow_unbound=True).evaluate(
        SensorEvent(action="fetch")
    )
    assert still_unscoped.policy_id == "scoped_engine.unscoped"


def test_allow_unscoped_keeps_its_meaning():
    tree = PyScopeTree()
    tree.bind(("org",), [Binding("egress", {"hosts": ["api.acme.com"]})])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES), allow_unscoped=True)
    assert engine.evaluate(SensorEvent(action="fetch")).verdict is Verdict.ALLOW


def test_a_fully_tombstoned_scope_is_unbound():
    tree = PyScopeTree()
    tree.bind(("org",), [Binding("egress", {"hosts": ["api.acme.com"]})])
    tree.bind(("org", "retired"), [Binding("egress", {}, enabled=False)])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES))

    decision = engine.evaluate(_fetch("api.acme.com", "org/retired"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.unbound"


def test_a_bound_descendant_inherits_and_is_not_unbound():
    # A bound ancestor makes the leaf's effective policy non-empty: this is
    # the kickoff's live-smoke "ok" shape and must keep allowing.
    tree = PyScopeTree()
    tree.bind(("acme",), [Binding("egress", {"hosts": ["api.acme.com"]})])
    engine = ScopedEngine(ScopeRegistry(tree, TEMPLATES))
    assert engine.evaluate(_fetch("api.acme.com", "acme/payemnts/agent")).verdict is Verdict.ALLOW


@pytest.mark.parametrize("tree_cls", BACKENDS, ids=BACKEND_IDS)
def test_unbound_refusal_holds_on_every_backend(tree_cls):
    tree = tree_cls()
    tree.bind(("org", "acme"), [Binding("egress", {"hosts": ["api.example"]})])
    registry = ScopeRegistry(tree, TEMPLATES)
    event = _fetch("api.example", "org/globex/agent")

    refused = ScopedEngine(registry).evaluate(event)
    assert refused.verdict is Verdict.BLOCK
    assert refused.policy_id == "scoped_engine.unbound"
    assert ScopedEngine(registry, allow_unbound=True).evaluate(event).verdict is Verdict.ALLOW


# --- deliverable 2: the cache stamp covers the delegation closure -----------


def _delegated_tree(tree_cls=PyScopeTree):
    """``org/grantee/agent`` delegates to the *sibling* ``org/grantor``.

    A sibling delegator matters: an ancestor rebind would already invalidate the
    old leaf-only stamp, so only a non-prefix delegator proves the closure walk.
    """
    tree = tree_cls()
    tree.bind(("org", "grantor"), [Binding("egress", {"hosts": ["api.example"]})])
    tree.bind(
        ("org", "grantee", "agent"),
        [
            Binding(
                "egress",
                {"hosts": ["api.example"]},
                delegated_from=("org", "grantor"),
            )
        ],
    )
    return tree


def test_rebinding_a_delegator_invalidates_a_cached_leaf():
    tree = _delegated_tree()
    registry = ScopeRegistry(tree, TEMPLATES)
    leaf = ("org", "grantee", "agent")

    cached = registry.for_scope(leaf)
    stamp = registry._cache[leaf][0]
    # Still a valid grant (the delegator widened), so this recompiles cleanly.
    tree.bind(
        ("org", "grantor"),
        [Binding("egress", {"hosts": ["api.example", "other.example"]})],
    )
    fresh = registry.for_scope(leaf)
    assert fresh is not cached
    assert registry._cache[leaf][0] != stamp


def test_a_delegator_narrowed_after_caching_blocks_the_leaf():
    # The kickoff's acceptance case: cache the delegated leaf, then re-bind the
    # (non-ancestor) delegator to a narrower allowlist. A leaf-only stamp would
    # be a cache hit here and keep allowing; the closure stamp recompiles, the
    # delegation check fails, and the call is refused.
    tree = _delegated_tree()
    registry = ScopeRegistry(tree, TEMPLATES)
    engine = ScopedEngine(registry)
    event = _fetch("api.example", "org/grantee/agent")
    assert engine.evaluate(event).verdict is Verdict.ALLOW

    tree.bind(("org", "grantor"), [Binding("egress", {"hosts": ["other.example"]})])

    decision = engine.evaluate(event)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.resolution"


def test_a_revoked_delegator_also_invalidates_the_cached_leaf():
    tree = _delegated_tree()
    registry = ScopeRegistry(tree, TEMPLATES)
    engine = ScopedEngine(registry)
    assert engine.evaluate(_fetch("api.example", "org/grantee/agent")).verdict is Verdict.ALLOW

    # Revoking the grant at the delegator bumps its version even though its own
    # binding is now a tombstone.
    tree.bind(("org", "grantor"), [Binding("egress", {}, enabled=False)])

    decision = engine.evaluate(_fetch("api.example", "org/grantee/agent"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.resolution"


def test_the_stamp_is_stable_without_a_relevant_change_and_the_cache_is_bounded():
    tree = _delegated_tree()
    registry = ScopeRegistry(tree, TEMPLATES, maxsize=1)
    leaf = ("org", "grantee", "agent")

    first = registry.for_scope(leaf)
    stamp = registry._cache[leaf][0]
    assert registry.for_scope(leaf) is first
    assert registry._cache[leaf][0] == stamp

    # Another leaf evicts the first: the LRU stays bounded.
    registry.for_scope(("org", "grantor"))
    assert len(registry._cache) == 1


@pytest.mark.parametrize("tree_cls", BACKENDS, ids=BACKEND_IDS)
def test_delegator_change_invalidates_on_every_backend(tree_cls):
    tree = _delegated_tree(tree_cls)
    registry = ScopeRegistry(tree, TEMPLATES)
    engine = ScopedEngine(registry)
    event = _fetch("api.example", "org/grantee/agent")
    assert engine.evaluate(event).verdict is Verdict.ALLOW

    tree.bind(("org", "grantor"), [Binding("egress", {"hosts": ["other.example"]})])
    decision = engine.evaluate(event)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.resolution"


# --- deliverable 3: a deny-list may only be narrowed ------------------------


def _deny_tree(tree_cls=PyScopeTree, delegate_denied=None):
    tree = tree_cls()
    tree.bind(
        ("org", "grantor"),
        [Binding("denied_tools", {"denied": ["shell", "write"]})],
    )
    tree.bind(
        ("org", "grantee"),
        [
            Binding(
                "denied_tools",
                {"denied": delegate_denied or ["shell"]},
                delegated_from=("org", "grantor"),
            )
        ],
    )
    return tree


def test_a_delegate_cannot_narrow_its_delegators_deny_list():
    registry = ScopeRegistry(_deny_tree(delegate_denied=["shell"]), TEMPLATES)
    with pytest.raises(DelegationOverGrant):
        registry.resolve(("org", "grantee"))


@pytest.mark.parametrize("tree_cls", BACKENDS, ids=BACKEND_IDS)
def test_a_delegate_cannot_omit_its_delegators_deny_list(tree_cls):
    # Not naming the deny key at all denies nothing, which is the same widening
    # as an explicitly shorter list. The check must look at delegator keys the
    # binding never sets, not only the keys the binding itself iterates.
    tree = tree_cls()
    tree.bind(
        ("org", "grantor"),
        [Binding("denied_tools", {"denied": ["shell", "write"]})],
    )
    tree.bind(
        ("org", "grantee"),
        [Binding("denied_tools", {}, delegated_from=("org", "grantor"))],
    )
    with pytest.raises(DelegationOverGrant):
        ScopeRegistry(tree, TEMPLATES).resolve(("org", "grantee"))


@pytest.mark.parametrize("tree_cls", BACKENDS, ids=BACKEND_IDS)
def test_a_delegate_may_omit_an_empty_deny_list(tree_cls):
    # A delegator that denies nothing constrains nothing: the delegate may
    # leave the key out and inherit no restrictions.
    tree = tree_cls()
    tree.bind(("org", "grantor"), [Binding("denied_tools", {"denied": []})])
    tree.bind(
        ("org", "grantee"),
        [Binding("denied_tools", {}, delegated_from=("org", "grantor"))],
    )
    assert "denied_tools" in ScopeRegistry(tree, TEMPLATES).resolve(("org", "grantee"))


def test_an_equal_deny_list_is_allowed():
    registry = ScopeRegistry(_deny_tree(delegate_denied=["shell", "write"]), TEMPLATES)
    assert "denied_tools" in registry.resolve(("org", "grantee"))


def test_a_wider_deny_list_is_allowed():
    # Denying *more* tools than the delegator is less power, never more.
    registry = ScopeRegistry(
        _deny_tree(delegate_denied=["shell", "write", "exec"]), TEMPLATES
    )
    assert "denied_tools" in registry.resolve(("org", "grantee"))


def test_an_allowlist_param_keeps_the_subset_rule():
    tree = PyScopeTree()
    tree.bind(
        ("org", "grantor"),
        [Binding("egress", {"hosts": ["a.example", "b.example"]})],
    )
    tree.bind(
        ("org", "grantee"),
        [
            Binding(
                "egress",
                {"hosts": ["a.example", "b.example", "evil.example"]},
                delegated_from=("org", "grantor"),
            )
        ],
    )
    registry = ScopeRegistry(tree, TEMPLATES)
    with pytest.raises(DelegationOverGrant):
        registry.resolve(("org", "grantee"))

    # A strict subset is the allowed direction for an allowlist.
    tree.bind(
        ("org", "grantee"),
        [
            Binding(
                "egress",
                {"hosts": ["a.example"]},
                delegated_from=("org", "grantor"),
            )
        ],
    )
    assert "egress" in ScopeRegistry(tree, TEMPLATES).resolve(("org", "grantee"))


@pytest.mark.parametrize("tree_cls", BACKENDS, ids=BACKEND_IDS)
def test_deny_direction_holds_on_every_backend(tree_cls):
    with pytest.raises(DelegationOverGrant):
        ScopeRegistry(_deny_tree(tree_cls, delegate_denied=["shell"]), TEMPLATES).resolve(
            ("org", "grantee")
        )
    allowed = ScopeRegistry(
        _deny_tree(tree_cls, delegate_denied=["shell", "write", "exec"]), TEMPLATES
    )
    assert "denied_tools" in allowed.resolve(("org", "grantee"))


def test_union_and_deny_params_may_not_overlap():
    with pytest.raises(ValueError) as excinfo:
        Template(
            "bad",
            lambda x: (lambda _event: None),
            union_params={"x"},
            deny_params={"x"},
        )
    assert "x" in str(excinfo.value)


def test_a_parameter_is_override_not_deny_unless_declared():
    # The deny direction applies only to declared keys: a plain list is still
    # an allowlist. ``row_cap`` is a scalar override template.
    assert Template("row_cap", row_cap).deny_params == frozenset()


# --- deliverable 1 + 4: the sidecar inherits the refusal, and parses grants -


def _scope_document(**extra):
    document = {
        "version": 1,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": {
            "org/grantor": [
                {"template": "egress", "params": {"hosts": ["api.example"]}},
            ],
            "org/grantee": [
                {
                    "template": "egress",
                    "params": {"hosts": ["api.example"]},
                    "delegated_from": "org/grantor",
                },
            ],
            "org/retired": [
                {"template": "egress", "params": {}, "enabled": False},
            ],
        },
    }
    document.update(extra)
    return document


def test_build_scoped_engine_parses_delegated_from_and_enabled():
    engine = build_scoped_engine(_scope_document(), TEMPLATES)
    tree = engine.registry.tree
    grant = tree.bindings_at(("org", "grantee"))[0]
    assert grant.delegated_from == ("org", "grantor")
    assert grant.enabled is True
    retired = tree.bindings_at(("org", "retired"))[0]
    assert retired.enabled is False
    # And the parsed grant is enforced, not merely stored.
    assert engine.evaluate(_fetch("api.example", "org/grantee")).verdict is Verdict.ALLOW


def test_a_document_without_the_new_keys_behaves_as_before():
    document = {
        "version": 1,
        "bindings": {
            "org/acme": [{"template": "egress", "params": {"hosts": ["api.example"]}}]
        },
    }
    engine = build_scoped_engine(document, TEMPLATES)
    grant = engine.registry.tree.bindings_at(("org", "acme"))[0]
    assert grant.delegated_from is None and grant.enabled is True


def test_an_over_granting_sidecar_document_blocks_through_scoped_engine():
    document = _scope_document()
    document["bindings"]["org/grantee"] = [
        {
            "template": "egress",
            "params": {"hosts": ["api.example", "evil.example"]},
            "delegated_from": "org/grantor",
        }
    ]
    engine = build_scoped_engine(document, TEMPLATES)
    decision = engine.evaluate(_fetch("evil.example", "org/grantee"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.resolution"


def test_an_unbound_sidecar_scope_blocks_with_the_same_refusal():
    engine = build_scoped_engine(_scope_document(), TEMPLATES)
    decision = engine.evaluate(_fetch("api.example", "org/globex/agent"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.unbound"


@pytest.mark.parametrize("bad", [7, None, ["org", "grantor"]])
def test_a_non_string_delegated_from_is_refused(bad):
    document = _scope_document()
    document["bindings"]["org/grantee"] = [
        {"template": "egress", "params": {}, "delegated_from": bad}
    ]
    with pytest.raises(RulesError):
        build_scoped_engine(document, TEMPLATES)


@pytest.mark.parametrize("bad", [1, 0, "false", None])
def test_a_non_bool_enabled_is_refused(bad):
    document = _scope_document()
    document["bindings"]["org/retired"] = [
        {"template": "egress", "params": {}, "enabled": bad}
    ]
    with pytest.raises(RulesError):
        build_scoped_engine(document, TEMPLATES)
