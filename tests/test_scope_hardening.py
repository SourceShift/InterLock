"""Scoped policy fails closed instead of quietly running no rules.

Two silent holes are pinned shut here. An event with no principal resolved to
no scope and was allowed without consulting any rule; and a binding naming a
template the registry did not know (for example one added after the registry
was built) was skipped, so its rule never existed.
"""
import pytest

import interlock
from interlock import Decision, PolicyEngine, SensorEvent, Verdict, deny_tool
from interlock.policy import Binding, ScopedEngine, ScopeRegistry, ScopeTree, Template
from interlock.policy.scopes import UnknownTemplate


def _deny(name):
    return deny_tool(name)


TEMPLATES = {"deny": Template("deny", _deny)}


def _registry():
    tree = ScopeTree()
    tree.bind(("root",), [Binding("deny", {"name": "run_shell"})])
    return ScopeRegistry(tree, TEMPLATES)


def setup_function(_):
    interlock.install(engine=PolicyEngine())


def test_an_event_with_no_scope_is_blocked_by_default():
    engine = ScopedEngine(_registry())
    decision = engine.evaluate(SensorEvent(action="anything"))
    assert decision.verdict is Verdict.BLOCK
    assert "no scope" in decision.reason


def test_allow_unscoped_restores_the_permissive_behaviour_explicitly():
    engine = ScopedEngine(_registry(), allow_unscoped=True)
    assert engine.evaluate(SensorEvent(action="anything")).verdict is Verdict.ALLOW


def test_default_scope_still_applies_a_floor_policy():
    engine = ScopedEngine(_registry(), default_scope=("root",))
    assert engine.evaluate(SensorEvent(action="run_shell")).verdict is Verdict.BLOCK
    assert engine.evaluate(SensorEvent(action="read_docs")).verdict is Verdict.ALLOW


def test_a_binding_to_an_unknown_template_raises_instead_of_vanishing():
    tree = ScopeTree()
    tree.bind(("root",), [Binding("not_registered", {"x": 1})])
    registry = ScopeRegistry(tree, TEMPLATES)
    with pytest.raises(UnknownTemplate) as excinfo:
        registry.resolve(("root",))
    assert "not_registered" in str(excinfo.value)


def test_a_template_added_after_construction_needs_add_template():
    tree = ScopeTree()
    tree.bind(("root",), [Binding("late", {"name": "drop_table"})])
    templates = dict(TEMPLATES)
    registry = ScopeRegistry(tree, templates)

    templates["late"] = Template("late", _deny)   # the registry copied the dict
    with pytest.raises(UnknownTemplate):
        registry.for_scope(("root",))

    registry.add_template(Template("late", _deny))
    engine = registry.for_scope(("root",))
    assert engine.evaluate(SensorEvent(action="drop_table")).verdict is Verdict.BLOCK


def test_add_template_replacing_a_template_drops_stale_compiled_engines():
    registry = _registry()
    assert registry.for_scope(("root",)).evaluate(SensorEvent(action="run_shell")).verdict is Verdict.BLOCK
    registry.add_template(Template("deny", lambda name: (lambda e: None)))
    assert registry.for_scope(("root",)).evaluate(SensorEvent(action="run_shell")).verdict is Verdict.ALLOW


def test_install_explains_that_a_scoped_engine_takes_no_extra_rules():
    with pytest.raises(TypeError) as excinfo:
        interlock.install(engine=ScopedEngine(_registry()), rules=[lambda e: Decision.block("x")])
    assert "ScopedEngine" in str(excinfo.value)


def test_a_resolution_error_during_a_call_blocks_instead_of_raising():
    # The registry still raises (a bad grant must never be cached), but a call
    # made through ScopedEngine gets a Blocked like every other refusal, not a
    # raw LookupError from the policy layer.
    tree = ScopeTree()
    tree.bind(("root",), [Binding("not_registered", {"x": 1})])
    registry = ScopeRegistry(tree, TEMPLATES)
    with pytest.raises(UnknownTemplate):
        registry.resolve(("root",))

    decision = ScopedEngine(registry).evaluate(SensorEvent(action="read_docs", principal="root"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.resolution"
    assert "not_registered" in decision.reason


def test_a_delegation_over_grant_during_a_call_blocks_instead_of_raising():
    from interlock.policy.scopes import DelegationOverGrant

    def allow_hosts(hosts):
        return lambda e: None

    templates = {"egress": Template("egress", allow_hosts, frozenset({"hosts"}))}
    tree = ScopeTree()
    tree.bind(("root",), [Binding("egress", {"hosts": ["a.example"]})])
    tree.bind(("root", "sub"), [Binding("egress", {"hosts": ["a.example", "evil.example"]},
                                        delegated_from=("root",))])
    registry = ScopeRegistry(tree, templates)
    with pytest.raises(DelegationOverGrant):
        registry.resolve(("root", "sub"))

    with interlock.span(principal="root/sub"):
        interlock.install(engine=ScopedEngine(registry))
        with pytest.raises(interlock.Blocked) as excinfo:
            interlock.enforce_tool_call("fetch", {"url": "https://a.example"})
    assert excinfo.value.decision.policy_id == "scoped_engine.resolution"
    assert "over-grant" in excinfo.value.decision.reason


@pytest.mark.parametrize("tree_cls", ["python", "active"])
def test_union_params_resolve_to_a_set_on_every_backend(tree_cls):
    from interlock.policy import PyScopeTree

    def allow_hosts(hosts):
        return lambda e: None

    templates = {"egress": Template("egress", allow_hosts, frozenset({"hosts"}))}
    tree = PyScopeTree() if tree_cls == "python" else ScopeTree()
    tree.bind(("root",), [Binding("egress", {"hosts": ["a.example"]})])
    tree.bind(("root", "acme"), [Binding("egress", {"hosts": ["b.example"]})])
    resolved = ScopeRegistry(tree, templates).resolve(("root", "acme"))
    assert resolved["egress"]["hosts"] == {"a.example", "b.example"}
    assert isinstance(resolved["egress"]["hosts"], set)
