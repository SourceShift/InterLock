"""``parent_principal`` is produced by the context and consumed by the chain.

The R1 patch declared ``SensorEvent.parent_principal`` but nothing set it and
nothing read it, so the delegation chain was recorded only in principle. These
tests pin the wiring in both directions: the interceptors carry the link from
the run context onto the event, and :func:`delegation_chain` turns it back into
the scope path a policy can key on.
"""
from __future__ import annotations

import pytest

from interlock import (
    Blocked,
    Decision,
    PolicyEngine,
    SensorEvent,
    enforce_tool_call,
    guard,
    set_engine,
    span,
)
from interlock import context as _context
from interlock.policy import delegation_chain, principal_scope


@pytest.fixture(autouse=True)
def _reset_context():
    """Isolate the run-identity contextvars between tests."""
    principal = _context._principal.set(None)
    parent = _context._parent_principal.set(None)
    yield
    _context._principal.reset(principal)
    _context._parent_principal.reset(parent)


def _capture():
    """An engine whose only rule records every event it is handed."""
    seen = []

    def rule(event):
        seen.append(event)
        return None

    return seen, PolicyEngine(rules=[rule])


# --- producer: the interceptors carry the link onto the event ---------------


def test_decorator_carries_parent_principal_from_context():
    seen, engine = _capture()
    set_engine(engine)

    @guard()
    def touch(path):
        return path

    with span(principal="acme/payments/agent42", parent_principal="acme/auditor"):
        assert touch("ledger") == "ledger"

    assert seen[-1].principal == "acme/payments/agent42"
    assert seen[-1].parent_principal == "acme/auditor"


def test_decorator_leaves_parent_none_without_delegation():
    seen, engine = _capture()
    set_engine(engine)

    @guard()
    def touch(path):
        return path

    with span(principal="acme/payments/agent42"):
        touch("ledger")

    assert seen[-1].parent_principal is None


def test_mcp_path_carries_parent_principal():
    seen, engine = _capture()

    with span(principal="acme/payments/agent42", parent_principal="acme/auditor"):
        enforce_tool_call(action="read_file", arguments={}, engine=engine)

    assert seen[-1].principal == "acme/payments/agent42"
    assert seen[-1].parent_principal == "acme/auditor"


# --- consumer: delegation_chain -------------------------------------------


def test_delegation_chain_orders_delegator_first():
    ev = SensorEvent(
        action="x",
        principal="acme/payments/agent42",
        parent_principal="acme/auditor",
    )
    assert delegation_chain(ev) == (
        ("acme", "auditor"),
        ("acme", "payments", "agent42"),
    )


def test_delegation_chain_shape_unchanged_when_not_delegated():
    ev = SensorEvent(action="x", principal="acme/payments/agent42")
    assert delegation_chain(ev) == (principal_scope(ev),)


def test_delegation_chain_empty_without_principal():
    assert delegation_chain(SensorEvent(action="x")) == ()


def test_delegation_chain_drops_empty_links():
    ev = SensorEvent(action="x", principal="a", parent_principal="")
    assert delegation_chain(ev) == (("a",),)


# --- the point of the field: a rule can see and bound the delegation --------


def test_rule_uses_chain_to_bound_a_delegated_call():
    """A rule keyed on the chain allows the expected delegator and blocks others."""
    seen = []

    def require_delegator(expected):
        def rule(event):
            scopes = delegation_chain(event)
            seen.append(scopes)
            if len(scopes) == 2 and scopes[0] != expected:
                return Decision.block("delegated by an unexpected principal", "deleg")
            return None

        return rule

    set_engine(PolicyEngine(rules=[require_delegator(("acme", "auditor"))]))

    @guard()
    def touch(path):
        return path

    with span(principal="acme/payments/agent42", parent_principal="acme/auditor"):
        assert touch("ledger") == "ledger"

    with span(principal="acme/payments/agent42", parent_principal="acme/rogue"):
        with pytest.raises(Blocked):
            touch("ledger")

    assert seen == [
        (("acme", "auditor"), ("acme", "payments", "agent42")),
        (("acme", "rogue"), ("acme", "payments", "agent42")),
    ]


# --- context hygiene: the link is scoped, not sticky ------------------------


def test_span_restores_parent_principal():
    with span(principal="a", parent_principal="p"):
        assert _context.current_parent_principal() == "p"
    assert _context.current_parent_principal() is None


def test_nested_span_restores_outer_link():
    with span(principal="outer", parent_principal="root"):
        with span(principal="inner", parent_principal="outer"):
            assert _context.current_parent_principal() == "outer"
        assert _context.current_parent_principal() == "root"


def test_set_principal_does_not_erase_an_inherited_link():
    with span(principal="a", parent_principal="p"):
        _context.set_principal("b")
        assert _context.current_principal() == "b"
        assert _context.current_parent_principal() == "p"
