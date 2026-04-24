"""Run identity: every event must be attributable to one agent run."""
import interlock
from interlock import current_span, guard, span


def test_event_carries_span_identity():
    seen = {}

    def recorder(event):
        seen["span"] = event.span_id
        seen["principal"] = event.principal
        return None  # allow

    interlock.install(rules=[recorder])

    @guard()
    def tool(x):
        return x

    with span(principal="agent-x"):
        assert tool(x=1) == 1

    assert seen["span"] is not None
    assert seen["principal"] == "agent-x"


def test_no_span_identity_outside_context():
    seen = {}

    def recorder(event):
        seen["span"] = event.span_id
        return None

    interlock.install(rules=[recorder])

    @guard()
    def tool(x):
        return x

    tool(x=1)
    assert seen["span"] is None


def test_span_restores_after_scope():
    assert current_span() is None
    with span(principal="a") as sid:
        assert current_span() == sid
    assert current_span() is None
