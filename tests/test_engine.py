"""Foundation invariants for the policy engine and enforcement."""
import pytest

import interlock
from interlock import Blocked, Decision, Verdict, deny_tool, deny_when, guard


def test_verdict_integer_contract():
    # These integers are a contract: the future native engine returns them as
    # an out-param, so ALLOW/BLOCK/MODIFY must stay 0/1/2.
    assert int(Verdict.ALLOW) == 0
    assert int(Verdict.BLOCK) == 1
    assert int(Verdict.MODIFY) == 2


def test_default_engine_allows():
    @guard()
    def tool(x):
        return x

    assert tool(x=7) == 7  # no rules installed -> allow


def test_first_non_allow_rule_wins():
    def block_first(_event):
        return Decision.block("first")

    def modify_second(_event):
        return Decision.modify({"x": 0}, "second")

    interlock.install(rules=[block_first, modify_second])

    @guard()
    def tool(x):
        return x

    with pytest.raises(Blocked) as excinfo:
        tool(x=5)
    assert excinfo.value.decision.reason == "first"


def test_deny_when_fails_closed_on_error():
    def boom(_event):
        raise RuntimeError("kaboom")

    interlock.install(rules=[deny_when(boom, reason="checked")])

    @guard()
    def tool(x):
        return x

    with pytest.raises(Blocked) as excinfo:
        tool(x=1)
    assert "fail-closed" in excinfo.value.decision.reason


def test_deny_tool_matches_by_action_name():
    interlock.install(rules=[deny_tool("secret_tool", reason="no")])

    @guard()
    def secret_tool():
        return "ran"

    @guard()
    def safe_tool():
        return "ok"

    assert safe_tool() == "ok"
    with pytest.raises(Blocked):
        secret_tool()


def test_modify_only_touches_named_kwarg():
    def cap(event):
        if event.args.get("amount", 0) > 100:
            return Decision.modify({"amount": 100}, reason="capped")
        return None

    interlock.install(rules=[cap])

    @guard()
    def pay(amount, memo="x"):
        return (amount, memo)

    assert pay(amount=1000, memo="rent") == (100, "rent")
