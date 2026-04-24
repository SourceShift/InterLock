import asyncio

import pytest

import interlock
from interlock import Blocked, Decision, PolicyEngine, deny_tool, guard


def setup_function(_):
    # Reset to an empty allow-all engine before each test.
    interlock.install(engine=PolicyEngine())


def test_allow_passes_through():
    @guard()
    def add(a, b):
        return a + b

    assert add(2, 3) == 5


def test_block_raises_before_call():
    ran = {"did": False}

    @guard(policy_id="p")
    def danger(cmd):
        ran["did"] = True
        return "ran"

    interlock.install(rules=[deny_tool("danger", reason="nope", policy_id="p")])

    with pytest.raises(Blocked) as excinfo:
        danger(cmd="x")

    assert excinfo.value.decision.reason == "nope"
    assert ran["did"] is False  # the effect never happened


def test_modify_rewrites_kwargs():
    @guard()
    def pay(amount):
        return amount

    def cap(event):
        if event.args.get("amount", 0) > 100:
            return Decision.modify({"amount": 100}, reason="capped")
        return None

    interlock.install(rules=[cap])
    assert pay(amount=1000) == 100


def test_monitor_never_blocks():
    from interlock import monitor

    @monitor(policy_id="p")
    def danger(cmd):
        return "ran"

    interlock.install(rules=[deny_tool("danger", reason="nope")])
    assert danger(cmd="x") == "ran"  # observed, not blocked


def test_async_guard_blocks():
    @guard(policy_id="p")
    async def danger(cmd):
        return "ran"

    interlock.install(rules=[deny_tool("danger", reason="no")])
    with pytest.raises(Blocked):
        asyncio.run(danger(cmd="x"))
