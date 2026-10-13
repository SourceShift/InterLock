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


def _cap_amount(event):
    if event.args.get("amount", 0) > 100:
        return Decision.modify({"amount": 100}, reason="capped")
    return None


def test_modify_rewrites_positional_arg():
    # A rewrite names the argument; the caller passed it positionally. Merging
    # into kwargs alone handed the function `amount` twice (TypeError).
    @guard()
    def transfer(amount, to):
        return (amount, to)

    interlock.install(rules=[_cap_amount])
    assert transfer(5000, "bob") == (100, "bob")
    assert transfer(5000, to="bob") == (100, "bob")


def test_modify_rewrites_positional_only_arg():
    # A positional-only parameter cannot be passed by keyword at all, so the
    # rewrite has to land back in its positional slot.
    @guard()
    def transfer(amount, /, to):
        return (amount, to)

    interlock.install(rules=[_cap_amount])
    assert transfer(5000, "bob") == (100, "bob")


def test_modify_fills_an_argument_the_caller_left_to_its_default():
    @guard()
    def transfer(to, amount=5000):
        return (amount, to)

    interlock.install(rules=[_cap_amount])
    assert transfer("bob") == (100, "bob")


def test_modify_routes_undeclared_names_into_var_keyword():
    @guard()
    def send(to, **options):
        return (to, options)

    def tag(_event):
        return Decision.modify({"priority": "low"}, reason="tagged")

    interlock.install(rules=[tag])
    assert send("bob", retries=2) == ("bob", {"retries": 2, "priority": "low"})


def test_async_modify_rewrites_positional_arg():
    @guard()
    async def transfer(amount, to):
        return (amount, to)

    interlock.install(rules=[_cap_amount])
    assert asyncio.run(transfer(5000, "bob")) == (100, "bob")


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
