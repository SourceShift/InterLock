"""What a rule sees for every shape of argument a guarded callable accepts.

``@guard`` binds a call to the wrapped signature before evaluating rules. A
keyword-variadic parameter used to hide its entries behind the variadic name,
and a positional-variadic tuple hid a command as an opaque sequence, so a rule
that blocked a named parameter let the same tool through. These tests drive
real decorated callables and real rule decisions: the event must expose each
argument under the caller's name while the call itself keeps exactly the values
the caller passed.
"""
import asyncio
import inspect

import pytest

import interlock
from interlock import Blocked, Decision, guard, monitor
from interlock.detectors.destructive_command_guard import destructive_command_guard

DESTRUCTIVE = "rm -rf /"
BENIGN = "echo hi"


def setup_function(_):
    interlock.install(engine=interlock.PolicyEngine())


def test_keyword_variadic_command_is_blocked_before_the_body_runs():
    ran = []

    @guard()
    def tool(**kwargs):
        ran.append(kwargs)
        return "ran"

    interlock.install(rules=[destructive_command_guard()])

    with pytest.raises(Blocked):
        tool(command=DESTRUCTIVE)
    assert ran == []  # the effect never happened

    assert tool(command=BENIGN) == "ran"
    assert ran == [{"command": BENIGN}]


def test_positional_variadic_command_is_blocked_and_the_body_gets_the_tuple():
    ran = []

    @guard()
    def tool(*argv):
        ran.append(argv)
        return "ran"

    interlock.install(rules=[destructive_command_guard()])

    with pytest.raises(Blocked):
        tool("rm", "-rf", "/")
    assert ran == []

    assert tool("echo", "hi") == "ran"
    assert ran == [("echo", "hi")]
    assert isinstance(ran[0], tuple)  # the call was not rewritten


def test_bound_instance_method_is_blocked():
    ran = []

    class Tool:
        @guard()
        def run(self, command):
            ran.append(command)
            return "ran"

    interlock.install(rules=[destructive_command_guard()])
    tool = Tool()

    with pytest.raises(Blocked):
        tool.run(command=DESTRUCTIVE)
    assert ran == []

    assert tool.run(command=BENIGN) == "ran"
    assert ran == [BENIGN]


class _Runner:
    def __init__(self):
        self.seen = []

    def run(self, command):
        self.seen.append(command)
        return "ran"


def test_already_bound_method_is_blocked():
    runner = _Runner()
    bound_run = guard()(runner.run)
    interlock.install(rules=[destructive_command_guard()])

    with pytest.raises(Blocked):
        bound_run(command=DESTRUCTIVE)
    assert runner.seen == []

    assert bound_run(BENIGN) == "ran"
    assert runner.seen == [BENIGN]


def test_a_rule_sees_every_keyword_by_name():
    seen = {}

    def capture(event):
        seen.update(event.args)
        return None

    @guard()
    def tool(command=None, **kwargs):
        return command, kwargs

    interlock.install(rules=[capture])
    assert tool(command=BENIGN, retries=2) == (BENIGN, {"retries": 2})

    assert seen["command"] == BENIGN
    assert seen["retries"] == 2
    # The variadic key survives with the caller's mapping.
    assert seen["kwargs"] == {"retries": 2}


def test_a_declared_parameter_wins_over_a_keyword_of_the_same_name():
    # A real caller cannot pass both (binding refuses the duplicate), but the
    # event map is policy-controlled state and must still be deterministic.
    from interlock.interceptors.decorator import _exposed_arguments

    def tool(command=None, **kwargs):
        return command, kwargs

    args = _exposed_arguments(
        inspect.signature(tool),
        {"command": "declared", "kwargs": {"command": "variadic"}},
    )
    assert args["command"] == "declared"
    assert args["kwargs"] == {"command": "variadic"}


def test_modify_of_a_keyword_variadic_name_reaches_the_kwargs_mapping():
    # A MODIFY naming a flattened keyword must reach the call as that keyword.
    @guard()
    def send(**kwargs):
        return kwargs

    def redact(event):
        if event.args.get("token") == "secret":
            return Decision.modify({"token": "***"}, reason="redacted")
        return None

    interlock.install(rules=[redact])
    assert send(token="secret", to="bob") == {"token": "***", "to": "bob"}


def test_modify_of_a_declared_parameter_still_rewrites_the_call():
    # The unchanged tests/test_guard.py case, kept here as the contract's
    # regression anchor: a rewrite of a named parameter still lands in place.
    @guard()
    def pay(amount):
        return amount

    def cap(event):
        if event.args.get("amount", 0) > 100:
            return Decision.modify({"amount": 100}, reason="capped")
        return None

    interlock.install(rules=[cap])
    assert pay(amount=1000) == 100
    assert pay(5000) == 100


def test_monitor_observes_a_variadic_tool_without_blocking_it():
    ran = []

    @monitor()
    def tool(**kwargs):
        ran.append(kwargs)
        return "ran"

    interlock.install(rules=[destructive_command_guard()])
    assert tool(command=DESTRUCTIVE) == "ran"
    assert ran == [{"command": DESTRUCTIVE}]


def test_a_non_string_variadic_stays_the_original_sequence():
    seen = {}

    def capture(event):
        seen.update(event.args)
        return None

    @guard()
    def tool(*argv):
        return argv

    interlock.install(rules=[capture])
    assert tool("echo", 3) == ("echo", 3)
    assert seen["argv"] == ("echo", 3)


def test_event_args_never_aliases_the_callers_mapping():
    def tamper(event):
        event.args["command"] = "benign"
        event.args["kwargs"]["command"] = "benign"
        return None

    @guard()
    def tool(**kwargs):
        return kwargs

    interlock.install(rules=[tamper])
    caller = {"command": DESTRUCTIVE}
    assert tool(**caller) == {"command": DESTRUCTIVE}
    assert caller == {"command": DESTRUCTIVE}


def test_a_method_event_keeps_its_declared_names():
    seen = {}

    def capture(event):
        seen.update(event.args)
        return None

    class Tool:
        @guard()
        def run(self, command):
            return command

    interlock.install(rules=[capture])
    tool = Tool()
    assert tool.run(BENIGN) == BENIGN
    assert seen["command"] == BENIGN
    assert seen["self"] is tool  # self is present but displaces nothing


def test_async_keyword_variadic_tool_is_blocked():
    ran = []

    @guard()
    async def tool(**kwargs):
        ran.append(kwargs)
        return "ran"

    interlock.install(rules=[destructive_command_guard()])

    with pytest.raises(Blocked):
        asyncio.run(tool(command=DESTRUCTIVE))
    assert ran == []

    assert asyncio.run(tool(command=BENIGN)) == "ran"
