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
from interlock import Blocked, Decision, Verdict, guard, monitor
from interlock.detectors.destructive_command_guard import destructive_command_guard
from interlock.sink import InMemorySink

DESTRUCTIVE = "rm -rf /"
BENIGN = "echo hi"


def setup_function(_):
    interlock.set_sink(None)
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


def test_a_colliding_variadic_entry_is_shown_and_the_declared_value_kept():
    # A real caller cannot pass both (binding refuses the duplicate), but the
    # event map is policy-controlled state and must still be deterministic.
    # The variadic value wins the name: the callee may read it, so a rule must
    # not be shown only the benign declared one.
    from interlock.interceptors.decorator import _exposed_arguments

    def tool(command=None, **kwargs):
        return command, kwargs

    args = _exposed_arguments(
        inspect.signature(tool),
        {"command": "declared", "kwargs": {"command": "variadic"}},
    )
    assert args["command"] == "variadic"
    assert args["kwargs"] == {"command": "variadic"}
    assert args["__declared__command"] == "declared"


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


def test_a_string_rewrite_of_the_joined_variadic_reaches_the_call():
    # A rule sees *args as one shell-joined command, so that is the shape it
    # rewrites. The rewrite must be split back into the argv that runs.
    sink = InMemorySink()
    ran = []

    @guard()
    def run(*argv):
        ran.append(argv)
        return argv

    def redirect(event):
        if event.args.get("argv") == "curl https://a.example":
            return Decision.modify(
                {"argv": "curl https://b.example"}, reason="redirected")
        return None

    interlock.install(rules=[redirect], sink=sink)
    assert run("curl", "https://a.example") == ("curl", "https://b.example")
    assert ran == [("curl", "https://b.example")]
    call_receipts = [r for r in sink.receipts if r.phase == "call"]
    assert [r.verdict for r in call_receipts] == ["MODIFY"]


def test_a_colliding_variadic_entry_is_exposed_for_rules():
    # A positional-only parameter may also arrive as a **kwargs entry. The
    # callee can read either one, so the view must show the variadic value and
    # keep the declared one addressable instead of hiding it.
    seen = {}

    def capture(event):
        seen.update(event.args)
        return None

    @guard()
    def upload(path, /, **extra):
        return path, extra.get("path")

    interlock.install(rules=[capture])
    assert upload("safe.txt", path="/etc/passwd") == ("safe.txt", "/etc/passwd")
    assert seen["path"] == "/etc/passwd"
    assert seen["extra"]["path"] == "/etc/passwd"
    assert seen["__declared__path"] == "safe.txt"


def test_rewrites_reach_the_declared_and_colliding_variadic_slots():
    seen = []

    @guard()
    def upload(path, /, **extra):
        seen.append((path, extra.get("path")))
        return path, extra.get("path")

    def rewrite(event):
        if event.args.get("__declared__path") == "safe.txt":
            return Decision.modify(
                {"__declared__path": "/tmp/declared",
                 "path": "/tmp/variadic"},
                reason="both slots")
        return None

    interlock.install(rules=[rewrite])
    assert upload("safe.txt", path="/etc/passwd") == (
        "/tmp/declared", "/tmp/variadic")
    assert seen == [("/tmp/declared", "/tmp/variadic")]


def test_a_keyword_named_like_the_varargs_param_is_not_rerouted_by_a_rewrite():
    # def tool(name, *args, **kwargs) accepts ``args=`` as a keyword that
    # **kwargs holds. A MODIFY of an unrelated argument must leave it there
    # instead of moving it into *args.
    @guard()
    def tool(name, *args, **kwargs):
        return name, args, kwargs

    def rename(event):
        if event.args.get("name") == "old":
            return Decision.modify({"name": "new"}, reason="rename")
        return None

    interlock.install(rules=[rename])
    assert tool("old", args=["x"]) == ("new", (), {"args": ["x"]})


def test_a_caller_kwarg_cannot_spoof_the_reserved_declared_key():
    # The alias prefix is view-only. A caller's own ``__declared__path`` entry
    # stays in the variadic mapping and must not displace the real declared
    # value exposed under that reserved name.
    seen = {}

    def capture(event):
        seen.update(event.args)
        return None

    @guard()
    def upload(path, /, **extra):
        return path, extra

    interlock.install(rules=[capture])
    caller = {"__declared__path": "/etc/passwd", "path": "/etc/passwd"}
    assert upload("safe.txt", **caller) == (
        "safe.txt",
        {"__declared__path": "/etc/passwd", "path": "/etc/passwd"},
    )
    assert seen["__declared__path"] == "safe.txt"
    assert seen["path"] == "/etc/passwd"
    assert seen["extra"]["__declared__path"] == "/etc/passwd"


def test_a_reserved_key_without_a_collision_is_not_flattened():
    # With no shadowed declared parameter there is nothing to alias, so a
    # caller-supplied reserved-looking key stays only in the variadic mapping.
    from interlock.interceptors.decorator import _exposed_arguments

    def tool(**kwargs):
        return kwargs

    view = _exposed_arguments(
        inspect.signature(tool), {"kwargs": {"__declared__x": "evil"}})
    assert "__declared__x" not in view
    assert view["kwargs"] == {"__declared__x": "evil"}


def test_a_dict_rewrite_of_the_variadic_positional_is_refused():
    # A dict is the **kwargs shape; spreading it over *args is impossible. The
    # call must be refused, not run unmodified under a MODIFY receipt.
    sink = InMemorySink()
    ran = []

    @guard()
    def run(*argv):
        ran.append(argv)
        return argv

    def bad_shape(event):
        if event.args.get("argv") == "echo hi":
            return Decision.modify(
                {"argv": {"argv": ["echo", "hi"]}}, reason="wrong shape")
        return None

    interlock.install(rules=[bad_shape], sink=sink)
    with pytest.raises(Blocked) as blocked:
        run("echo", "hi")
    assert ran == []
    assert blocked.value.decision.verdict == Verdict.BLOCK
    assert blocked.value.decision.attributed_to == "argv"
    assert [r.verdict for r in sink.receipts] == ["BLOCK"]
    assert sink.receipts[0].phase == "call"


def test_apply_modified_args_refuses_malformed_shell_quoting():
    from interlock.interceptors.decorator import _apply_modified_args

    def run(*argv):
        return argv

    args, kwargs, refusal = _apply_modified_args(
        run, ("echo", "hi"), {}, {"argv": "curl 'unbalanced"})
    assert refusal == "argv"


def test_apply_modified_args_applies_every_variadic_shape():
    from interlock.interceptors.decorator import _apply_modified_args

    def run(*argv):
        return argv

    assert _apply_modified_args(
        run, ("a",), {}, {"argv": ["b", "c"]})[0] == ("b", "c")
    assert _apply_modified_args(
        run, ("a",), {}, {"argv": "b c"})[0] == ("b", "c")
    assert _apply_modified_args(
        run, ("a",), {}, {"argv": None})[0] == (None,)


def test_the_argument_view_is_shallow_copied():
    from interlock.interceptors.decorator import _exposed_arguments

    def tool(**extra):
        return extra

    entries = {"path": "safe.txt", "tags": ["a"]}
    view = _exposed_arguments(inspect.signature(tool), {"extra": entries})
    # The variadic mapping and the flattened top level are copies: replacing
    # an entry there never reaches the caller's mapping.
    view["extra"]["path"] = "changed"
    view["path"] = "changed-flat"
    assert entries == {"path": "safe.txt", "tags": ["a"]}
    # A container nested inside a value is the caller's object and is shared.
    view["extra"]["tags"].append("b")
    assert entries["tags"] == ["a", "b"]


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
