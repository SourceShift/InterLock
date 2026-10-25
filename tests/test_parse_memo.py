"""One parse per event, and a bounded parse when a command is hostile."""
from __future__ import annotations

from interlock.shell import parser as parser_mod
from interlock.shell.parser import MAX_ARGS, MAX_INPUT, parse


def test_parse_is_shared_inside_one_event(monkeypatch):
    calls = []
    original = parser_mod._parse

    def counting(command):
        calls.append(command)
        return original(command)

    monkeypatch.setattr(parser_mod, "_parse", counting)

    parse("ls")
    parse("ls")
    assert calls == ["ls", "ls"]  # outside a memo, nothing is shared

    calls.clear()
    with parser_mod.memoized_parse():
        first = parse("ls")
        second = parse("ls")
        assert first is second
        with parser_mod.memoized_parse():  # nested: reuse the outer table
            assert parse("ls") is first
        parse("pwd")
    assert calls == ["ls", "pwd"]

    parse("ls")
    assert calls[-1] == "ls"  # the memo did not outlive its block


def test_a_long_argument_list_is_partial_not_unbounded():
    command = "echo " + " ".join("arg{}".format(i) for i in range(MAX_ARGS + 100))
    parsed = parse(command)
    assert parsed.partial is True
    assert len(parsed.invocations) == 1
    # The program name is the first token, so the argument list stops one short
    # of the cap - or earlier, when MAX_INPUT truncated the text first.
    assert len(parsed.invocations[0].args) <= MAX_ARGS - 1
    assert parsed.invocations[0].args[0] == "arg0"


def test_input_past_the_cap_is_partial():
    assert parse("echo " + "x" * MAX_INPUT).partial is True
    assert parse("echo x").partial is False
