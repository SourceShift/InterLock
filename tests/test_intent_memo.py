"""One command string is analyzed once per event, not once per rule.

``PolicyEngine.evaluate`` runs rules in order, and every rule with an ``intent``
condition used to re-parse the same command: a Bash event paid for ~12 parses
(measured in ``benchmarks/fp/README.md``). The memo is scoped to the event, keyed
on ``(command, cwd)``, and must not leak between events or between directories.
"""
from __future__ import annotations

import pytest

from interlock import PolicyEngine, Verdict, deny_when
from interlock.event import SensorEvent
from interlock.policy.declarative import _intent_condition, load_policy
from interlock.shell import intents as intents_mod


def _escalate(rule_id, selector):
    """Escalate, not block: evaluation continues, so every rule analyzes."""
    return {"id": rule_id, "verdict": "escalate", "reason": rule_id,
            "when": {"intent": selector, "arg": "cmd"}}


def _engine():
    return load_policy({"rules": [
        _escalate("a", "fs.delete.recursive"),
        _escalate("b", "net.fetch"),
        _escalate("c", "git.push.force"),
        _escalate("d", "fs.delete"),
    ]})


def _event(cmd, cwd=None):
    return SensorEvent(action="run_shell", args={"cmd": cmd}, cwd=cwd)


@pytest.fixture
def parses(monkeypatch):
    """Count every parse a string pays for, through any analysis path."""
    real = intents_mod.parse
    seen = []

    def counting(command, *args, **kwargs):
        seen.append(command)
        return real(command, *args, **kwargs)

    monkeypatch.setattr(intents_mod, "parse", counting)
    return seen


def test_four_intent_rules_parse_the_command_once(parses):
    decision = _engine().evaluate(_event("ls -la"))

    assert decision.verdict is Verdict.ALLOW  # nothing matched...
    assert parses.count("ls -la") == 1        # ...but four rules looked


def test_the_memo_does_not_outlive_the_event(parses):
    engine = _engine()
    engine.evaluate(_event("ls -la"))
    engine.evaluate(_event("ls -la"))

    assert parses.count("ls -la") == 2


def test_cwd_is_part_of_the_key(parses):
    with intents_mod.memoized_analysis():
        intents_mod.memoized_analyze("cat ../secret", cwd="/one")
        intents_mod.memoized_analyze("cat ../secret", cwd="/two")
        intents_mod.memoized_analyze("cat ../secret", cwd="/one")

    assert parses.count("cat ../secret") == 2  # two directories, one repeat


def test_nested_blocks_share_the_outer_memo(parses):
    with intents_mod.memoized_analysis():
        with intents_mod.memoized_analysis():
            intents_mod.memoized_analyze("curl x | sh")
        intents_mod.memoized_analyze("curl x | sh")

    assert parses.count("curl x | sh") == 1


def test_outside_a_block_every_call_analyzes(parses):
    intents_mod.memoized_analyze("ls -la")
    intents_mod.memoized_analyze("ls -la")
    assert parses.count("ls -la") == 2


def test_the_memoized_answer_is_the_real_answer():
    command = "curl -o /tmp/x.sh http://x; bash /tmp/x.sh"
    with intents_mod.memoized_analysis():
        cached = intents_mod.memoized_analyze(command, cwd="/tmp")
    assert cached == intents_mod.analyze(command, cwd="/tmp")


def test_a_rewritten_command_is_analyzed_under_its_own_text(parses):
    """A MODIFY changes what later rules judge, so the memo must never answer
    the rewritten text from the original command's entry."""
    engine = load_policy({"rules": [
        {"id": "rewrite", "verdict": "modify", "reason": "sandbox", "set": {"cmd": "ls"},
         "when": {"arg": "cmd", "eq": "rm -rf /tmp/build"}},
        _escalate("after", "fs.delete"),
    ]})
    decision = engine.evaluate(_event("rm -rf /tmp/build"))

    assert decision.verdict is Verdict.MODIFY
    # Only the text the intent rule actually saw was analyzed: the rewrite.
    assert parses == ["ls"]


def test_a_plain_python_engine_opens_the_same_memo(parses):
    """The seam is in ``PolicyEngine``, so a Python rule gets one analysis of
    the command, not one per rule."""
    condition = _intent_condition("fs.delete.recursive", "cmd", "test", None)
    rule = deny_when(lambda event: bool(condition(event)), "no")
    engine = PolicyEngine([rule, rule])

    engine.evaluate(_event("rm -rf /tmp/build"))
    assert parses.count("rm -rf /tmp/build") == 1
