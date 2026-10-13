"""ESCALATE and bound approvals (R2): who decides, what an approval covers, and
every way an approval must fail closed."""
import pytest

import interlock
from interlock import (
    Blocked,
    Decision,
    NotApproved,
    PolicyEngine,
    Verdict,
    approve_for,
    approve_for_session,
    approve_once,
    deny_tool,
    guard,
    install,
    monitor,
    set_approver,
    span,
)
from interlock import approval as approval_mod
from interlock.approval import MAX_REASON_BYTES, ApprovalRequest, bound_reason, grants, tty_approver
from interlock.interceptors.mcp import enforce_tool_call, enforce_tool_result
from interlock.receipt import set_sink
from interlock.sink import InMemorySink


def escalate_on(action, reason="needs a human"):
    def rule(event):
        if event.action == action:
            return Decision.escalate(reason, policy_id="ask", attributed_to="cmd")
        return None
    return rule


class Recorder:
    def __init__(self, answer=True):
        self.answer = answer
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return self.answer


@pytest.fixture
def sink():
    s = InMemorySink()
    set_sink(s)
    yield s
    set_sink(None)


def make_tool(calls):
    @guard()
    def publish(cmd):
        calls.append(cmd)
        return "done"
    return publish


# --- the verdict and the engine ----------------------------------------------


def test_escalate_builder():
    d = Decision.escalate("why", policy_id="p", attributed_to="a")
    assert (d.verdict, d.reason, d.policy_id, d.attributed_to) == (Verdict.ESCALATE, "why", "p", "a")
    assert int(Verdict.ESCALATE) == 3


@pytest.mark.parametrize("order", ["escalate_first", "block_first"])
def test_a_block_from_any_rule_wins_over_an_escalation(order):
    rules = [escalate_on("publish"), deny_tool("publish")]
    if order == "block_first":
        rules.reverse()
    approver = Recorder()
    install(rules=rules, approver=approver)
    calls = []
    with pytest.raises(Blocked) as info:
        make_tool(calls)("npm publish")
    assert not isinstance(info.value, NotApproved)
    assert calls == [] and approver.requests == []


def test_escalation_carries_later_rewrites():
    def rewrite(event):
        return Decision.modify({"cmd": "npm publish --dry-run"}, "dry run first")
    engine = PolicyEngine([escalate_on("publish"), rewrite])
    decision = engine.evaluate(interlock.SensorEvent("publish", {"cmd": "npm publish"}))
    assert decision.verdict is Verdict.ESCALATE
    assert decision.modified_args == {"cmd": "npm publish --dry-run"}
    install(engine=engine, approver=Recorder())
    calls = []
    make_tool(calls)("npm publish")
    assert calls == ["npm publish --dry-run"]


# --- who decides ---------------------------------------------------------------


def test_no_approver_blocks(sink):
    install(rules=[escalate_on("publish")])
    calls = []
    with pytest.raises(NotApproved) as info:
        make_tool(calls)("npm publish")
    assert isinstance(info.value, Blocked)
    assert calls == []
    assert "no approver" in info.value.decision.reason
    receipt = sink.receipts[-1]
    assert (receipt.verdict, receipt.policy_verdict, receipt.approval) == (
        "BLOCK", "ESCALATE", "no-approver")


def test_approved_once_runs_and_is_recorded(sink):
    approver = Recorder(True)
    install(rules=[escalate_on("publish")], approver=approver)
    calls = []
    assert make_tool(calls)("npm publish") == "done"
    assert calls == ["npm publish"]
    call_receipt = [r for r in sink.receipts if r.phase == "call"][0]
    assert (call_receipt.verdict, call_receipt.policy_verdict, call_receipt.approval) == (
        "ALLOW", "ESCALATE", "approved:once")
    request = approver.requests[0]
    assert request.action == "publish" and request.attributed_to == "cmd"
    assert request.event.args == {"cmd": "npm publish"}


def test_once_is_not_replayable():
    approver = Recorder(approve_once())
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    tool("npm publish")
    tool("npm publish")
    assert len(approver.requests) == 2


@pytest.mark.parametrize("answer, how", [
    (False, "declined"), (None, "declined"), ("yes", "declined"),
])
def test_anything_but_an_approval_declines(sink, answer, how):
    install(rules=[escalate_on("publish")], approver=Recorder(answer))
    with pytest.raises(NotApproved):
        make_tool([])("npm publish")
    assert sink.receipts[-1].approval == how


def test_an_approver_that_raises_has_not_approved(sink):
    def broken(request):
        raise RuntimeError("ui crashed")
    install(rules=[escalate_on("publish")], approver=broken)
    with pytest.raises(NotApproved) as info:
        make_tool([])("npm publish")
    assert "RuntimeError" in info.value.decision.reason
    assert sink.receipts[-1].approval == "approver-error"


# --- what an approval covers ---------------------------------------------------


def test_session_grant_reuses_only_within_the_span_and_for_the_same_args(sink):
    approver = Recorder(approve_for_session())
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    with span(principal="agent"):
        tool("npm publish")
        tool("npm publish")
        assert len(approver.requests) == 1
        assert sink.receipts[-2].approval == "reused:session"
        tool("npm publish --tag beta")  # different args: asked again
        assert len(approver.requests) == 2
    with span(principal="agent"):
        tool("npm publish")  # new span: asked again
        assert len(approver.requests) == 3


def test_session_grant_without_a_span_is_one_use(sink):
    approver = Recorder(approve_for_session())
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    tool("npm publish")
    tool("npm publish")
    assert len(approver.requests) == 2
    assert [r.approval for r in sink.receipts if r.phase == "call"] == [
        "approved:once", "approved:once"]


def test_ttl_grant_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(approval_mod.time, "time", lambda: clock[0])
    approver = Recorder(approve_for(60))
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    tool("npm publish")
    clock[0] += 30
    tool("npm publish")
    assert len(approver.requests) == 1
    clock[0] += 31
    tool("npm publish")
    assert len(approver.requests) == 2


def test_a_policy_reload_invalidates_grants():
    approver = Recorder(approve_for(3600))
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    tool("npm publish")
    tool("npm publish")
    assert len(approver.requests) == 1
    install(rules=[escalate_on("publish")])  # same rule names, new rule set
    tool("npm publish")
    assert len(approver.requests) == 2


def test_a_policy_change_while_the_approver_decides_fails_closed():
    def reloading_approver(request):
        install(rules=[escalate_on("publish")])
        return True
    install(rules=[escalate_on("publish")], approver=reloading_approver)
    calls = []
    with pytest.raises(NotApproved) as info:
        make_tool(calls)("npm publish")
    assert "policy changed" in info.value.decision.reason
    assert calls == []


def test_revoke():
    approver = Recorder(approve_for(3600))
    install(rules=[escalate_on("publish")], approver=approver)
    tool = make_tool([])
    tool("npm publish")
    assert len(grants().active()) == 1
    assert grants().revoke(action="publish") == 1
    assert grants().active() == []
    tool("npm publish")
    assert len(approver.requests) == 2


def test_approve_for_needs_positive_seconds():
    with pytest.raises(ValueError):
        approve_for(0)


# --- the reason ---------------------------------------------------------------


def test_reason_is_bounded_to_one_printable_line():
    long = "line one\nline two\t\x1b[31m" + "é" * 600
    bounded = bound_reason(long)
    assert "\n" not in bounded and "\x1b" not in bounded
    assert len(bounded.encode("utf-8")) <= MAX_REASON_BYTES
    assert bounded.startswith("line one line two")


def test_request_is_frozen():
    approver = Recorder(True)
    install(rules=[escalate_on("publish", reason="a\nb")], approver=approver)
    make_tool([])("x")
    request = approver.requests[0]
    assert request.reason == "a b"
    with pytest.raises(Exception):
        request.reason = "something else"  # type: ignore[misc]
    assert isinstance(request, ApprovalRequest)


# --- other paths --------------------------------------------------------------


def test_result_phase_escalation():
    def ask_about_result(event):
        return Decision.escalate("result looks odd")
    ask_about_result.phase = "result"
    install(rules=[ask_about_result])
    with pytest.raises(NotApproved):
        enforce_tool_result("read", "payload")
    set_approver(lambda r: True)
    assert enforce_tool_result("read", "payload") == "payload"


def test_mcp_call_escalation():
    install(rules=[escalate_on("publish")], approver=Recorder(False))
    with pytest.raises(NotApproved):
        enforce_tool_call("publish", {"cmd": "x"})


def test_monitor_mode_records_and_never_asks(sink):
    approver = Recorder(False)
    install(rules=[escalate_on("publish")], approver=approver)
    calls = []

    @monitor()
    def publish(cmd):
        calls.append(cmd)

    publish("npm publish")
    assert calls == ["npm publish"] and approver.requests == []
    assert sink.receipts[0].verdict == "ESCALATE" and sink.receipts[0].observed


def test_tty_approver_without_a_terminal_declines(monkeypatch):
    def no_tty(*args, **kwargs):
        raise OSError("no tty")
    monkeypatch.setattr("builtins.open", no_tty)
    request = ApprovalRequest(request_id="r", action="a", phase="call",
                              args_digest="d", reason="why")
    assert tty_approver()(request) is None
