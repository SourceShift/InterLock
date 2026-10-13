"""Enforcement provenance in receipts (R17): call ids, policy epochs, outcome
receipts, timing, and fail-closed sink writes with dropped-receipt accounting."""
import json

import pytest

from interlock import (
    Blocked,
    Decision,
    PolicyEngine,
    deny_tool,
    guard,
    install,
    monitor,
)
from interlock.interceptors.mcp import enforce_tool_call, enforce_tool_result, guard_mcp_session
from interlock.receipt import (
    GENESIS,
    SINK_POLICY_ID,
    Receipt,
    dropped_receipts,
    set_sink,
    verify_chain,
)
from interlock.sink import FileSink, InMemorySink


@pytest.fixture
def sink():
    s = InMemorySink()
    set_sink(s)
    yield s
    set_sink(None)


def test_call_and_result_receipts_share_one_call_id(sink):
    @guard()
    def tool(x):
        return x

    tool(1)
    tool(2)
    call_ids = [r.call_id for r in sink.receipts]
    assert len(call_ids) == 4 and all(call_ids)
    assert call_ids[0] == call_ids[1] and call_ids[2] == call_ids[3]
    assert call_ids[0] != call_ids[2]
    assert [r.phase for r in sink.receipts] == ["call", "result", "call", "result"]


def test_mcp_session_links_call_and_result(sink):
    class Session:
        def call_tool(self, name, arguments=None):
            return {"content": [{"type": "text", "text": "ok"}]}

    guard_mcp_session(Session()).call_tool("read", {"p": 1})
    assert len(sink.receipts) == 2
    assert sink.receipts[0].call_id == sink.receipts[1].call_id is not None


def test_explicit_call_id_threads_through_the_functional_api(sink):
    enforce_tool_call("t", {"a": 1}, call_id="abc")
    enforce_tool_result("t", "out", call_id="abc")
    assert [r.call_id for r in sink.receipts] == ["abc", "abc"]


def test_policy_epoch_is_recorded_and_changes_with_the_rules(sink):
    engine = install(rules=[deny_tool("never")])
    enforce_tool_call("t", {})
    first = sink.receipts[-1].policy_epoch
    assert first == engine.epoch and len(first) == 16
    engine.add_rule(deny_tool("also_never"))
    enforce_tool_call("t", {})
    assert sink.receipts[-1].policy_epoch == engine.epoch != first


def test_elapsed_us_is_recorded(sink):
    enforce_tool_call("t", {})
    assert isinstance(sink.receipts[0].elapsed_us, int)
    assert sink.receipts[0].elapsed_us >= 0


def test_failed_tool_leaves_an_outcome_receipt(sink):
    @guard()
    def broken():
        raise ValueError("boom")

    @guard()
    def forbidden():
        raise PermissionError("Operation not permitted")

    with pytest.raises(ValueError):
        broken()
    with pytest.raises(PermissionError):
        forbidden()
    outcomes = [r for r in sink.receipts if r.phase == "outcome"]
    assert [(r.outcome, r.enforcer, r.reason) for r in outcomes] == [
        ("failed", "tool", "ValueError"), ("failed", "os", "PermissionError"),
    ]
    calls = [r for r in sink.receipts if r.phase == "call"]
    assert [r.call_id for r in calls] == [r.call_id for r in outcomes]


def test_failed_mcp_tool_leaves_an_outcome_receipt(sink):
    class Session:
        def call_tool(self, name, arguments=None):
            raise PermissionError("denied")

    with pytest.raises(PermissionError):
        guard_mcp_session(Session()).call_tool("write", {})
    assert sink.receipts[-1].phase == "outcome"
    assert sink.receipts[-1].enforcer == "os"
    assert sink.receipts[-1].call_id == sink.receipts[0].call_id


def test_nested_guard_block_is_attributed_to_policy(sink):
    install(rules=[deny_tool("inner")])

    @guard()
    def inner():
        return 1

    @guard()
    def outer():
        return inner()

    with pytest.raises(Blocked):
        outer()
    outcome = [r for r in sink.receipts if r.phase == "outcome"]
    assert outcome and outcome[0].enforcer == "policy"


def test_monitor_receipts_keep_their_shape(sink):
    install(rules=[deny_tool("t")])

    @monitor()
    def t():
        return 1

    t()
    call = sink.receipts[0]
    assert call.verdict == "BLOCK" and call.observed and call.policy_verdict is None


def test_empty_provenance_fields_are_omitted_from_the_serialized_form():
    receipt = Receipt(ts=1.0, action="a", verdict="ALLOW")
    body = json.loads(receipt.to_json())
    for name in ("call_id", "policy_epoch", "policy_verdict", "approval", "outcome",
                 "enforcer", "elapsed_us", "observed"):
        assert name not in body


def test_chains_with_and_without_provenance_verify_together(tmp_path):
    path = tmp_path / "r.jsonl"
    sink = FileSink(str(path), key=b"k")
    sink.write(Receipt(ts=1.0, action="old", verdict="ALLOW"))
    set_sink(sink)
    try:
        enforce_tool_call("new", {"a": 1}, call_id="c1")
    finally:
        set_sink(None)
    assert sink.verify() is None
    lines = path.read_text().splitlines()
    assert "call_id" not in lines[0] and '"call_id":"c1"' in lines[1]


class FlakySink(InMemorySink):
    def __init__(self, failures):
        super().__init__()
        self.failures = failures

    def _append(self, receipt):
        if self.failures:
            self.failures -= 1
            raise OSError("disk full")
        super()._append(receipt)


def test_a_failed_write_blocks_fail_closed_and_is_reported_later():
    sink = FlakySink(failures=2)
    set_sink(sink)
    ran = []

    @guard()
    def tool():
        ran.append(1)

    try:
        for _ in range(2):
            with pytest.raises(Blocked) as info:
                tool()
            assert info.value.decision.policy_id == SINK_POLICY_ID
            assert isinstance(info.value.__cause__, OSError)
        assert ran == []
        assert dropped_receipts() == 2
        tool()
    finally:
        set_sink(None)
    assert ran == [1]
    notice = sink.receipts[0]
    assert notice.action == "receipts.dropped"
    assert notice.reason.startswith("2 receipt(s) could not be written")
    assert dropped_receipts() == 0


def test_dropped_notice_is_part_of_the_chain():
    sink = FlakySink(failures=1)
    set_sink(sink)
    try:
        with pytest.raises(Blocked):
            enforce_tool_call("t", {})
        enforce_tool_call("t", {})
    finally:
        set_sink(None)
    assert sink.receipts[0].prev == GENESIS
    assert sink.verify() is None
    assert verify_chain(sink.receipts, sink._signer, sink._key) is None


def test_unknown_verdict_is_blocked_and_recorded(sink):
    install(rules=[lambda e: Decision(verdict=7, reason="weird")])  # type: ignore[arg-type]
    with pytest.raises(Blocked) as info:
        enforce_tool_call("t", {})
    assert "unhandled verdict" in info.value.decision.reason
    assert sink.receipts[-1].verdict == "BLOCK"
    assert sink.receipts[-1].policy_verdict == "7"


def test_scoped_engine_epoch_follows_the_scope():
    from interlock import SensorEvent
    from interlock.policy.engine import epoch_of
    from interlock.policy.scopes import (
        Binding,
        ScopedEngine,
        ScopeRegistry,
        ScopeTree,
        Template,
    )

    tree = ScopeTree()
    tree.bind(("org",), [Binding("deny", {"name": "x"})])
    registry = ScopeRegistry(tree, {"deny": Template("deny", lambda name: deny_tool(name))})
    engine = ScopedEngine(registry)
    event = SensorEvent(action="t", principal="org")
    first = epoch_of(engine, event)
    assert first is not None and len(first) == 16
    assert epoch_of(engine, SensorEvent(action="t")) is None
    tree.bind(("org",), [Binding("deny", {"name": "y"})])
    assert epoch_of(engine, event) != first
