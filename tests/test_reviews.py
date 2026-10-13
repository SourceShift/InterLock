"""The durable review queue (hoop review H3): file, decide, release once."""
import json
import threading
import time

import pytest

from interlock import Decision, NotApproved, guard, install, set_approver
from interlock.adapters import get_adapter, run_hook
from interlock.approval import make_request
from interlock.cli import main
from interlock.event import SensorEvent
from interlock.mcp_server import StdioServer
from interlock.policy.declarative import load_policy
from interlock.receipt import set_sink
from interlock.reviews import ReviewError, ReviewQueue, binding_hash, queue_approver
from interlock.shell import analyze
from interlock.sink import InMemorySink


@pytest.fixture
def queue(tmp_path):
    return ReviewQueue(str(tmp_path / "reviews.db"), pending_ttl=60, approval_ttl=30)


def request_for(cmd="npm publish", reason="publishing"):
    event = SensorEvent("run", {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate(reason, "publish"), "epoch1")


def file(queue, cmd="npm publish", now=1000.0):
    request = request_for(cmd)
    return queue.lookup_or_file(binding_hash(request), request, now=now), request


# --- the queue --------------------------------------------------------------------


def test_lifecycle_and_exactly_once_claim(queue):
    review, request = file(queue)
    assert review.status == "pending" and review.next == "wait"
    assert review.id.startswith("r-") and "npm publish" in review.preview
    again, _ = file(queue, now=1001.0)
    assert again.id == review.id  # the same request finds the same review
    approved = queue.approve(review.id, "alice", now=1002.0)
    assert approved.status == "approved" and approved.next == "retry_identical_call"
    assert approved.approval_until == 1032.0
    assert queue.claim(review.id, now=1003.0)
    assert not queue.claim(review.id, now=1003.0)
    assert queue.get(review.id).status == "executed"
    fresh, _ = file(queue, now=1004.0)
    assert fresh.id != review.id and fresh.status == "pending"


def test_a_different_call_files_its_own_review(queue):
    one, _ = file(queue, "npm publish")
    two, _ = file(queue, "npm publish --tag beta")
    assert one.id != two.id


def test_rejection_is_the_answer_for_the_identical_retry(queue):
    review, _ = file(queue)
    queue.reject(review.id, "not today", "alice", now=1001.0)
    again, _ = file(queue, now=1002.0)
    assert again.id == review.id and again.status == "rejected" and again.next == "stop"
    later, _ = file(queue, now=1001.0 + 61)  # after pending_ttl a new review may be filed
    assert later.id != review.id


def test_two_clocks(queue):
    review, _ = file(queue, now=1000.0)
    assert queue.get(review.id, now=1061.0).status == "expired"  # nobody decided in time
    review2, _ = file(queue, now=2000.0)
    queue.approve(review2.id, "alice", now=2010.0)
    assert not queue.claim(review2.id, now=2041.0)  # the approval was not used in time
    assert queue.get(review2.id, now=2041.0).status == "expired"


def test_quorum_and_self_approval(tmp_path):
    queue = ReviewQueue(str(tmp_path / "q.db"), min_approvals=2, allow_self_approval=False)
    review, _ = file(queue, now=time.time())
    with pytest.raises(ReviewError, match="may not approve"):
        queue.approve(review.id, review.requester)
    assert queue.approve(review.id, "alice").status == "pending"
    assert queue.approve(review.id, "alice").status == "pending"  # the same person twice
    done = queue.approve(review.id, "bob")
    assert done.status == "approved" and done.approvers == ["alice", "bob"]


def test_wrong_states(queue):
    review, _ = file(queue, now=time.time())
    queue.reject(review.id, "no")
    with pytest.raises(ReviewError):
        queue.approve(review.id, "alice")
    with pytest.raises(ReviewError):
        queue.get("r-missing")
    with pytest.raises(ReviewError):
        queue.list(status="weird")
    with pytest.raises(ValueError):
        ReviewQueue(str(queue.path) + "2", min_approvals=0)


def test_revoke_an_approval_before_it_is_used(queue):
    review, _ = file(queue, now=time.time())
    queue.approve(review.id, "alice")
    queue.revoke(review.id, "alice")
    assert not queue.claim(review.id)


def test_concurrent_claims_settle_once(queue):
    review, _ = file(queue, now=time.time())
    queue.approve(review.id, "alice")
    wins = []
    threads = [threading.Thread(target=lambda: wins.append(queue.claim(review.id)))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1


def test_binding_can_leave_out_an_unstable_epoch():
    a = request_for()
    event = SensorEvent("run", {"cmd": "npm publish"}, principal="agent")
    b = make_request(event, Decision.escalate("publishing", "publish"), "epoch2")
    assert binding_hash(a) != binding_hash(b)
    assert binding_hash(a, bind_epoch=False) == binding_hash(b, bind_epoch=False)


# --- the approver in-process ------------------------------------------------------


def escalate_publish(event):
    if event.action == "publish":
        return Decision.escalate("publishing needs a human", "publish")
    return None


def test_queue_approver_round_trip(queue):
    sink = InMemorySink()
    set_sink(sink)
    try:
        install(rules=[escalate_publish], approver=queue_approver(queue))
        calls = []

        @guard()
        def publish(pkg):
            calls.append(pkg)

        with pytest.raises(NotApproved) as info:
            publish("lib")
        assert "interlock reviews approve r-" in str(info.value)
        assert sink.receipts[-1].approval == "pending"
        review_id = queue.list("pending")[0].id
        queue.approve(review_id, "alice")
        publish("lib")
        assert calls == ["lib"]
        with pytest.raises(NotApproved):
            publish("lib")  # the approval was used up
    finally:
        set_sink(None)
        set_approver(None)


def test_queue_approver_can_wait(queue):
    install(rules=[escalate_publish], approver=queue_approver(queue, wait=5, poll=0.05))

    @guard()
    def publish(pkg):
        return "published " + pkg

    def approve_soon():
        for _ in range(100):
            pending = queue.list("pending")
            if pending:
                queue.approve(pending[0].id, "alice")
                return
            time.sleep(0.02)

    helper = threading.Thread(target=approve_soon)
    helper.start()
    try:
        assert publish("lib") == "published lib"
    finally:
        helper.join()
        set_approver(None)


# --- the coding-agent hooks ----------------------------------------------------------


def test_codex_escalation_goes_through_the_queue(queue, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    engine = load_policy({"extends": "builtin:coding-agent"})
    adapter = get_adapter("codex")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "npm publish"}, "session_id": "s", "cwd": "/w"}
    sink = InMemorySink()
    set_sink(sink)
    try:
        _, stderr, code = run_hook(adapter, payload, engine, reviews=queue)
        assert code == 2 and "interlock reviews approve r-" in stderr
        assert sink.receipts[-1].approval.startswith("pending:r-")
        review_id = queue.list("pending")[0].id
        queue.approve(review_id, "alice")
        engine2 = load_policy({"extends": "builtin:coding-agent"})  # a new hook process
        assert run_hook(adapter, payload, engine2, reviews=queue) == ("", "", 0)
        assert sink.receipts[-1].approval == "approved:review " + review_id
        _, _, code = run_hook(adapter, payload, engine2, reviews=queue)
        assert code == 2  # used once
    finally:
        set_sink(None)


def test_claude_keeps_its_native_prompt_unless_always(queue, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    engine = load_policy({"extends": "builtin:coding-agent"})
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "npm publish"}, "session_id": "s", "cwd": "/w"}
    stdout, _, _ = run_hook(get_adapter("claude-code"), payload, engine, reviews=queue)
    assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    stdout, _, _ = run_hook(get_adapter("claude-code"), payload, engine, reviews=queue,
                            review_mode="always")
    body = json.loads(stdout)["hookSpecificOutput"]
    assert body["permissionDecision"] == "deny" and "reviews approve r-" in body["permissionDecisionReason"]


def test_agents_cannot_approve_their_own_reviews():
    assert any(i.kind == "interlock.tamper" for i in analyze("interlock reviews approve r-1"))
    assert not any(i.kind == "interlock.tamper" for i in analyze("interlock reviews list"))


# --- the CLI and the MCP server -------------------------------------------------------


def test_cli(queue, capsys):
    review, _ = file(queue, now=time.time())
    db = ["reviews", "--db", queue.path]
    assert main(db + ["approve", review.id, "--as", "alice"]) == 0
    assert "APPROVED" in capsys.readouterr().out
    assert main(db + ["reject", review.id]) == 1
    assert main(db + ["--json", "show", review.id]) == 0
    assert json.loads(capsys.readouterr().out)["next"] == "retry_identical_call"
    assert main(db + ["--json", "list"]) == 0
    assert main(["reviews"]) == 64


def test_mcp_server(queue):
    from interlock.cli.reviews import serve_mcp  # noqa: F401  (import check)
    review, _ = file(queue, now=time.time())
    server = _server(queue)
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["serverInfo"]["name"] == "interlock-reviews"
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert {t["name"] for t in tools["result"]["tools"]} == {"review_status", "review_list", "review_wait"}
    call = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "review_status", "arguments": {"id": review.id}}})
    status = call["result"]["structuredContent"]
    assert status["next"] == "wait" and "Do not retry" in status["instruction"]
    assert "preview" not in status
    missing = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "review_status", "arguments": {"id": "r-x"}}})
    assert missing["result"]["isError"] is True
    assert server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})["error"]["code"] == -32601
    assert server.handle({"id": 6})["error"]["code"] == -32600


def _server(queue) -> StdioServer:
    """The same tools serve_mcp registers, without taking over stdio."""
    import io

    import interlock.cli.reviews as cli_reviews
    captured = {}
    original = StdioServer.serve

    def capture(self, stdin=None, stdout=None):
        captured["server"] = self
    StdioServer.serve = capture  # type: ignore[assignment]
    try:
        cli_reviews.serve_mcp(queue)
    finally:
        StdioServer.serve = original  # type: ignore[assignment]
    server = captured["server"]
    out = io.StringIO()
    server.serve(io.StringIO('{"jsonrpc":"2.0","id":9,"method":"ping"}\nnot json\n'), out)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert lines[0]["result"] == {} and lines[1]["error"]["code"] == -32700
    return server
