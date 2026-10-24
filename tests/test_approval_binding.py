"""An approval covers the call that will actually run (A07).

The approver must see and sign the post-rewrite effective arguments, a grant
must not travel between working directories, and the review database must keep
the approval policy it was filed under.
"""
import sqlite3
import time

import pytest

from interlock import Decision, Verdict, guard, install, set_approver
from interlock.adapters.base import Adapter, HookCall, call_events, run_hook
from interlock.approval import SESSION, Grant, GrantStore, make_request
from interlock.event import SensorEvent
from interlock.policy.engine import PolicyEngine
from interlock.receipt import digest_args, set_sink
from interlock.reviews import ReviewError, ReviewQueue, binding_hash
from interlock.sink import InMemorySink

#: The documented live-grant cap; spelled out here so this file also runs
#: against a tree that predates the symbol.
MAX_GRANTS = 1024


def rewrite_publish(event):
    if event.action == "publish":
        return Decision.modify({"command": "publish --live"}, "publish the live build", "rw")
    return None


def escalate_publish(event):
    if event.action == "publish":
        return Decision.escalate("confirm the publish", "ask")
    return None


def request_for(command="npm publish", *, cwd=None, epoch="epoch1"):
    event = SensorEvent("run", {"cmd": command}, principal="agent", cwd=cwd)
    return make_request(event, Decision.escalate("needs a human", "publish"), epoch)


# --- 1. the approver decides on the arguments that will run ----------------------


def test_the_approver_signs_the_rewritten_arguments():
    sink = InMemorySink()
    set_sink(sink)
    set_approver(None)
    seen = []

    def approver(request):
        seen.append(request)
        return True

    install(rules=[rewrite_publish, escalate_publish], approver=approver)
    ran = []

    @guard()
    def publish(command="publish --dry"):
        ran.append(command)
        return command

    try:
        assert publish() == "publish --live"
        assert ran == ["publish --live"]
        request = seen[0]
        assert request.event.args == {"command": "publish --live"}
        assert request.args_digest == digest_args({"command": "publish --live"})
        receipt = [r for r in sink.receipts if r.phase == "call"][-1]
        assert receipt.args_digest == digest_args({"command": "publish --live"})
        assert receipt.policy_verdict == "ESCALATE"
    finally:
        set_sink(None)
        set_approver(None)


def test_a_different_rewrite_is_a_different_binding():
    event = SensorEvent("publish", {"command": "publish --dry"}, principal="agent")
    live = Decision(Verdict.ESCALATE, "confirm", "ask",
                    modified_args={"command": "publish --live"})
    other = Decision(Verdict.ESCALATE, "confirm", "ask",
                     modified_args={"command": "publish --staging"})
    assert make_request(event, live, "e").binding != make_request(event, other, "e").binding
    assert make_request(event, live, "e").args_digest != \
        make_request(event, other, "e").args_digest


# --- 2. the review queue path runs the approved rewrite, or refuses -------------


class RecordingAdapter(Adapter):
    """A hook adapter that records the arguments it would run."""

    name = "recording"
    title = "Recording agent"

    def __init__(self, can_rewrite=True):
        self.can_rewrite = can_rewrite
        self.ran = []
        self.outcomes = []

    def parse(self, payload):
        tool_name = payload.get("tool_name", "publish")
        tool_input = dict(payload.get("tool_input") or {})
        session_id, cwd = payload.get("session_id"), payload.get("cwd")
        return HookCall(agent=self.name, kind="pre", event_name="PreToolUse",
                        tool_name=tool_name, tool_input=tool_input,
                        events=call_events(self.name, tool_name, tool_input,
                                           session_id=session_id, call_id="c1", cwd=cwd),
                        session_id=session_id, cwd=cwd, call_id="c1",
                        can_ask=True, can_rewrite=self.can_rewrite)

    def render(self, call, outcome):
        self.outcomes.append(outcome)
        if outcome.verdict == Verdict.MODIFY:
            merged = dict(call.tool_input)
            merged.update(outcome.modified_args or {})
            self.ran.append(merged)
        elif outcome.verdict == Verdict.ALLOW:
            self.ran.append(dict(call.tool_input))
        return "", "", 0

    def render_error(self, call, message, *, fail_open):
        return "", message, 2


PAYLOAD = {"tool_name": "publish", "tool_input": {"command": "publish --dry"},
           "session_id": "s1", "cwd": "/work"}


def test_review_approval_runs_the_rewrite_it_showed(tmp_path):
    engine = PolicyEngine([rewrite_publish, escalate_publish])
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    adapter = RecordingAdapter(can_rewrite=True)
    sink = InMemorySink()
    set_sink(sink)
    try:
        run_hook(adapter, PAYLOAD, engine, reviews=queue, review_mode="always")
        pending = queue.list("pending")
        assert len(pending) == 1
        assert "publish --live" in pending[0].preview
        assert "publish --dry" not in pending[0].preview

        queue.approve(pending[0].id, "alice")
        run_hook(adapter, PAYLOAD, engine, reviews=queue, review_mode="always")
        assert adapter.outcomes[-1].verdict == Verdict.MODIFY
        assert adapter.ran[-1] == {"command": "publish --live"}
        receipt = [r for r in sink.receipts if r.phase == "call"][-1]
        assert receipt.verdict == "MODIFY"
        assert receipt.args_digest == digest_args({"command": "publish --live"})
        assert receipt.approval == "approved:review " + pending[0].id
    finally:
        set_sink(None)


def test_review_approval_refuses_a_rewrite_the_adapter_cannot_apply(tmp_path):
    engine = PolicyEngine([rewrite_publish, escalate_publish])
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    adapter = RecordingAdapter(can_rewrite=False)
    sink = InMemorySink()
    set_sink(sink)
    try:
        run_hook(adapter, PAYLOAD, engine, reviews=queue, review_mode="always")
        pending = queue.list("pending")
        queue.approve(pending[0].id, "alice")
        run_hook(adapter, PAYLOAD, engine, reviews=queue, review_mode="always")
        assert adapter.outcomes[-1].verdict == Verdict.BLOCK
        assert "cannot apply a rewrite" in adapter.outcomes[-1].reason
        assert adapter.ran == []  # the original arguments never ran
    finally:
        set_sink(None)


# --- 3. the review database keeps the policy the review was filed under --------


def test_a_review_keeps_its_four_eyes_rule_across_reopen(tmp_path):
    path = str(tmp_path / "reviews.db")
    strict = ReviewQueue(path, allow_self_approval=False)
    request = request_for()
    review = strict.lookup_or_file(binding_hash(request), request)
    reopened = ReviewQueue(path)  # constructor defaults would allow self-approval
    with pytest.raises(ReviewError, match="may not approve"):
        reopened.approve(review.id, review.requester)


def test_a_review_keeps_its_approval_ttl_across_reopen(tmp_path):
    path = str(tmp_path / "reviews.db")
    short = ReviewQueue(path, approval_ttl=1)
    request = request_for()
    review = short.lookup_or_file(binding_hash(request), request, now=time.time())
    reopened = ReviewQueue(path)  # default TTL is longer, but cannot loosen the row
    began = time.time()
    approved = reopened.approve(review.id, "alice", now=began)
    assert approved.approval_until == began + 1
    assert not reopened.claim(review.id, now=began + 2)


# --- 4. a grant binds the working directory ------------------------------------


def test_a_session_grant_does_not_travel_between_directories():
    store = GrantStore()

    def bound(cwd):
        return make_request(
            SensorEvent("deploy", {"env": "prod"}, principal="agent", span_id="sp", cwd=cwd),
            Decision.escalate("deploy?", "deploy"), "e")

    at_a, at_b = bound("/a"), bound("/b")
    assert at_a.binding != at_b.binding
    store.add(Grant("g", at_a.binding, SESSION, at_a.action, at_a.principal, "sp", time.time()))
    assert store.match(at_a) is not None
    assert store.match(at_b) is None


# --- 5. expired grants are pruned, and the store is bounded --------------------


def test_grants_are_pruned_and_capped():
    store = GrantStore()
    start = time.time()
    for i in range(2000):
        store.add(Grant("g%d" % i, ("deploy", "call", "d", None, None, None, None, None),
                        "ttl", "deploy", None, None, start, expires=start + 60))
    assert len(store.active()) <= MAX_GRANTS
    store.prune(now=start + 61)
    assert store.active() == []


# --- 6. an old database keeps working ------------------------------------------


OLD_SCHEMA = """
CREATE TABLE reviews (
    id TEXT PRIMARY KEY,
    binding TEXT NOT NULL,
    status TEXT NOT NULL,
    action TEXT NOT NULL,
    phase TEXT NOT NULL,
    principal TEXT,
    requester TEXT,
    policy_id TEXT,
    reason TEXT,
    args_digest TEXT,
    preview TEXT,
    created REAL NOT NULL,
    pending_until REAL NOT NULL,
    decided REAL,
    approval_until REAL,
    executed REAL,
    decided_by TEXT,
    rejection_reason TEXT,
    min_approvals INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX reviews_binding ON reviews (binding, status);
CREATE TABLE approvals (
    review_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY (review_id, approver)
);
"""


def test_an_old_schema_database_opens_and_approves(tmp_path):
    path = str(tmp_path / "old.db")
    now = time.time()
    db = sqlite3.connect(path)
    try:
        db.executescript(OLD_SCHEMA)
        db.execute(
            "INSERT INTO reviews (id, binding, status, action, phase, principal, requester, "
            "policy_id, reason, args_digest, preview, created, pending_until, min_approvals) "
            "VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("r-old", "binding", "publish", "call", "agent", "requester", "ask",
             "filed by an older release", "digest", "{}", now, now + 3600, 1))
        db.commit()
    finally:
        db.close()

    queue = ReviewQueue(path)  # migrates in place
    assert [review.id for review in queue.list()] == ["r-old"]
    approved = queue.approve("r-old", "bob", now=now + 1)
    assert approved.status == "approved"
    assert approved.reason == "filed by an older release"
    assert approved.allow_self_approval is True
    assert approved.approval_ttl == 900.0

    db = sqlite3.connect(path)
    try:
        columns = {row[1] for row in db.execute("PRAGMA table_info(reviews)")}
        assert {"allow_self_approval", "approval_ttl"} <= columns
    finally:
        db.close()
