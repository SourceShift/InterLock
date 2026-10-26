"""One-way notification when a review is filed (Slack or a JSON webhook).

The notifier is allowed to be unreliable; the decision is not. Every test that
breaks the receiver asserts the review was still filed.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import pytest

from interlock import Decision
from interlock.adapters import get_adapter, run_hook
from interlock.approval import make_request
from interlock.event import SensorEvent
from interlock.notify import (
    ENV_CONSOLE,
    ENV_FORMAT,
    ENV_WEBHOOK,
    ReviewNotifier,
    from_env,
    message_for,
    payload_for,
    post,
)
from interlock.policy.declarative import load_policy
from interlock.receipt import set_sink
from interlock.reviews import ReviewQueue, binding_hash
from interlock.sink import InMemorySink


class Receiver:
    """A local HTTP endpoint that records the JSON bodies it receives."""

    def __init__(self, status: int = 200, location: Optional[str] = None,
                 delay: float = 0.0) -> None:
        receiver = self
        self.bodies: List[Dict[str, Any]] = []
        self.status = status
        self.location = location
        self.delay = delay

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server naming
                length = int(self.headers.get("Content-Length") or 0)
                receiver.bodies.append(json.loads(self.rfile.read(length) or b"{}"))
                if receiver.delay:
                    time.sleep(receiver.delay)
                self.send_response(receiver.status)
                if receiver.location:
                    self.send_header("Location", receiver.location)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: Any) -> None:
                del format, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:{}/hook".format(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture
def receiver():
    endpoint = Receiver()
    try:
        yield endpoint
    finally:
        endpoint.close()


def request_for(cmd: str = "npm publish", reason: str = "publishing",
                args: Optional[Dict[str, Any]] = None):
    event = SensorEvent("run", args if args is not None else {"cmd": cmd}, principal="agent")
    return make_request(event, Decision.escalate(reason, "publish"), "epoch1")


def file_review(queue: ReviewQueue, request=None, now: float = 1000.0):
    request = request or request_for()
    return queue.lookup_or_file(binding_hash(request), request, now=now)


def queue_with(tmp_path, notifier) -> ReviewQueue:
    return ReviewQueue(str(tmp_path / "reviews.db"), pending_ttl=60, approval_ttl=30,
                       on_file=notifier)


# --- filing posts once ---------------------------------------------------------------


def test_a_filed_review_posts_one_slack_message(tmp_path, receiver):
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url))
    review = file_review(queue)
    deadline = time.time() + 5
    while not receiver.bodies and time.time() < deadline:
        time.sleep(0.01)
    assert len(receiver.bodies) == 1
    text = receiver.bodies[0]["text"]
    assert review.id in text and "npm publish" in text
    assert "#/reviews/" + review.id in text
    assert "expires " in text


def test_reusing_or_rejecting_a_review_posts_once(tmp_path, receiver):
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url))
    first = file_review(queue)
    file_review(queue, now=1001.0)              # pending: reused, no new message
    queue.reject(first.id, "wrong table", "alice", now=1002.0)
    again = file_review(queue, now=1003.0)      # the rejection is the answer
    assert again.status == "rejected"
    assert len(receiver.bodies) == 1


def test_the_message_never_carries_the_arguments(tmp_path, receiver):
    secret = "must-not-leave-the-machine"
    request = request_for(args={"cmd": "npm publish", "token": secret})
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url))
    file_review(queue, request)
    assert secret not in json.dumps(receiver.bodies)


def test_free_text_is_masked_before_it_leaves(tmp_path, receiver):
    # A low-entropy stand-in for a bearer token: the redactor matches the shape.
    request = request_for(reason="forwarding with Authorization: Bearer abcdefghijklmnop")
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url))
    file_review(queue, request)
    body = json.dumps(receiver.bodies)
    assert "abcdefghijklmnop" not in body
    assert "REDACTED" in body


def test_json_format_carries_structured_fields(tmp_path, receiver):
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url, fmt="json"))
    review = file_review(queue)
    body = receiver.bodies[0]
    assert body["event"] == "interlock.review.filed"
    assert body["review_id"] == review.id and body["action"] == "run"
    assert body["target"] == "npm publish"
    assert body["principal"] == "agent" and body["rule"] == "publish"
    assert body["console_url"].endswith("#/reviews/" + review.id)
    assert body["pending_until"].endswith(("+00:00", "Z"))


def test_min_approvals_is_named_in_the_message():
    review = type("R", (), {"id": "r-1", "action": "a", "principal": "p", "policy_id": "x",
                            "reason": "r", "pending_until": 0.0, "min_approvals": 2})()
    text = payload_for(message_for(review), "slack")["text"]
    assert "2 distinct approvers" in text


# --- a broken receiver never blocks or fails a filing --------------------------------


def test_a_500_still_files_the_review(tmp_path):
    endpoint = Receiver(status=500)
    try:
        queue = queue_with(tmp_path, ReviewNotifier(endpoint.url))
        review = file_review(queue, now=time.time())
        assert review.status == "pending"
        assert queue.get(review.id).status == "pending"
    finally:
        endpoint.close()


def test_a_refused_connection_still_files_the_review(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()                                 # nothing listens there now
    queue = queue_with(tmp_path, ReviewNotifier("http://127.0.0.1:{}/hook".format(port)))
    assert file_review(queue).status == "pending"


def test_a_timeout_still_files_the_review(tmp_path):
    endpoint = Receiver(delay=0.5)
    try:
        notifier = ReviewNotifier(endpoint.url, timeout=0.05)
        queue = queue_with(tmp_path, notifier)
        started = time.time()
        assert file_review(queue).status == "pending"
        assert time.time() - started < 0.45        # the hook did not wait for the receiver
    finally:
        endpoint.close()


def test_a_redirect_is_refused_not_followed(tmp_path):
    target = Receiver()
    redirector = Receiver(status=302, location=target.url)
    try:
        assert post(redirector.url, {"text": "x"}) is False
        assert target.bodies == []
    finally:
        redirector.close()
        target.close()


def test_a_notifier_that_raises_does_not_change_the_filing(tmp_path):
    def broken(review):
        raise RuntimeError("boom")

    queue = queue_with(tmp_path, broken)
    assert file_review(queue, now=time.time()).status == "pending"
    assert len(queue.list("pending")) == 1


# --- configuration --------------------------------------------------------------------


def test_no_webhook_means_no_notifier():
    assert from_env({}) is None


def test_environment_builds_the_notifier():
    notifier = from_env({ENV_WEBHOOK: "https://example.invalid/hook",
                         ENV_FORMAT: "json", ENV_CONSOLE: "http://127.0.0.1:9000"})
    assert notifier is not None and notifier.fmt == "json"
    assert notifier.console_url == "http://127.0.0.1:9000"


def test_a_bad_setting_warns_and_disables_rather_than_failing():
    assert from_env({ENV_WEBHOOK: "file:///tmp/hook"}) is None
    assert from_env({ENV_WEBHOOK: "https://example.invalid/hook", ENV_FORMAT: "xml"}) is None


def test_construction_rejects_a_non_http_url():
    with pytest.raises(ValueError):
        ReviewNotifier("file:///tmp/hook")
    with pytest.raises(ValueError):
        ReviewNotifier("https://example.invalid/hook", fmt="xml")
    with pytest.raises(ValueError):
        ReviewNotifier("https://example.invalid/hook", timeout=0)


# --- the real hook path ---------------------------------------------------------------


def test_the_codex_hook_notifies_when_it_files(tmp_path, monkeypatch, receiver):
    monkeypatch.setenv("HOME", str(tmp_path))
    engine = load_policy({"extends": "builtin:coding-agent"})
    queue = queue_with(tmp_path, ReviewNotifier(receiver.url))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "npm publish"}, "session_id": "s", "cwd": "/w"}
    sink = InMemorySink()
    set_sink(sink)
    try:
        _, stderr, code = run_hook(get_adapter("codex"), payload, engine, reviews=queue)
        assert code == 2 and "interlock reviews approve r-" in stderr
    finally:
        set_sink(None)
    deadline = time.time() + 5
    while not receiver.bodies and time.time() < deadline:
        time.sleep(0.01)
    assert len(receiver.bodies) == 1
    assert "npm publish" in receiver.bodies[0]["text"]
