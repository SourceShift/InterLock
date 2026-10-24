"""A sidecar refusal is not a sidecar outage (A08).

``RemoteEngine`` decides whether a failed call follows ``unreachable`` by
classifying the exception. Only an absent, refused, timed-out, or hung-up
daemon is an outage. A request the daemon *refuses* - oversized, unencodable,
undecodable, or one whose receipt cannot be written - must block under every
``unreachable`` level, including ``allow``.

The checks here are the ones that classification rests on:

- an oversized request is refused before a socket is opened, so the daemon's
  closing race can never be mistaken for an outage;
- a deeply nested argument that blows the encoder's stack is refused the same
  way;
- a raw undecodable or over-deep frame gets an error frame and the connection
  keeps serving (a dead connection would look like an outage);
- a receipt sink that raises is answered ``receipt_failed``, no decision is
  sent, and the handler survives to serve the next frame;
- a genuine outage still follows the configured level.
"""
from __future__ import annotations

import socket

import pytest

from interlock import Blocked, Verdict
from interlock.event import SensorEvent
from interlock.policy.engine import PolicyEngine
from interlock.receipt import set_sink
from interlock.sidecar import client as client_mod
from interlock.sidecar.client import UNREACHABLE_POLICY_ID, RemoteEngine
from interlock.sink import InMemorySink
from interlock.testing.harness import serve
from interlock.wire import MAX_LINE, PROTOCOL_VERSION, canonical, decode_line


def _event(action="ping", **args):
    return SensorEvent(action=action, args=args)


def _ping_line(op_id="t-1"):
    frame = {"v": PROTOCOL_VERSION, "id": op_id, "event": {"action": "ping", "args": {}}}
    return (canonical(frame) + "\n").encode("utf-8")


def _nested_list(depth=10000):
    """A list nested deeper than the interpreter's recursion limit."""
    root = value = []
    for _ in range(depth):
        nxt = []
        value.append(nxt)
        value = nxt
    return root


def _exchange(sock, reader, line):
    if isinstance(line, str):
        line = line.encode("utf-8")
    if not line.endswith(b"\n"):
        line += b"\n"
    sock.sendall(line)
    raw = reader.readline(MAX_LINE + 1)
    assert raw, "the daemon closed the connection instead of answering"
    return decode_line(raw)


def _frames_on_one_connection(path, *lines):
    """Send each line on one connection and return one decoded reply each."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect(str(path))
        reader = sock.makefile("rb")
        try:
            return [_exchange(sock, reader, line) for line in lines]
        finally:
            reader.close()
    finally:
        sock.close()


class _RaisingSink:
    """A sink whose every write fails, like a full disk."""

    def __init__(self):
        self.attempts = 0

    def write(self, receipt):
        self.attempts += 1
        raise OSError("no space left on device")


# --- refused locally, before the socket --------------------------------------


def test_an_oversized_request_blocks_locally_under_allow(sock_path):
    # Nothing listens at this path. If the client opened a socket at all, the
    # connect would fail with OSError and unreachable='allow' would let the call
    # through. The request must be refused before that connect, and the reason
    # must name the refusal rather than an outage.
    engine = RemoteEngine(sock_path("absent.sock"), unreachable="allow")
    with pytest.raises(Blocked) as excinfo:
        engine.evaluate(_event("huge", text="x" * (MAX_LINE + 1024)))
    reason = excinfo.value.decision.reason
    assert "too_large" in reason
    assert "unreachable" not in reason
    assert engine.fallbacks == 0


def test_a_deeply_nested_request_blocks_locally_under_allow(sock_path):
    engine = RemoteEngine(sock_path("absent.sock"), unreachable="allow")
    with pytest.raises(Blocked) as excinfo:
        engine.evaluate(_event("deep", tree=_nested_list()))
    reason = excinfo.value.decision.reason
    assert "bad_request" in reason
    assert "unreachable" not in reason
    assert engine.fallbacks == 0


@pytest.mark.parametrize("level", ["deny", "degraded", "allow"])
def test_a_local_refusal_blocks_under_every_unreachable_level(
    sock_path, monkeypatch, level
):
    # The frame bound is patched down so this does not allocate 8 MiB per
    # level; the classification is the same at any bound. 'degraded' carries a
    # key so that a genuine outage would have taken the fallback path instead -
    # a refusal must not reach it.
    monkeypatch.setattr(client_mod, "MAX_LINE", 256)
    kwargs = {"fallback_key": b"k" * 32} if level == "degraded" else {}
    engine = RemoteEngine(sock_path("absent.sock"), unreachable=level, **kwargs)
    with pytest.raises(Blocked) as excinfo:
        engine.evaluate(_event("huge", text="x" * 300))
    assert "too_large" in excinfo.value.decision.reason
    assert engine.fallbacks == 0


# --- the daemon answers a bad frame and keeps serving ------------------------


def test_an_over_deep_frame_is_answered_and_the_connection_keeps_serving(sock_path):
    path = sock_path()
    deep = '{"v":1,"id":"deep","event":' + "[" * 10000 + "]" * 10000 + "}"
    with serve(PolicyEngine(rules=[]), path):
        first, second = _frames_on_one_connection(path, deep, _ping_line("t-2"))
    assert first["error"]["code"] == "internal"
    assert second["verdict"] == 0


def test_a_malformed_frame_is_answered_and_the_connection_keeps_serving(sock_path):
    path = sock_path()
    with serve(PolicyEngine(rules=[]), path):
        first, second = _frames_on_one_connection(path, "not json", _ping_line("t-2"))
    assert first["error"]["code"] == "bad_request"
    assert second["verdict"] == 0


# --- a receipt that cannot be written is a refusal ---------------------------


def test_a_failed_receipt_write_blocks_under_allow(sock_path):
    path = sock_path()
    sink = _RaisingSink()
    with serve(PolicyEngine(rules=[]), path, sink=sink):
        engine = RemoteEngine(path, unreachable="allow")
        try:
            with pytest.raises(Blocked) as excinfo:
                engine.evaluate(_event("ping"))
        finally:
            engine.close()
    assert "receipt_failed" in excinfo.value.decision.reason
    # The write was attempted once and is not retried before the reply.
    assert sink.attempts == 1


def test_the_handler_survives_a_failed_receipt_and_serves_the_next_frame(sock_path):
    path = sock_path()
    sink = _RaisingSink()
    with serve(PolicyEngine(rules=[]), path, sink=sink):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5.0)
        try:
            client.connect(path)
            reader = client.makefile("rb")
            try:
                first = _exchange(client, reader, _ping_line("t-1"))
                assert first["error"]["code"] == "receipt_failed"
                assert sink.attempts == 1
                # No decision frame followed the error - the next line read is
                # an answer to the next request, on the same connection.
                set_sink(InMemorySink())
                second = _exchange(client, reader, _ping_line("t-2"))
                assert second["verdict"] == 0
            finally:
                reader.close()
        finally:
            client.close()


# --- a genuine outage keeps today's behaviour --------------------------------


def test_a_genuine_outage_still_follows_the_configured_level(sock_path):
    engine = RemoteEngine(sock_path("absent.sock"), unreachable="allow")
    decision = engine.evaluate(_event("ping"))
    assert decision.verdict is Verdict.ALLOW
    assert decision.policy_id == UNREACHABLE_POLICY_ID
    assert engine.fallbacks == 1
