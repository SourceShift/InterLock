"""The daemon over a real unix socket, in a temporary directory.

The checks here are the ones the design's claims rest on, each named for the
claim it proves:

- one receipt chain survives concurrent requests (why the server is threaded
  rather than forking),
- an empty rule set is refused rather than served (the guard that would
  otherwise report success while enforcing nothing),
- the socket is owner-only, and a directory another user could rebind in is
  refused,
- an unreachable daemon blocks (fail-closed, with no hatch),
- a receipt chain carried by an injected key verifies under that key and fails
  under another.

``serve`` hosts the daemon in-process and restores the process-global sink on
the way out, so these tests do not leak a sink into the next one.
"""
from __future__ import annotations

import os
import socket
import stat
import threading

import pytest

import interlock
from interlock import Blocked, guard
from interlock.event import SensorEvent
from interlock.policy.engine import PolicyEngine
from interlock.receipt import Receipt
from interlock.sidecar import server as server_mod
from interlock.sidecar.client import RemoteEngine
from interlock.sidecar.rules import EmptyRules, RulesError, load_rules
from interlock.sidecar.server import SidecarServer, peer_uid
from interlock.sidecar.__main__ import (
    EXIT_ALREADY_RUNNING,
    EXIT_BAD_RULES,
    _prepare_socket,
    main,
)
from interlock.sink import FileSink, InMemorySink
from interlock.testing.fixtures import CONFORMANCE_ENGINE, CONFORMANCE_SPEC
from interlock.testing.harness import send_raw, serve
from interlock.wire import PROTOCOL_VERSION, canonical


def _send(path, action, args=None, **event_fields):
    event = {"action": action, "args": {} if args is None else args}
    event.update(event_fields)
    return send_raw(
        path,
        canonical({"v": PROTOCOL_VERSION, "id": "t-1", "event": event}),
    )


def _receipt(action):
    return Receipt(ts=0.0, action=action, verdict="ALLOW")


# --- decisions over the wire -------------------------------------------------


def test_an_unopinionated_action_comes_back_allow(sock_path):
    path = sock_path()
    sink = InMemorySink()
    with serve(CONFORMANCE_ENGINE, path, sink=sink):
        reply = _send(path, "ping")
    assert reply["verdict"] == 0
    assert reply["reason"] == ""
    assert len(sink.receipts) == 1


def test_a_block_survives_and_never_names_the_value(sock_path):
    path = sock_path()
    sink = InMemorySink()
    with serve(CONFORMANCE_ENGINE, path, sink=sink):
        reply = _send(path, "read_file", {"path": "/etc/passwd"})
    assert reply["verdict"] == 1
    assert reply["reason"] == "etc is off limits"
    assert reply["policy_id"] == "p.no-etc"
    assert reply["attributed_to"] == "path"
    # The data-exfil guard: the reason names the argument, never its value, so
    # no field of the decision or the durable receipt carries the value.
    assert "/etc/passwd" not in canonical(reply)
    assert "/etc/passwd" not in sink.receipts[0].to_json()


def test_a_modify_carries_the_rewrite(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = _send(path, "write_file", {"path": "/etc/hosts"})
    assert reply["verdict"] == 2
    assert reply["modified_args"] == {"path": "/tmp/quarantine"}
    assert reply["attributed_to"] == "path"


def test_a_result_phase_event_reaches_a_result_rule(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = _send(
            path, "fetch_url", {"result": "token secret"}, phase="result"
        )
    assert reply["verdict"] == 2
    assert reply["modified_result"] == "redacted"
    assert reply["attributed_to"] == "result"


# --- the one chain -----------------------------------------------------------


def test_one_receipt_chain_under_concurrent_requests(sock_path):
    """The check that justifies threads over forking.

    ``ChainedSink`` serializes read-prev / sign / append only *within* a
    process; a forking server would start a new chain at GENESIS per child and
    shatter the chain. Threads sharing one sink keep it intact, so verify()
    must return None after many interleaved requests.
    """
    path = sock_path()
    sink = InMemorySink()
    threads, per_thread = 8, 25
    errors = []

    def worker(n):
        try:
            for i in range(per_thread):
                send_raw(
                    path,
                    canonical(
                        {
                            "v": PROTOCOL_VERSION,
                            "id": "{}-{}".format(n, i),
                            "event": {"action": "ping", "args": {}},
                        }
                    ),
                )
        except Exception as exc:  # reported after join, not swallowed
            errors.append(exc)

    with serve(CONFORMANCE_ENGINE, path, sink=sink):
        workers = [
            threading.Thread(target=worker, args=(n,)) for n in range(threads)
        ]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()

    assert errors == []
    assert len(sink.receipts) == threads * per_thread
    assert sink.verify() is None


# --- the socket boundary -----------------------------------------------------


def test_the_socket_is_owner_only(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_a_world_writable_socket_directory_is_refused(socket_dir):
    # In a directory anyone can write, anyone can unlink the socket and bind
    # their own in its place. The sticky bit is what makes sharing safe.
    shared = os.path.join(socket_dir, "shared")
    os.mkdir(shared)
    os.chmod(shared, 0o777)
    path = os.path.join(shared, "g.sock")
    with pytest.raises(OSError):
        SidecarServer(path, CONFORMANCE_ENGINE)
    assert not os.path.exists(path)


def test_a_sticky_shared_directory_is_accepted(socket_dir):
    shared = os.path.join(socket_dir, "shared")
    os.mkdir(shared)
    os.chmod(shared, 0o1777)
    path = os.path.join(shared, "g.sock")
    server = SidecarServer(path, CONFORMANCE_ENGINE)
    try:
        assert os.path.exists(path)
    finally:
        server.server_close()
        os.unlink(path)


def test_peer_uid_reads_the_kernel_where_available():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        uid = peer_uid(right)
    finally:
        left.close()
        right.close()
    # Best-effort by contract: the file mode is the real boundary, so None
    # ("could not ask") is acceptable; a number, if returned, must be ours.
    assert uid is None or uid == os.getuid()


def test_a_connection_from_another_uid_is_refused(sock_path, monkeypatch):
    path = sock_path()
    monkeypatch.setattr(server_mod, "peer_uid", lambda conn: os.getuid() + 1)
    with serve(CONFORMANCE_ENGINE, path):
        reply = _send(path, "ping")
    assert reply == {}  # dropped before any frame was answered


def test_an_oversized_frame_is_refused(sock_path, monkeypatch):
    # The size check runs before parsing, so the frame is never parsed. The
    # limit is patched down so the test does not ship 8 MiB through a socket.
    monkeypatch.setattr(server_mod, "MAX_LINE", 256)
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = send_raw(path, "x" * 300)
    assert reply["error"]["code"] == "too_large"


def test_a_raising_rule_is_denied_fail_closed(sock_path):
    def boom(event):
        raise RuntimeError("the value was /etc/passwd")

    engine = PolicyEngine(rules=[boom])
    path = sock_path()
    sink = InMemorySink()
    with serve(engine, path, sink=sink):
        reply = _send(path, "ping")
    assert reply["verdict"] == 1
    assert "rule error" in reply["reason"]
    # The exception *type* is durable; its message (which can quote an
    # argument) is not, because the reason lands in a receipt.
    assert "RuntimeError" in reply["reason"]
    assert "/etc/passwd" not in reply["reason"]
    assert "/etc/passwd" not in sink.receipts[0].to_json()


# --- fail-closed -------------------------------------------------------------


def test_a_remote_engine_without_a_daemon_blocks(sock_path):
    remote = RemoteEngine(sock_path("absent.sock"))
    with pytest.raises(Blocked) as excinfo:
        remote.evaluate(SensorEvent(action="ping"))
    assert "unreachable" in excinfo.value.decision.reason


def test_a_guard_routed_through_the_remote_engine_blocks(sock_path):
    path = sock_path()
    remote = RemoteEngine(path)
    with serve(CONFORMANCE_ENGINE, path):
        interlock.set_engine(remote)

        @guard()
        def read_file(path):
            return "contents"

        @guard()
        def ping():
            return "pong"

        with pytest.raises(Blocked) as excinfo:
            read_file(path="/etc/passwd")
        assert excinfo.value.decision.policy_id == "p.no-etc"
        assert excinfo.value.decision.attributed_to == "path"
        # An action the engine has no opinion on still runs: routing through
        # the daemon does not turn "no opinion" into "deny".
        assert ping() == "pong"


# --- rules resolution --------------------------------------------------------


@pytest.fixture
def rules_module(tmp_path, monkeypatch):
    (tmp_path / "sidecar_rules_fixture.py").write_text(
        "from interlock.policy.engine import PolicyEngine, deny_tool\n"
        "ENGINE = PolicyEngine(rules=[deny_tool('x')])\n"
        "RULES = [deny_tool('x')]\n"
        "EMPTY_ENGINE = PolicyEngine()\n"
        "EMPTY_LIST = []\n"
        "NOT_RULES = 'a string'\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    return "sidecar_rules_fixture"


def test_the_fixture_engine_loads():
    assert len(load_rules(CONFORMANCE_SPEC)) > 0


def test_load_rules_accepts_an_engine(rules_module):
    assert len(load_rules(rules_module + ":ENGINE")) == 1


def test_load_rules_accepts_a_plain_list(rules_module):
    assert len(load_rules(rules_module + ":RULES")) == 1


def test_an_empty_engine_is_refused(rules_module):
    with pytest.raises(EmptyRules):
        load_rules(rules_module + ":EMPTY_ENGINE")
    with pytest.raises(EmptyRules):
        load_rules(rules_module + ":EMPTY_LIST")


def test_a_malformed_spec_is_refused():
    with pytest.raises(RulesError):
        load_rules("no_colon_here")


def test_a_missing_module_is_refused():
    with pytest.raises(RulesError):
        load_rules("no_such_module_xyz:ENGINE")


def test_a_wrong_shaped_attribute_is_refused(rules_module):
    with pytest.raises(RulesError):
        load_rules(rules_module + ":NOT_RULES")


def test_main_check_reports_exit_codes(rules_module):
    assert main(["--rules", CONFORMANCE_SPEC, "--check"]) == 0
    assert (
        main(["--rules", rules_module + ":EMPTY_ENGINE", "--check"])
        == EXIT_BAD_RULES
    )
    assert main(["--rules", "malformed", "--check"]) == EXIT_BAD_RULES


def test_prepare_socket_clears_a_stale_file(socket_dir):
    path = os.path.join(socket_dir, "g.sock")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("stale socket file")
    _prepare_socket(path)
    assert not os.path.exists(path)
    assert stat.S_IMODE(os.stat(socket_dir).st_mode) == 0o700


def test_prepare_socket_refuses_when_a_daemon_is_live(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        with pytest.raises(SystemExit) as excinfo:
            _prepare_socket(path)
    assert excinfo.value.code == EXIT_ALREADY_RUNNING


# --- receipts ----------------------------------------------------------------


def test_receipts_verify_under_the_injected_key(socket_dir, sock_path):
    path = sock_path()
    receipts = os.path.join(socket_dir, "receipts.ndjson")
    key = bytes.fromhex("ab" * 32)
    other = bytes.fromhex("cd" * 32)
    with serve(CONFORMANCE_ENGINE, path, sink=FileSink(receipts, key=key)):
        _send(path, "ping")
        _send(path, "read_file", {"path": "/etc/passwd"})
    assert FileSink(receipts, key=key).verify() is None
    # The wrong-key failure mode proves the key is load-bearing, not decorative.
    assert "MAC mismatch" in FileSink(receipts).verify(key=other)


def test_a_second_writer_starts_a_new_chain(socket_dir):
    """The limitation the daemon design is built around, asserted rather than
    assumed: one sink instance, one process, one chain. A second writer begins
    at GENESIS, so verify() names the junction - which is why the daemon must
    stay a single process rather than fork per connection."""
    receipts = os.path.join(socket_dir, "receipts.ndjson")
    key = b"k" * 32
    FileSink(receipts, key=key).write(_receipt("first"))
    FileSink(receipts, key=key).write(_receipt("second"))
    report = FileSink(receipts).verify(key=key)
    assert report is not None
    assert "chain break" in report
