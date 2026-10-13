"""Sidecar hardening: socket-directory handling, key-file errors, closing live
connections on shutdown, and client timeouts.

Each test pins one refusal or bound that used to be missing:

- the daemon never changes the mode of a shared directory like ``/tmp`` (as a
  normal user that failed; as root it would have locked ``/tmp`` down), and
  refuses a directory another user owns;
- a missing ``--key-file`` is a one-line configuration error, not a traceback;
- ``serve()`` ends connections that were open when its block exited;
- ``RemoteEngine`` has a finite default timeout, so a hung daemon blocks a call
  instead of hanging it.
"""
from __future__ import annotations

import os
import socket
import stat
import time

import pytest

from interlock import Blocked
from interlock.event import SensorEvent
from interlock.sidecar import __main__ as cli
from interlock.sidecar.__main__ import (
    EXIT_BAD_RULES,
    UnsafeSocketDir,
    _prepare_socket,
    main,
)
from interlock.sidecar.client import DEFAULT_TIMEOUT, RemoteEngine
from interlock.testing.fixtures import CONFORMANCE_ENGINE, CONFORMANCE_SPEC
from interlock.testing.harness import serve
from interlock.wire import PROTOCOL_VERSION, canonical


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _ping_frame(op_id="t-1"):
    frame = {"v": PROTOCOL_VERSION, "id": op_id, "event": {"action": "ping", "args": {}}}
    return (canonical(frame) + "\n").encode("utf-8")


# --- socket directory ---------------------------------------------------------


def test_a_missing_socket_directory_is_created_private(socket_dir):
    directory = os.path.join(socket_dir, "new", "nested")
    _prepare_socket(os.path.join(directory, "g.sock"))
    assert os.path.isdir(directory)
    assert _mode(directory) == 0o700


def test_an_owned_directory_is_tightened_to_0700(socket_dir):
    directory = os.path.join(socket_dir, "mine")
    os.mkdir(directory)
    os.chmod(directory, 0o755)
    _prepare_socket(os.path.join(directory, "g.sock"))
    assert _mode(directory) == 0o700


@pytest.mark.parametrize("shared_mode", [0o1777, 0o777, 0o1755])
def test_a_shared_directory_is_refused_and_left_unchanged(socket_dir, shared_mode):
    # World-writable or sticky: a directory meant for many users. The daemon
    # must neither use it nor change its mode.
    directory = os.path.join(socket_dir, "shared")
    os.mkdir(directory)
    os.chmod(directory, shared_mode)
    with pytest.raises(UnsafeSocketDir) as excinfo:
        _prepare_socket(os.path.join(directory, "g.sock"))
    assert _mode(directory) == shared_mode
    message = str(excinfo.value)
    assert "shared" in message
    assert "-interlock/guard.sock" in message  # suggests a private directory


def test_the_real_tmp_is_refused_and_left_unchanged():
    if not os.path.isdir("/tmp"):
        pytest.skip("no /tmp on this host")
    before = _mode("/tmp")
    if not (before & 0o002 or before & stat.S_ISVTX):
        pytest.skip("/tmp is not a shared directory on this host")
    with pytest.raises(UnsafeSocketDir):
        _prepare_socket("/tmp/interlock-hardening-test.sock")
    assert _mode("/tmp") == before


def test_a_directory_owned_by_another_user_is_refused(socket_dir, monkeypatch):
    directory = os.path.join(socket_dir, "theirs")
    os.mkdir(directory)
    os.chmod(directory, 0o755)
    owner = os.stat(directory).st_uid
    monkeypatch.setattr(cli.os, "getuid", lambda: owner + 1)
    with pytest.raises(UnsafeSocketDir) as excinfo:
        _prepare_socket(os.path.join(directory, "g.sock"))
    assert "owned by uid" in str(excinfo.value)
    assert _mode(directory) == 0o755


def test_main_exits_2_on_a_shared_socket_directory(socket_dir, capsys):
    directory = os.path.join(socket_dir, "shared")
    os.mkdir(directory)
    os.chmod(directory, 0o1777)
    path = os.path.join(directory, "g.sock")
    assert main(["--rules", CONFORMANCE_SPEC, "--socket", path]) == EXIT_BAD_RULES
    err = capsys.readouterr().err
    assert err.startswith("interlock-sidecar: socket directory")
    assert "Traceback" not in err
    assert not os.path.exists(path)


# --- key file -----------------------------------------------------------------


def test_a_missing_key_file_exits_2_with_one_line(socket_dir, capsys):
    path = os.path.join(socket_dir, "g.sock")
    code = main([
        "--rules", CONFORMANCE_SPEC,
        "--socket", path,
        "--receipts", os.path.join(socket_dir, "receipts.ndjson"),
        "--key-file", os.path.join(socket_dir, "no-such-key"),
    ])
    assert code == EXIT_BAD_RULES
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "cannot read key file" in err
    assert "Traceback" not in err
    assert not os.path.exists(path)  # refused before the socket was touched


def test_a_missing_key_file_is_caught_even_without_receipts(socket_dir, capsys):
    code = main([
        "--rules", CONFORMANCE_SPEC,
        "--socket", os.path.join(socket_dir, "g.sock"),
        "--key-file", os.path.join(socket_dir, "no-such-key"),
    ])
    assert code == EXIT_BAD_RULES
    assert "cannot read key file" in capsys.readouterr().err


def test_an_unreadable_key_file_exits_2(socket_dir, capsys):
    if os.getuid() == 0:
        pytest.skip("root can read any file")
    key = os.path.join(socket_dir, "key")
    with open(key, "w", encoding="ascii") as fh:
        fh.write("ab" * 32)
    os.chmod(key, 0)
    code = main([
        "--rules", CONFORMANCE_SPEC,
        "--socket", os.path.join(socket_dir, "g.sock"),
        "--receipts", os.path.join(socket_dir, "receipts.ndjson"),
        "--key-file", key,
    ])
    assert code == EXIT_BAD_RULES
    assert "cannot read key file" in capsys.readouterr().err


# --- live connections at shutdown ---------------------------------------------


def test_serve_closes_connections_that_were_open_when_it_exited(sock_path):
    path = sock_path()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        with serve(CONFORMANCE_ENGINE, path):
            client.connect(path)
            reader = client.makefile("rb")
            client.sendall(_ping_frame("t-1"))
            assert reader.readline()  # answered while the server is up

        # The block has exited. The same connection must not be answered.
        try:
            client.sendall(_ping_frame("t-2"))
            reply = reader.readline()
        except (ConnectionError, OSError):
            reply = b""
        assert reply == b""
    finally:
        client.close()


# --- client timeouts ----------------------------------------------------------


def test_remote_engine_has_a_finite_default_timeout():
    assert DEFAULT_TIMEOUT == 5.0
    assert RemoteEngine("/nonexistent.sock").timeout == DEFAULT_TIMEOUT
    assert RemoteEngine("/nonexistent.sock", timeout=1.5).timeout == 1.5
    assert RemoteEngine("/nonexistent.sock", timeout=None).timeout is None


def test_a_daemon_that_never_replies_blocks_after_the_timeout(sock_path):
    # Listening but never accepting: connect and send succeed, the reply
    # never comes. That is what a hung daemon looks like to a client.
    path = sock_path()
    hung = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    hung.bind(path)
    hung.listen(8)
    remote = RemoteEngine(path, timeout=0.3)
    try:
        started = time.monotonic()
        with pytest.raises(Blocked) as excinfo:
            remote.evaluate(SensorEvent(action="ping"))
        elapsed = time.monotonic() - started
        assert 0.25 <= elapsed < 3.0
        assert "unreachable" in excinfo.value.decision.reason
    finally:
        remote.close()
        hung.close()


def test_a_damaged_receipts_file_is_a_clean_refusal(tmp_path, capsys):
    from interlock.sidecar.__main__ import RulesError, _build_sink

    receipts = tmp_path / "receipts.ndjson"
    receipts.write_text('{"not": "a receipt"\n')
    with pytest.raises(RulesError, match="cannot use receipts file"):
        _build_sink(str(receipts), None)
