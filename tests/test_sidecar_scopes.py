"""A scoped engine over the sidecar wire, and the signed scope document.

Two claims, each with a test that proves it rather than asserts it:

- a remote client gets the *same per-principal decision* an in-process
  ``ScopedEngine`` reaches for the same event (the live smoke starts a real
  daemon and compares the wire verdict to a locally built oracle), and
- a scope-document overlay on the wire is only trusted when it is signed - an
  unsigned, tampered, or non-matching overlay is refused, never ignored.

The scope document here is the same one ``tests.fixtures.rules`` declares, so
the daemon (which publishes and serves it) and the oracle (built locally from a
plain tree) resolve the identical bindings.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from interlock import Verdict
from interlock.event import SensorEvent
from interlock.policy.scopes import Binding, ScopeRegistry, ScopeTree, ScopedEngine
from interlock.sidecar.__main__ import _load_scope, main
from interlock.sidecar.rules import RulesError, scope_document_of
from interlock.sink import InMemorySink
from interlock.testing.harness import send_raw, serve
from interlock.wire import (
    canonical,
    decode_line,
    encode_frame,
    request_frame,
    scope_envelope,
    scope_identity,
)

from tests.fixtures import rules as fixture_rules

KEY = b"an-r29-scope-signing-key-0123456789"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _scoped_engine() -> ScopedEngine:
    """An in-process ScopedEngine over the fixture's scopes, built by hand.

    Deliberately *not* ``build_scoped_engine``: the smoke wants an oracle the
    daemon did not construct, so an equality is evidence about the wire rather
    than about a shared builder.
    """
    tree = ScopeTree()
    tree.bind(("acme",), [Binding("shell_allowlist", {"allow": ["ls", "pwd"]})])
    tree.bind(("acme", "agent1"), [Binding("shell_allowlist", {"allow": ["ls"]})])
    return ScopedEngine(ScopeRegistry(tree, fixture_rules.templates))


def _event(cmd: str, principal: str = "acme/agent1") -> SensorEvent:
    return SensorEvent(action="run_shell", args={"cmd": cmd}, principal=principal)


def _signed() -> dict:
    return scope_envelope(fixture_rules.scope_document(), KEY, written_at=1_700_000_000)


def _args(scope=None, rules="tests.fixtures.rules:rules", key_file=None):
    return argparse.Namespace(scope_document=scope, rules=rules, key_file=key_file)


# --- scoped decisions over the socket ---------------------------------------


def test_the_wire_reaches_the_same_per_principal_decision_as_the_oracle(sock_path):
    path = sock_path()
    engine = _scoped_engine()
    with serve(engine, path):
        allowed = send_raw(path, canonical(request_frame("op-1", _event("ls"))))
        blocked = send_raw(path, canonical(request_frame("op-2", _event("rm -rf /"))))
        other = send_raw(path, canonical(request_frame("op-3", _event("rm", "beta/agent2"))))
    assert allowed["verdict"] == int(Verdict.ALLOW)
    assert blocked["verdict"] == int(Verdict.BLOCK)
    # A principal with no bound prefix resolves to an empty engine, which is a
    # refusal, not a permission: beta/agent2 is blocked as an unbound scope
    # rather than silently allowed. The oracle uses the same ScopedEngine, so
    # wire == oracle still holds.
    assert other["verdict"] == int(Verdict.BLOCK)


def test_an_unscoped_event_is_blocked_fail_closed(sock_path):
    path = sock_path()
    with serve(_scoped_engine(), path):
        reply = send_raw(path, canonical(request_frame("op-1", _event("ls", ""))))
    assert reply["verdict"] == int(Verdict.BLOCK)


# --- the scope document is recorded in the receipt provenance ---------------


def test_the_served_scope_document_is_recorded_in_the_receipt(sock_path):
    path = sock_path()
    sink = InMemorySink()
    envelope = _signed()
    with serve(_scoped_engine(), path, sink=sink) as server:
        server.scope_key = KEY
        server.scope_document = envelope
        send_raw(path, canonical(request_frame("op-1", _event("ls"))))
    assert sink.receipts[-1].scope_document == scope_identity(envelope)


def test_no_scope_document_means_no_provenance_field(sock_path):
    path = sock_path()
    sink = InMemorySink()
    with serve(_scoped_engine(), path, sink=sink):
        send_raw(path, canonical(request_frame("op-1", _event("ls"))))
    assert sink.receipts[-1].scope_document is None
    assert "scope_document" not in sink.receipts[-1].to_json()


# --- a verified overlay is accepted and recorded -----------------------------


def test_a_signed_overlay_is_accepted_and_recorded(sock_path):
    path = sock_path()
    sink = InMemorySink()
    envelope = _signed()
    with serve(_scoped_engine(), path, sink=sink) as server:
        server.scope_key = KEY
        server.scope_document = envelope
        reply = send_raw(
            path, canonical(request_frame("op-1", _event("ls"), scope=envelope))
        )
    assert reply["verdict"] == int(Verdict.ALLOW)
    assert sink.receipts[-1].scope_document == scope_identity(envelope)


# --- an overlay that is not signed / does not verify is refused --------------


def test_an_unsigned_overlay_is_refused(sock_path):
    path = sock_path()
    envelope = _signed()
    unsigned = {k: v for k, v in envelope.items() if k != "mac"}
    with serve(_scoped_engine(), path) as server:
        server.scope_key = KEY
        server.scope_document = envelope
        reply = send_raw(
            path, canonical(request_frame("op-1", _event("ls"), scope=unsigned))
        )
    assert "error" in reply
    assert reply["error"]["code"] == "unauthenticated_scope"


def test_a_tampered_overlay_is_refused(sock_path):
    path = sock_path()
    envelope = _signed()
    tampered = dict(envelope, mac="0" * 64)
    with serve(_scoped_engine(), path) as server:
        server.scope_key = KEY
        server.scope_document = envelope
        reply = send_raw(
            path, canonical(request_frame("op-1", _event("ls"), scope=tampered))
        )
    assert "error" in reply
    assert reply["error"]["code"] == "unauthenticated_scope"


def test_an_overlay_with_no_key_to_verify_it_is_refused(sock_path):
    # A daemon serving no scope document holds no key; an overlay it is handed
    # is refused rather than waved through unverified.
    path = sock_path()
    with serve(_scoped_engine(), path):
        reply = send_raw(
            path, canonical(request_frame("op-1", _event("ls"), scope=_signed()))
        )
    assert "error" in reply
    assert reply["error"]["code"] == "unauthenticated_scope"


def test_a_well_signed_but_non_matching_overlay_is_refused(sock_path):
    path = sock_path()
    served = _signed()
    other = scope_envelope(
        {"version": 1, "bindings": {}, "default_scope": []}, KEY, written_at=1_600_000_000
    )
    with serve(_scoped_engine(), path) as server:
        server.scope_key = KEY
        server.scope_document = served
        reply = send_raw(
            path, canonical(request_frame("op-1", _event("ls"), scope=other))
        )
    assert "error" in reply
    assert reply["error"]["code"] == "scope_mismatch"


# --- startup: the scope document is read, published, or refused --------------


def test_an_existing_document_signed_with_another_key_is_refused(tmp_path):
    path = tmp_path / "scope.json"
    envelope = scope_envelope(fixture_rules.scope_document(), b"a-different-key")
    path.write_text(canonical(envelope))
    with pytest.raises(RulesError):
        _load_scope(_args(str(path)))


def test_an_existing_verified_document_is_loaded(tmp_path):
    key_file = tmp_path / "key"
    key_file.write_bytes(KEY)
    scope = tmp_path / "scope.json"
    envelope = scope_envelope(fixture_rules.scope_document(), KEY)
    scope.write_text(canonical(envelope))
    engine, key, loaded = _load_scope(_args(str(scope), key_file=str(key_file)))
    assert key == KEY
    assert scope_identity(loaded) == scope_identity(envelope)
    assert engine.evaluate(_event("rm -rf /")).verdict is Verdict.BLOCK


def test_a_missing_document_is_published_from_the_module(tmp_path):
    scope = tmp_path / "scope.json"
    assert not scope.exists()
    _, _, envelope = _load_scope(_args(str(scope)))
    assert scope.exists()
    assert envelope["version"] == 1 and envelope["mac"]


def test_a_module_with_no_scope_document_refuses_to_publish(tmp_path):
    scope = tmp_path / "scope.json"
    with pytest.raises(RulesError):
        _load_scope(_args(str(scope), rules="interlock.sidecar.rules:load_rules"))


def test_check_does_not_touch_the_scope_document(tmp_path, capsys):
    scope = tmp_path / "scope.json"
    rc = main(["--rules", "tests.fixtures.rules:rules",
               "--scope-document", str(scope), "--check"])
    assert rc == 0
    assert not scope.exists()


# --- the live smoke: a real daemon, one event, the oracle --------------------


def test_live_smoke_wire_decision_equals_in_process_scoped_engine(sock_path, tmp_path):
    """Start a real daemon, send events over the wire, compare to the oracle."""
    sock = sock_path("s")
    scope = tmp_path / "scope.json"
    proc = subprocess.Popen(
        [sys.executable, "-m", "interlock.sidecar", "--socket", sock,
         "--rules", "tests.fixtures.rules:rules", "--scope-document", str(scope)],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 30
        while not os.path.exists(sock) and time.time() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        assert os.path.exists(sock), proc.stderr.read().decode()

        oracle = _scoped_engine()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5.0)
        client.connect(sock)
        try:
            for op, cmd in (("op-1", "ls"), ("op-2", "rm -rf /"), ("op-3", "pwd")):
                event = _event(cmd)
                client.sendall(encode_frame(request_frame(op, event)))
                reply = decode_line(client.recv(65536))
                assert reply["verdict"] == int(oracle.evaluate(event).verdict)
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
    print("R29 smoke pass")
