"""Artifact mode in the sidecar (C6).

A daemon started with ``--artifact`` serves a ``CompiledPolicy``. Every
response frame and every receipt then carries the artifact's sha256 and epoch,
so a client can pin the policy it believes it is talking to and refuse a
rollback or a wrong-environment daemon. A plain ``--rules`` daemon keeps the
R19 frame exactly: the optional keys are present only in artifact mode.

The offline fallback file gets the same treatment: when the daemon published
it from an artifact, the file carries the artifact identity under its own MAC,
and a degraded client that pinned an artifact refuses a fallback that belongs
to another one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from interlock import Blocked
from interlock.enforce import Verdict
from interlock.event import SensorEvent
from interlock.policy.artifact import (
    ARTIFACT_FORMAT,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
    seal_artifact,
)
from interlock.sidecar.client import RemoteEngine
from interlock.sidecar.fallback import (
    FallbackError,
    fallback_path,
    read_fallback_metadata,
    write_fallback,
)
from interlock.sidecar.__main__ import (
    EXIT_BAD_RULES,
    _parse_args,
    main as sidecar_main,
)
from interlock.sink import InMemorySink
from interlock.testing.fixtures import CONFORMANCE_ENGINE
from interlock.testing.harness import send_raw, serve
from interlock.wire import PROTOCOL_VERSION, canonical

KEY = b"k" * 32
SHA = "a" * 64
EPOCH = "0123456789abcdef"

FALLBACK_POLICY = {
    "version": 1,
    "rules": [{
        "id": "no-rm",
        "verdict": "block",
        "reason": "recursive delete",
        "when": {"all": [
            {"action": "run_shell"},
            {"arg": "cmd", "contains": "rm -rf"},
        ]},
    }],
}


def _artifact_bytes() -> bytes:
    return canonical_bytes(seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": [{
            "id": "no-rm",
            "verdict": "block",
            "reason": "recursive delete",
            "when": {"all": [
                {"action": "run_shell"},
                {"arg": "cmd", "contains": "rm -rf"},
            ]},
        }]}],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": True},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }))


def _artifact(tmp_path):
    path = tmp_path / "policy.json"
    path.write_bytes(_artifact_bytes())
    return path, load_artifact(str(path))


def _rm_event():
    return SensorEvent("run_shell", {"cmd": "rm -rf /"})


def _send(path, action, args):
    return send_raw(path, canonical({
        "v": PROTOCOL_VERSION,
        "id": "t-1",
        "event": {"action": action, "args": args},
    }))


# --- artifact daemon ------------------------------------------------------


def test_artifact_daemon_stamps_frames_and_receipts(sock_path, tmp_path):
    path = sock_path()
    _, engine = _artifact(tmp_path)
    reply = None
    sink = InMemorySink()
    with serve(engine, path, sink=sink) as server:
        assert server.artifact_sha256 == engine.sha256
        assert server.policy_epoch == engine.epoch
        reply = _send(path, "run_shell", {"cmd": "rm -rf /"})

    assert reply["verdict"] == int(Verdict.BLOCK)
    assert reply["policy_id"] == "no-rm"
    assert reply["policy_artifact"] == engine.sha256
    assert reply["policy_epoch"] == engine.epoch

    receipt = sink.receipts[0]
    assert receipt.policy_artifact == engine.sha256
    assert receipt.policy_epoch == engine.epoch


def test_a_plain_daemon_keeps_the_r19_frame_shape(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = _send(path, "ping", {})
    assert reply["verdict"] == int(Verdict.ALLOW)
    assert "policy_artifact" not in reply
    assert "policy_epoch" not in reply


def test_an_artifact_client_evaluates_through_the_daemon(sock_path, tmp_path):
    path = sock_path()
    _, engine = _artifact(tmp_path)
    with serve(engine, path):
        with RemoteEngine(path) as client:
            decision = client.evaluate(_rm_event())
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "no-rm"


# --- client pinning -------------------------------------------------------


def test_a_matching_pin_is_accepted(sock_path, tmp_path):
    path = sock_path()
    _, engine = _artifact(tmp_path)
    with serve(engine, path):
        with RemoteEngine(path, artifact_sha256=engine.sha256,
                          artifact_epoch=engine.epoch) as client:
            assert client.evaluate(_rm_event()).verdict is Verdict.BLOCK


def test_a_mismatched_artifact_is_refused(sock_path, tmp_path):
    path = sock_path()
    _, engine = _artifact(tmp_path)
    with serve(engine, path):
        with RemoteEngine(path, artifact_sha256="b" * 64) as client:
            with pytest.raises(Blocked) as caught:
                client.evaluate(_rm_event())
    assert "artifact_mismatch" in str(caught.value)


def test_a_daemon_without_an_artifact_cannot_satisfy_a_pin(sock_path):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        with RemoteEngine(path, artifact_sha256=SHA) as client:
            with pytest.raises(Blocked) as caught:
                client.evaluate(_rm_event())
    assert "no policy artifact" in str(caught.value)


def test_a_mismatched_epoch_is_refused(sock_path, tmp_path):
    path = sock_path()
    _, engine = _artifact(tmp_path)
    with serve(engine, path):
        with RemoteEngine(path, artifact_sha256=engine.sha256,
                          artifact_epoch="fedcba9876543210") as client:
            with pytest.raises(Blocked) as caught:
                client.evaluate(_rm_event())
    assert "epoch" in str(caught.value)


# --- fallback pinning -----------------------------------------------------


def test_the_fallback_file_round_trips_its_artifact_identity(tmp_path):
    path = str(tmp_path / "guard.sock.fallback.json")
    write_fallback(path, FALLBACK_POLICY, KEY, artifact_sha256=SHA, epoch=EPOCH)
    metadata = read_fallback_metadata(path, KEY)
    assert metadata["policy"] == FALLBACK_POLICY
    assert metadata["artifact_sha256"] == SHA
    assert metadata["epoch"] == EPOCH


def test_a_degraded_client_accepts_a_fallback_for_its_artifact(socket_dir):
    sock = os.path.join(socket_dir, "dead.sock")
    write_fallback(fallback_path(sock), FALLBACK_POLICY, KEY,
                   artifact_sha256=SHA, epoch=EPOCH)
    client = RemoteEngine(
        sock, unreachable="degraded", fallback_key=KEY,
        artifact_sha256=SHA, artifact_epoch=EPOCH,
    )
    decision = client.evaluate(_rm_event())
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "fallback/no-rm"
    assert client.fallbacks == 1


def test_a_degraded_client_refuses_another_artifacts_fallback(socket_dir):
    sock = os.path.join(socket_dir, "dead.sock")
    write_fallback(fallback_path(sock), FALLBACK_POLICY, KEY,
                   artifact_sha256=SHA, epoch=EPOCH)
    client = RemoteEngine(
        sock, unreachable="degraded", fallback_key=KEY,
        artifact_sha256="b" * 64,
    )
    with pytest.raises(Blocked) as caught:
        client.evaluate(_rm_event())
    assert "belongs to artifact" in str(caught.value)


def test_a_legacy_fallback_cannot_satisfy_a_pin(socket_dir):
    sock = os.path.join(socket_dir, "dead.sock")
    write_fallback(fallback_path(sock), FALLBACK_POLICY, KEY)
    client = RemoteEngine(
        sock, unreachable="degraded", fallback_key=KEY, artifact_sha256=SHA,
    )
    with pytest.raises(Blocked) as caught:
        client.evaluate(_rm_event())
    assert "not pinned to an artifact" in str(caught.value)


def test_a_rewritten_artifact_sha_is_refused(tmp_path):
    path = str(tmp_path / "guard.sock.fallback.json")
    write_fallback(path, FALLBACK_POLICY, KEY, artifact_sha256=SHA, epoch=EPOCH)
    body = json.loads(Path(path).read_text(encoding="utf-8"))
    # The legacy MAC does not cover the artifact fields, so an attacker can
    # rewrite this without touching it. The second MAC is what refuses.
    body["artifact_sha256"] = "b" * 64
    Path(path).write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(FallbackError, match="does not verify"):
        read_fallback_metadata(path, KEY)


def test_artifact_fields_without_their_mac_are_refused(tmp_path):
    path = str(tmp_path / "guard.sock.fallback.json")
    write_fallback(path, FALLBACK_POLICY, KEY, artifact_sha256=SHA, epoch=EPOCH)
    body = json.loads(Path(path).read_text(encoding="utf-8"))
    del body["artifact_mac"]
    Path(path).write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(FallbackError, match="unsigned or malformed"):
        read_fallback_metadata(path, KEY)


# --- CLI ------------------------------------------------------------------


def test_artifact_is_a_single_policy_source():
    args = _parse_args(["--artifact", "policy.json"])
    assert args.artifact == "policy.json"
    assert args.rules is None


def test_sidecar_refuses_two_sources(capsys):
    code = sidecar_main(["--artifact", "a.json", "--rules", "m:e"])
    assert code == EXIT_BAD_RULES
    assert "choose one policy source" in capsys.readouterr().err


def test_sidecar_refuses_no_source(capsys):
    code = sidecar_main([])
    assert code == EXIT_BAD_RULES
    assert "one policy source is required" in capsys.readouterr().err


def test_sidecar_refuses_artifact_with_scope_document(capsys):
    code = sidecar_main(["--artifact", "a.json", "--scope-document", "s.json"])
    assert code == EXIT_BAD_RULES
    assert "cannot be combined" in capsys.readouterr().err


def test_sidecar_refuses_an_artifact_with_no_effective_rules(tmp_path, capsys):
    raw = canonical_bytes(seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": True},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }))
    path = tmp_path / "empty.json"
    path.write_bytes(raw)

    code = sidecar_main(["--check", "--artifact", str(path)])

    err = capsys.readouterr().err
    assert code == EXIT_BAD_RULES
    assert "no effective rules" in err
    assert "allow every call" in err


def test_check_reports_the_artifact_sha(tmp_path, capsys):
    path, engine = _artifact(tmp_path)
    code = sidecar_main(["--check", "--artifact", str(path)])
    err = capsys.readouterr().err
    assert code == 0
    assert engine.sha256 in err
    assert str(path) in err
