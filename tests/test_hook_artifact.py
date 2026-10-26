"""The hook's distributed-artifact path (C5).

``--artifact`` loads the verified bytes once, before any event, and never
falls back to a local policy. A missing, corrupt or unmaterialisable artifact
takes the existing fail-closed deny bootstrap, so an agent whose hook cannot
start is refused in its own protocol rather than left unguarded.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess

import pytest

from interlock.adapters import get_adapter
from interlock.adapters.base import run_hook
from interlock.adapters.config import load_engine
from interlock.cli.install_hook import hook_command
from interlock.cloud.policy.compile import compile_from_source
from interlock.policy.artifact import load_artifact, materialize, seal_artifact, canonical_bytes
from interlock.receipt import set_sink
from interlock.sink import InMemorySink
from tests.fixtures.cloud.rules_module import scope_document

MODULE = "tests.fixtures.cloud.rules_module:templates"


def flags(**overrides):
    values = dict(agent=None, policy=None, artifact=None, rules=None,
                  sidecar=None, receipts=None, key_file=None,
                  no_receipts=False, no_overlay=False, monitor=False,
                  on_error="deny", reviews="off", review_db=None)
    values.update(overrides)
    return argparse.Namespace(**values)


def _scope():
    document = scope_document()
    document["bindings"]["claude-code"] = [
        {"template": "shell_allowlist", "params": {"allow": ["ls", "pwd"]}},
    ]
    return document


def _compiled():
    return compile_from_source([], _scope(), rules_module=MODULE)


def _artifact(tmp_path, name="policy.json"):
    result = _compiled()
    path = tmp_path / name
    materialize(result.artifact_bytes, path)
    return result, path


def _payload(command):
    return json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": command}, "session_id": "s",
        "cwd": "/tmp",
    })


def _decide(command, payload, home, tmp_path):
    environment = dict(os.environ, HOME=str(home))
    completed = subprocess.run(
        command, shell=True, cwd=str(tmp_path), env=environment,
        input=payload.encode(), capture_output=True, timeout=60,
    )
    return (completed.stdout.decode(), completed.stderr.decode(),
            completed.returncode)


def _deny_reason(stdout, code):
    assert code == 0
    body = json.loads(stdout)
    decision = body["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    return decision["permissionDecisionReason"]


# -- fail closed before any event ---------------------------------------

def test_a_missing_artifact_denies_before_the_event_is_parsed(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    command = hook_command("claude-code", flags(artifact=str(tmp_path / "gone.json")))
    # The payload is not even valid JSON: the artifact is loaded first, so the
    # refusal names the artifact, not the event.
    stdout, stderr, code = _decide(command, "not json", home, tmp_path)
    assert "Traceback" not in stdout + stderr
    assert "ArtifactError" in _deny_reason(stdout, code)


def test_a_corrupt_artifact_denies(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    path = tmp_path / "bad.json"
    path.write_bytes(b'{"format": 1, "epoch": ')
    command = hook_command("claude-code", flags(artifact=str(path)))
    stdout, _stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    assert "ArtifactError" in _deny_reason(stdout, code)


def test_an_artifact_whose_module_is_gone_denies_instead_of_allowing(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    artifact = json.loads(_compiled().artifact_bytes.decode("utf-8"))
    artifact["rules_module"] = "tests.fixtures.cloud.gone:templates"
    path = tmp_path / "gone-module.json"
    path.write_bytes(canonical_bytes(seal_artifact(artifact)))
    command = hook_command("claude-code", flags(artifact=str(path)))
    stdout, _stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    assert "ArtifactError" in _deny_reason(stdout, code)


def test_a_directory_without_an_active_pointer_denies(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    directory = tmp_path / "artifacts"
    directory.mkdir()
    command = hook_command("claude-code", flags(artifact=str(directory)))
    stdout, _stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    assert "ArtifactError" in _deny_reason(stdout, code)


# -- the artifact decides -------------------------------------------------

def test_the_artifact_allows_and_blocks_in_the_agents_protocol(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    _result, path = _artifact(tmp_path)
    command = hook_command("claude-code", flags(artifact=str(path)))

    stdout, stderr, code = _decide(command, _payload("ls -la"), home, tmp_path)
    assert (stdout, stderr, code) == ("", "", 0)

    stdout, _stderr, code = _decide(command, _payload("rm -rf /"), home, tmp_path)
    reason = _deny_reason(stdout, code)
    assert "shell_allowlist" in reason and "not allowed" in reason


def test_an_active_kill_denies_even_a_fresh_artifact(tmp_path):
    # The connector writes kill.json beside the artifact after verifying a
    # signed kill (FR-067). The hook must block every call whatever
    # --on-error says: a kill is a decision, not an internal error.
    home = tmp_path / "home"
    home.mkdir()
    result, path = _artifact(tmp_path)
    (tmp_path / "kill.json").write_text(json.dumps({
        "kill": {"id": "k-1", "reason": "credential leak",
                 "target": {"kind": "ring", "id": "stable"}},
        "kill_epoch": 1,
        "verified_at": 1.0,
    }), encoding="utf-8")
    command = hook_command("claude-code", flags(
        artifact=str(path), on_error="allow"))

    # 'ls' is allowed by the artifact itself; the kill overrides it.
    stdout, _stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    reason = _deny_reason(stdout, code)
    assert "kill switch k-1" in reason and "credential leak" in reason


def test_an_unreadable_kill_marker_fails_closed(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    _result, path = _artifact(tmp_path)
    (tmp_path / "kill.json").write_bytes(b"{not json")
    command = hook_command("claude-code", flags(artifact=str(path)))
    stdout, _stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    assert "kill switch unreadable" in _deny_reason(stdout, code)


def test_a_directory_containing_active_json_is_accepted(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    result = _compiled()
    directory = tmp_path / "artifacts"
    directory.mkdir()
    (directory / "{}.json".format(result.sha256)).write_bytes(result.artifact_bytes)
    (directory / "active.json").write_bytes(canonical_bytes(
        {"sha256": result.sha256, "version": 1, "epoch": result.epoch,
         "mode": "enforce", "rules_module": result.rules_module}))
    command = hook_command("claude-code", flags(artifact=str(directory)))

    stdout, stderr, code = _decide(command, _payload("ls"), home, tmp_path)
    assert (stdout, stderr, code) == ("", "", 0)


# -- receipts ------------------------------------------------------------

def test_receipts_stamp_the_artifact_epoch_and_sha(tmp_path):
    result, path = _artifact(tmp_path)
    policy = load_artifact(path)
    sink = InMemorySink(key=b"k" * 32)
    set_sink(sink)
    try:
        adapter = get_adapter("claude-code")
        payload = json.loads(_payload("ls"))
        stdout, _stderr, code = run_hook(adapter, payload, policy,
                                         enforcement="blocking",
                                         review_mode="off")
    finally:
        set_sink(None)

    assert (stdout, code) == ("", 0)
    assert len(sink.receipts) == 1
    receipt = sink.receipts[0]
    assert receipt.policy_epoch == result.epoch == policy.epoch
    assert receipt.policy_artifact == result.sha256 == policy.sha256
    assert receipt.fields()["policy_artifact"] == result.sha256


def test_a_local_policy_receipt_keeps_the_artifact_field_absent(tmp_path):
    engine = load_engine(cwd=str(tmp_path), overlay=False)
    sink = InMemorySink(key=b"k" * 32)
    set_sink(sink)
    try:
        adapter = get_adapter("claude-code")
        run_hook(adapter, json.loads(_payload("ls")), engine,
                 enforcement="blocking", review_mode="off")
    finally:
        set_sink(None)
    assert sink.receipts
    assert "policy_artifact" not in sink.receipts[0].fields()


def test_the_hook_module_is_the_artifact_module_not_a_local_override(tmp_path):
    # A different rules module under the same artifact hash is refused: the
    # process is pinned to the module the artifact names.
    result, path = _artifact(tmp_path)
    with pytest.raises(Exception) as exc:
        load_artifact(path, module="tests.fixtures.cloud.rules_module:other")
    assert getattr(exc.value, "code", None) == "module_mismatch"
    assert result.rules_module == MODULE
