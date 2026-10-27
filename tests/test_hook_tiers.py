"""The hook's artifact-plus-sidecar path (C6).

An artifact is the local primary for every call. When ``--sidecar`` is also
given, the high-risk classes are additionally asked of the daemon under a
deadline and the artifact's per-class failure policy. The rule the tests pin:
a read-only call never opens a socket, and a shell call whose second opinion
cannot be had is blocked with ``policy_id='fail_closed'`` - never allowed.

Receipts keep naming the artifact: the ``TierEngine`` adapter must not hide
``artifact_bytes``/``sha256``/``epoch`` from ``run_hook``.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys

import pytest

from interlock.adapters import get_adapter
from interlock.adapters.base import run_hook
from interlock.cli import hook as hook_cli
from interlock.policy import tiers
from interlock.policy.artifact import (
    ARTIFACT_FORMAT,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
    seal_artifact,
)
from interlock.receipt import set_sink
from interlock.sink import InMemorySink

RULES = [
    {"id": "no-rm", "verdict": "block", "reason": "recursive delete",
     "when": {"all": [{"action": "Bash"},
                      {"arg": "command", "contains": "rm -rf"}]}},
]

SCOPE = {
    "version": 1,
    "bindings": {
        "claude-code": [{
            "template": "shell_allowlist",
            "params": {"allow": ["ls", "pwd"]},
        }],
    },
    "default_scope": [],
    "allow_unscoped": True,
}


def flags(**overrides):
    values = dict(agent="claude-code", policy=None, artifact=None, rules=None,
                  sidecar=None, receipts=None, key_file=None,
                  no_receipts=True, no_overlay=False, monitor=False,
                  on_error="deny", reviews="off", review_db=None)
    values.update(overrides)
    return argparse.Namespace(**values)


def _artifact(tmp_path, **failure_policy):
    policy = dict(FAILURE_POLICY_DEFAULTS)
    policy.update(failure_policy)
    raw = canonical_bytes(seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": RULES}],
        "scope": SCOPE,
        "rules_module": "tests.fixtures.cloud.rules_module:templates",
        "template_ids": ["shell_allowlist"],
        "catalog": "",
        "failure_policy": policy,
    }))
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    return path, load_artifact(raw)


def _payload(tool, tool_input):
    return json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "session_id": "s",
        "cwd": "/tmp",
    })


def _read_payload():
    return json.loads(_payload("Read", {"file_path": "/tmp/notes.txt"}))


def _bash_payload(command="ls"):
    return json.loads(_payload("Bash", {"command": command}))


def _deny_reason(stdout, code):
    assert code == 0
    body = json.loads(stdout)
    decision = body["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    return decision["permissionDecisionReason"]


@pytest.fixture(autouse=True)
def _fresh_warnings():
    tiers.reset_warning_state()
    yield
    tiers.reset_warning_state()


# --- wiring ---------------------------------------------------------------


def test_artifact_alone_is_the_engine(tmp_path, socket_dir):
    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(flags(artifact=str(path)), str(tmp_path), engine)
    assert built is engine


def test_artifact_and_sidecar_build_a_tier_engine(tmp_path, socket_dir):
    from interlock.policy.tiers import TierEngine
    from interlock.sidecar.client import RemoteEngine

    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "dead.sock")),
        str(tmp_path), engine,
    )
    assert isinstance(built, TierEngine)
    assert built.evaluator.primary is engine
    assert isinstance(built.evaluator.secondary, RemoteEngine)


# --- routing through run_hook --------------------------------------------


def test_a_read_only_call_is_decided_locally_without_a_socket(tmp_path, socket_dir):
    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "dead.sock")),
        str(tmp_path), engine,
    )
    adapter = get_adapter("claude-code")

    stdout, stderr, code = run_hook(adapter, _read_payload(), built,
                                    enforcement="blocking", review_mode="off")

    assert (stdout, stderr, code) == ("", "", 0)
    assert built.last.tier == "primary"
    assert built.last.class_ == "read_only"


def test_a_shell_call_with_a_missing_secondary_blocks_fail_closed(tmp_path, socket_dir):
    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "dead.sock")),
        str(tmp_path), engine,
    )
    adapter = get_adapter("claude-code")

    stdout, _stderr, code = run_hook(adapter, _bash_payload("ls"), built,
                                     enforcement="blocking", review_mode="off")

    reason = _deny_reason(stdout, code)
    assert "sidecar_unavailable" in reason
    assert "fail_closed" in reason
    assert built.last.tier == "fail_closed"


def test_the_receipt_still_names_the_artifact(tmp_path, socket_dir):
    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "dead.sock")),
        str(tmp_path), engine,
    )
    sink = InMemorySink(key=b"k" * 32)
    set_sink(sink)
    try:
        run_hook(get_adapter("claude-code"), _read_payload(), built,
                 enforcement="blocking", review_mode="off")
    finally:
        set_sink(None)

    assert len(sink.receipts) == 1
    assert sink.receipts[0].policy_artifact == engine.sha256


def test_an_open_class_records_a_coverage_gap_and_warns_once(
        tmp_path, socket_dir, caplog):
    path, engine = _artifact(tmp_path, shell="open")
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "dead.sock")),
        str(tmp_path), engine,
    )
    adapter = get_adapter("claude-code")

    with caplog.at_level(logging.WARNING, logger="interlock"):
        first = run_hook(adapter, _bash_payload("ls"), built,
                         enforcement="blocking", review_mode="off")
        second = run_hook(adapter, _bash_payload("pwd"), built,
                          enforcement="blocking", review_mode="off")

    # Both were allowed by the primary, but never presented as a policy pass.
    assert first == ("", "", 0)
    assert second == ("", "", 0)
    assert built.last.decision.verdict.name == "ALLOW"
    assert built.last.decision.policy_id == "coverage_gap"
    assert built.evaluator.coverage_gaps == {"shell": 2}
    warnings = [r for r in caplog.records if "coverage_gap" in r.getMessage()]
    assert len(warnings) == 1


# --- the command line -----------------------------------------------------


def test_the_cli_refuses_artifact_with_a_local_policy(tmp_path, capsys):
    path, _engine = _artifact(tmp_path)
    args = flags(artifact=str(path), policy=str(tmp_path / "policy.json"))
    code = hook_cli.run(args)
    assert code == 64
    assert "--artifact cannot be combined" in capsys.readouterr().err


def test_the_cli_allows_artifact_with_a_sidecar(tmp_path, socket_dir, monkeypatch, capsys):
    path, _engine = _artifact(tmp_path)
    payload = _payload("Read", {"file_path": "/tmp/notes.txt"}).encode()
    monkeypatch.setattr(
        sys, "stdin", type("Stdin", (), {"buffer": io.BytesIO(payload)})())
    args = flags(artifact=str(path),
                 sidecar=os.path.join(socket_dir, "dead.sock"))

    code = hook_cli.run(args)

    out, err = capsys.readouterr()
    assert code == 0
    assert out == ""
    assert "--artifact cannot be combined" not in err


def _empty_artifact(tmp_path):
    """An artifact that seals and verifies but has no rule to decide with."""
    raw = canonical_bytes(seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": []}],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": True},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }))
    path = tmp_path / "empty.json"
    path.write_bytes(raw)
    return path


def test_the_cli_refuses_an_artifact_that_decides_nothing(tmp_path, monkeypatch, capsys):
    # An empty rule set allows every call. The hook must refuse to run under
    # it whatever --on-error says, and it must refuse before reading stdin: an
    # allow-everything guard is a configuration error, not a per-call decision.
    path = _empty_artifact(tmp_path)
    monkeypatch.setattr(
        sys, "stdin", type("Stdin", (), {"buffer": io.BytesIO(b"{}")})())

    code = hook_cli.run(flags(artifact=str(path)))

    assert code == 64
    assert "no effective rules" in capsys.readouterr().err


def test_the_second_tier_is_pinned_to_the_artifact(tmp_path, socket_dir):
    path, engine = _artifact(tmp_path)
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=os.path.join(socket_dir, "x.sock")),
        str(tmp_path), engine,
    )
    secondary = built.evaluator.secondary
    assert secondary.artifact_sha256 == engine.sha256
    assert secondary.artifact_epoch == engine.epoch
    assert secondary.timeout == tiers.DEFAULT_DEADLINE


def test_a_tier_serving_another_artifact_fails_closed(tmp_path, sock_path):
    from interlock.testing.harness import serve

    path, engine = _artifact(tmp_path)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    _other_path, other_engine = _artifact(other_dir, shell="open")
    socket = sock_path()
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=str(socket)), str(tmp_path), engine)
    adapter = get_adapter("claude-code")

    with serve(other_engine, socket):
        stdout, _stderr, code = run_hook(adapter, _bash_payload("ls"), built,
                                         enforcement="blocking", review_mode="off")

    # The daemon was reachable and allowed the call, but it is not serving the
    # artifact this hook pinned, so its verdict cannot decide the class.
    reason = _deny_reason(stdout, code)
    assert "sidecar_unavailable" in reason
    assert built.last.tier == "fail_closed"


def test_a_tier_serving_the_pinned_artifact_decides_the_class(tmp_path, sock_path):
    from interlock.testing.harness import serve

    path, engine = _artifact(tmp_path)
    socket = sock_path()
    built = hook_cli._engine(
        flags(artifact=str(path), sidecar=str(socket)), str(tmp_path), engine)
    # This test is about the pin, not the budget: give the round trip room so a
    # loaded runner cannot turn it into a deadline miss.
    built.evaluator.deadline = 0.5
    built.evaluator.secondary.timeout = 0.5
    adapter = get_adapter("claude-code")

    with serve(engine, socket):
        stdout, stderr, code = run_hook(adapter, _bash_payload("ls"), built,
                                        enforcement="blocking", review_mode="off")

    assert (stdout, stderr, code) == ("", "", 0)
    assert built.last.tier == "secondary"
    assert built.last.class_ == "shell"
