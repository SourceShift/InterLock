"""``install-hook --artifact``: embed the distributed policy in the hook.

The installed command must stay one isolated line and carry an absolute
artifact path, exactly as ``--policy`` does. The two authorities are mutually
exclusive and a command line carrying both is usage error 64, not a silent
choice between them.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex

from interlock.adapters.base import is_ours
from interlock.cli import main
from interlock.cli.install_hook import hook_command


def flags(**overrides):
    values = dict(agents="claude-code", settings=None, policy=None,
                  artifact=None, sidecar=None, receipts=None, key_file=None,
                  reviews=None, review_db=None, monitor=False,
                  dry_run=False, uninstall=False)
    values.update(overrides)
    return argparse.Namespace(**values)


def test_the_artifact_path_is_embedded_absolute_and_quoted(tmp_path):
    spaced = tmp_path / "with space" / "policy.json"
    command = hook_command("codex", flags(artifact=str(spaced)))
    argv = shlex.split(command)
    assert "\n" not in command and is_ours(command)
    assert argv[argv.index("--agent"):] == [
        "--agent", "codex", "--artifact", str(spaced)]


def test_an_artifact_install_does_not_also_carry_a_policy_path(tmp_path):
    command = hook_command("claude-code", flags(
        artifact=str(tmp_path / "active"), policy=None))
    assert "--artifact" in command and "--policy" not in command


def test_a_local_install_is_unchanged_without_the_artifact_flag(tmp_path):
    command = hook_command("claude-code", flags(
        policy=str(tmp_path / "policy.json")))
    assert "--artifact" not in command
    assert "--policy" in command


def test_hook_command_orders_the_artifact_after_policy(tmp_path):
    command = hook_command("claude-code", flags(
        policy=str(tmp_path / "p.json"), artifact=str(tmp_path / "a.json")))
    argv = shlex.split(command)
    assert argv[argv.index("--policy"):] == [
        "--policy", str(tmp_path / "p.json"),
        "--artifact", str(tmp_path / "a.json")]


def test_install_hook_refuses_both_authorities_with_usage_error(tmp_path, capsys):
    settings = tmp_path / "settings.json"
    code = main(["install-hook", "--for", "claude-code",
                 "--settings", str(settings),
                 "--policy", str(tmp_path / "p.json"),
                 "--artifact", str(tmp_path / "a.json"), "--dry-run"])
    assert code == 64
    assert "cannot be combined" in capsys.readouterr().err
    assert not settings.exists()


def test_hook_refuses_both_authorities_with_usage_error(tmp_path, capsys):
    code = main(["hook", "--agent", "claude-code",
                 "--policy", str(tmp_path / "p.json"),
                 "--artifact", str(tmp_path / "a.json")])
    assert code == 64
    assert "cannot be combined" in capsys.readouterr().err


def test_dry_run_shows_the_artifact_command_and_writes_nothing(tmp_path, capsys):
    artifact = tmp_path / "a.json"
    code = main(["install-hook", "--for", "claude-code",
                 "--artifact", str(artifact), "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "--artifact " + str(artifact) in out
    assert not (tmp_path / ".claude").exists()


def test_a_real_install_persists_the_artifact_flag(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    artifact = tmp_path / "artifacts"
    artifact.mkdir()

    code = main(["install-hook", "--for", "claude-code",
                 "--settings", str(settings), "--artifact", str(artifact)])
    assert code == 0, capsys.readouterr().err

    text = settings.read_text(encoding="utf-8")
    document = json.loads(text)
    commands = [entry["hooks"][0]["command"]
                for entry in document["hooks"].get("PreToolUse", [])]
    assert commands and "--artifact " + str(artifact) in commands[0]
    assert os.path.isabs(str(artifact))
    assert is_ours(commands[0])
