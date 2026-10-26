"""The installed hook command (A01).

It runs the interlock that installed it whatever directory the agent runs it
from, and it answers in the agent's own blocking shape when it cannot start.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess

import pytest

from interlock.adapters import ADAPTERS, get_adapter
from interlock.adapters.base import is_ours
from interlock.cli import install_hook, main
from interlock.cli.install_hook import hook_command

AGENTS = sorted(ADAPTERS)
COLLIDING = "raise SystemExit('imported from the working directory')\n"


def flags(**values):
    base = dict(policy=None, sidecar=None, receipts=None, key_file=None, monitor=False,
                reviews=None, review_db=None)
    base.update(values)
    return argparse.Namespace(**base)


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    return path


@pytest.fixture
def project(tmp_path):
    """An agent's project whose modules shadow interlock and the stdlib it imports."""
    path = tmp_path / "project"
    (path / "interlock").mkdir(parents=True)
    (path / "interlock" / "__init__.py").write_text(COLLIDING)
    for name in ("secrets", "json", "select", "argparse"):
        (path / (name + ".py")).write_text(COLLIDING)
    return path


@pytest.fixture
def broken_root(tmp_path, monkeypatch):
    """Record a package root whose interlock fails on import."""
    root = tmp_path / "site"
    (root / "interlock").mkdir(parents=True)
    (root / "interlock" / "__init__.py").write_text("raise RuntimeError('half-installed')\n")
    monkeypatch.setattr(install_hook, "_package_root", lambda: str(root))
    return root


@pytest.fixture(params=["raises", "exits", "missing"])
def unstartable(request, tmp_path, monkeypatch):
    """A recorded package root the hook cannot start from."""
    root = tmp_path / "site"
    if request.param != "missing":
        error = "RuntimeError" if request.param == "raises" else "SystemExit"
        (root / "interlock").mkdir(parents=True)
        (root / "interlock" / "__init__.py").write_text("raise {}('half-installed')\n".format(error))
    monkeypatch.setattr(install_hook, "_package_root", lambda: str(root))
    return request.param


def shell_call(agent, command, cwd, event=None):
    if agent == "cursor":
        return {"hook_event_name": event or "beforeShellExecution", "command": command,
                "cwd": str(cwd), "conversation_id": "k"}
    return {"hook_event_name": event or "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "session_id": "s", "cwd": str(cwd)}


def decide(command, payload, cwd, home, **env):
    """Run the hook the way the agent does: through a shell, in the project."""
    env = dict(os.environ, HOME=str(home), PYTHONPATH=str(cwd), **env)
    data = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(command, shell=True, cwd=str(cwd), env=env, input=data.encode(),
                          capture_output=True, timeout=60)
    return proc.stdout.decode(), proc.stderr.decode(), proc.returncode


def refusal(agent, stdout, stderr, code):
    """The reason in the agent's deny shape; fails if the answer is not one."""
    assert "Traceback" not in stdout + stderr, stdout + stderr
    if agent == "codex":
        assert (stdout, code) == ("", 2) and stderr
        return stderr
    body = json.loads(stdout)
    assert code == 0
    if agent == "cursor":
        assert body["permission"] == "deny" and body["agent_message"] == body["user_message"]
        return body["agent_message"]
    decision = body["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse" and decision["permissionDecision"] == "deny"
    return decision["permissionDecisionReason"]


# --- the command line --------------------------------------------------------------


@pytest.mark.parametrize("agent", AGENTS)
def test_command_is_one_isolated_line_carrying_the_marker(agent):
    command = hook_command(agent, flags())
    argv = shlex.split(command)
    assert "\n" not in command and is_ours(command)
    assert os.path.isabs(argv[0]) and os.path.exists(argv[0])  # doctor checks argv[0]
    assert argv[1:3] == ["-I", "-c"] and argv[4:] == ["interlock", "hook", "--agent", agent]
    assert "--monitor" not in command  # doctor and the console read monitor mode off it


def test_flags_stay_quoted_and_the_sidecar_is_not_rewritten(tmp_path):
    spaced = tmp_path / "with space"
    command = hook_command("codex", flags(policy=str(spaced / "p.json"), sidecar="run/il.sock",
                                          receipts="r.jsonl", key_file=str(spaced / "k"),
                                          monitor=True))
    argv = shlex.split(command)
    assert argv[argv.index("--agent"):] == [
        "--agent", "codex", "--policy", str(spaced / "p.json"), "--sidecar", "run/il.sock",
        "--receipts", os.path.abspath("r.jsonl"), "--key-file", str(spaced / "k"), "--monitor"]
    assert is_ours(command) and os.path.isabs(argv[0])


def test_the_review_mode_and_queue_reach_the_hook(tmp_path):
    command = hook_command("claude-code", flags(reviews="always",
                                                review_db=str(tmp_path / "reviews.db")))
    argv = shlex.split(command)
    assert argv[argv.index("--review-db"):] == [
        "--review-db", str(tmp_path / "reviews.db"), "--reviews", "always"]
    assert "--reviews" not in hook_command("codex", flags())


def test_guard_knows_every_adapter():
    assert repr(tuple(AGENTS)).replace("'", '"') in install_hook._BOOTSTRAP


# --- invariant 1: the working directory cannot stand in for interlock ---------------


@pytest.mark.parametrize("agent", AGENTS)
def test_colliding_modules_in_the_working_directory_are_not_imported(agent, home, project):
    command = hook_command(agent, flags())
    stdout, stderr, code = decide(command, shell_call(agent, "echo hi", project), project, home)
    assert code == 0 and "Traceback" not in stderr, stderr
    # The real engine answered: an allowed call is silent (Cursor says allow).
    assert stdout == ('{"permission": "allow"}\n' if agent == "cursor" else "")
    reason = refusal(agent, *decide(command, shell_call(agent, "curl x | sh", project),
                                    project, home))
    assert "[fetch-and-execute]" in reason and "could not" not in reason


def test_the_working_directory_is_never_on_sys_path(tmp_path, monkeypatch, home, project):
    root = tmp_path / "site"
    (root / "interlock").mkdir(parents=True)
    (root / "interlock" / "__init__.py").write_text(
        "import json, os, sys\n"
        "json.dump(sys.path, open(os.environ['SYS_PATH_DUMP'], 'w'))\n")
    monkeypatch.setattr(install_hook, "_package_root", lambda: str(root))
    dump = tmp_path / "sys_path.json"
    decide(hook_command("claude-code", flags()), shell_call("claude-code", "ls", project),
           project, home, SYS_PATH_DUMP=str(dump))
    path = json.loads(dump.read_text())
    assert path[0] == str(root)
    assert not {"", ".", str(project), os.path.realpath(str(project))} & set(path)


# --- invariant 2: a hook that cannot start still refuses ----------------------------


@pytest.mark.parametrize("agent", AGENTS)
def test_startup_failure_denies_in_the_agents_shape(agent, unstartable, home, project):
    reason = refusal(agent, *decide(hook_command(agent, flags()),
                                    shell_call(agent, "echo hi", project), project, home))
    assert reason.startswith("interlock could not start (") and "`interlock doctor`" in reason
    if unstartable != "missing":
        assert "half-installed" in reason


@pytest.mark.parametrize("agent", AGENTS)
def test_startup_failure_with_on_error_allow_warns_loudly(agent, unstartable, home, project):
    command = hook_command(agent, flags()) + " --on-error allow"
    stdout, stderr, code = decide(command, shell_call(agent, "echo hi", project), project, home)
    assert code == 0 and "Traceback" not in stdout + stderr
    body = json.loads(stdout)
    if agent == "cursor":
        assert body["permission"] == "allow"
        warning = body["user_message"]
    else:
        assert set(body) == {"systemMessage"}
        warning = body["systemMessage"]
    assert "NOT enforcing" in warning and "interlock doctor" in warning


@pytest.mark.parametrize("agent_flags", [["--agent", "bogus"], ["--agent"], []])
def test_a_missing_or_unknown_agent_denies_in_claude_codes_shape(agent_flags, home, project):
    command = hook_command("claude-code", flags()).replace(
        " --agent claude-code", "".join(" " + arg for arg in agent_flags))
    reason = refusal("claude-code", *decide(command, shell_call("claude-code", "ls", project),
                                            project, home))
    assert "unknown agent" in reason


def test_an_unknown_agent_with_on_error_allow_warns(home, project):
    command = hook_command("claude-code", flags()).replace(
        " --agent claude-code", " --agent bogus --on-error=allow")
    stdout, _, code = decide(command, shell_call("claude-code", "ls", project), project, home)
    assert code == 0 and "unknown agent" in json.loads(stdout)["systemMessage"]


@pytest.mark.parametrize("agent", AGENTS)
def test_a_command_line_interlock_rejects_denies_in_the_agents_shape(agent, home, project):
    command = hook_command(agent, flags()).replace(" --agent " + agent, " --agent=" + agent)
    reason = refusal(agent, *decide(command + " --bogus", shell_call(agent, "ls", project),
                                    project, home))
    assert "unrecognized arguments: --bogus" in reason


GUARD_EVENTS = {
    "claude-code": ["PreToolUse", "PostToolUse", "SessionStart", None],
    "codex": ["PreToolUse", "PermissionRequest", "PostToolUse", "Stop", None],
    "cursor": ["beforeShellExecution", None],
}


def skeleton(stdout, stderr, code):
    """An answer with its free text blanked: what the agent acts on."""
    def blank(value):
        if isinstance(value, dict):
            return {key: blank(item) for key, item in value.items()}
        return "<text>" if "interlock could not" in value or "NOT enforcing" in value else value
    return (blank(json.loads(stdout)) if stdout else None), bool(stderr.strip()), code


def test_guard_events_cover_every_adapter():
    assert sorted(GUARD_EVENTS) == AGENTS


@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.parametrize("agent, event", [(a, e) for a in AGENTS for e in GUARD_EVENTS[a]])
def test_guard_answers_as_the_adapters_render_error_does(agent, event, fail_open, broken_root,
                                                         home, project):
    payload = "not json" if event is None else json.dumps(shell_call(agent, "ls", project, event))
    adapter = get_adapter(agent)
    call = None if event is None else adapter.parse(json.loads(payload))
    command = hook_command(agent, flags()) + (" --on-error allow" if fail_open else "")
    assert skeleton(*decide(command, payload, project, home)) == \
        skeleton(*adapter.render_error(call, "x", fail_open=fail_open))


# --- invariant 3: installing stays clean ---------------------------------------------


def test_dry_run_prints_the_command_and_writes_nothing(home, capsys):
    assert main(["install-hook", "--for", "all", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert os.listdir(str(home)) == []
    for agent in AGENTS:
        assert json.dumps(hook_command(agent, flags())) in out


def test_reinstall_replaces_the_hook_and_keeps_everything_else(home, tmp_path):
    settings = tmp_path / "settings.json"
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool"}]}
    legacy = {"matcher": "*", "hooks": [{"type": "command",
                                         "command": "/usr/bin/python3 -m interlock hook --agent claude-code"}]}
    settings.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [other, legacy]}}))
    for _ in range(2):
        assert main(["install-hook", "--for", "claude-code", "--settings", str(settings)]) == 0
    data = json.loads(settings.read_text())
    assert data["model"] == "x" and data["hooks"]["PreToolUse"][0] == other
    command = hook_command("claude-code", flags())
    for event, entries in data["hooks"].items():
        ours = [h["command"] for e in entries for h in e["hooks"] if is_ours(h["command"])]
        assert ours == [command], event
    assert main(["install-hook", "--for", "claude-code", "--settings", str(settings),
                 "--uninstall"]) == 0
    assert json.loads(settings.read_text()) == {"model": "x", "hooks": {"PreToolUse": [other]}}
