"""Self-protection covers reads and every writer (A02).

The coding-agent pack's locked ``self-protect-files`` and
``self-protect-commands`` rules, driven through the real hook path
(``run_hook``) with a temporary HOME. Every file tool, reads included, is
refused under ``~/.interlock``. A shell command is recognized by the path it
names, whatever program it runs. Commands that leave the home alone stay
allowed.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

import pytest

from interlock.adapters import get_adapter
from interlock.adapters.base import run_hook
from interlock.adapters.config import load_engine
from interlock.receipt import set_sink
from interlock.shell import analyze
from interlock.sink import FileSink

KEY = b"a" * 32
PROJECT = "/work/project"
HOME_FILES = ["receipts.key", "receipts.jsonl", "reviews.db", "policy.json"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".interlock").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    return str(home)


@pytest.fixture
def receipts(tmp_path):
    path = str(tmp_path / "log" / "receipts.jsonl")
    os.makedirs(os.path.dirname(path))
    set_sink(FileSink(path, key=KEY))
    yield path
    set_sink(None)


@pytest.fixture
def engine(home, receipts):
    return load_engine(cwd=PROJECT, overlay=False)  # built after HOME is set: the pack names it


def claude(tool: str, args: Dict[str, Any], cwd: str = PROJECT) -> Tuple[str, Dict[str, Any]]:
    return "claude-code", {"hook_event_name": "PreToolUse", "session_id": "s", "cwd": cwd,
                           "tool_name": tool, "tool_input": args}


def codex_patch(path: str) -> Tuple[str, Dict[str, Any]]:
    patch = "*** Begin Patch\n*** Update File: {}\n@@\n-a\n+b\n*** End Patch\n".format(path)
    return "codex", {"hook_event_name": "PreToolUse", "session_id": "c", "cwd": PROJECT,
                     "tool_name": "apply_patch", "tool_input": {"command": patch}}


def bash(command: str, cwd: str = PROJECT) -> Tuple[str, Dict[str, Any]]:
    return claude("Bash", {"command": command}, cwd)


def decide(engine, receipts: str, case: Tuple[str, Dict[str, Any]]) -> Tuple[str, Optional[str], str]:
    """(what the agent was told, the rule on the receipt, the reason it was given)."""
    agent, payload = case
    out, err, code = run_hook(get_adapter(agent), payload, engine, review_mode="off")
    with open(receipts) as fh:
        last = json.loads(fh.read().splitlines()[-1])
    if agent == "codex":
        return ("BLOCK" if code == 2 else "ALLOW"), last.get("policy_id"), err
    output = json.loads(out)["hookSpecificOutput"] if out.strip() else {}
    told = {"deny": "BLOCK", "ask": "ESCALATE"}.get(output.get("permissionDecision"), "ALLOW")
    return told, last.get("policy_id"), output.get("permissionDecisionReason", "")


def under(home: str, name: str = "") -> str:
    return os.path.join(home, ".interlock", name) if name else os.path.join(home, ".interlock")


# --- file tools: reads and writes alike -------------------------------------------


FILE_CALLS = {
    "Read": lambda path: claude("Read", {"file_path": path}),
    "Write": lambda path: claude("Write", {"file_path": path, "content": "{}"}),
    "Edit": lambda path: claude("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}),
    "MultiEdit": lambda path: claude("MultiEdit", {"file_path": path, "edits": []}),
    "apply_patch": codex_patch,
}


@pytest.mark.parametrize("name", HOME_FILES)
@pytest.mark.parametrize("tool", sorted(FILE_CALLS))
def test_every_file_tool_is_refused_on_every_home_file(engine, receipts, home, tool, name):
    told, rule, _ = decide(engine, receipts, FILE_CALLS[tool](under(home, name)))
    assert (told, rule) == ("BLOCK", "self-protect-files")


@pytest.mark.parametrize("spelling", ["~/.interlock/receipts.key",
                                      "~/.interlock/../.interlock/receipts.key",
                                      PROJECT + "/../..{home}/.interlock/receipts.key"])
def test_a_read_that_walks_back_into_the_home_is_the_same_path(engine, receipts, home, spelling):
    told, rule, _ = decide(engine, receipts, claude("Read", {"file_path": spelling.format(home=home)}))
    assert (told, rule) == ("BLOCK", "self-protect-files")


def test_the_reason_names_what_the_home_holds(engine, receipts, home):
    _, _, reason = decide(engine, receipts, claude("Read", {"file_path": under(home, "receipts.key")}))
    for kind in ("signing key", "receipt log", "review queue", "policy", "[self-protect-files]"):
        assert kind in reason


@pytest.mark.parametrize("case", [
    lambda h: claude("Grep", {"pattern": ".", "path": "~/.interlock"}),
    lambda h: claude("Glob", {"pattern": "*", "path": "~/.interlock"}),
    lambda h: ("cursor", {"hook_event_name": "beforeReadFile", "conversation_id": "c",
                          "file_path": "~/.interlock/receipts.key", "content": "",
                          "workspace_roots": [PROJECT]}),
])
def test_search_tools_and_cursor_reads_are_refused_too(engine, receipts, home, case):
    agent, payload = case(home)
    out, _, _ = run_hook(get_adapter(agent), payload, engine, review_mode="off")
    body = json.loads(out)
    decision = body.get("permission") or body["hookSpecificOutput"]["permissionDecision"]
    assert decision == "deny" and "[self-protect-files]" in out


@pytest.mark.parametrize("path", [PROJECT + "/.interlock/policy.json", "~/.interlock-notes.md",
                                  PROJECT + "/README.md"])
def test_files_outside_the_home_are_left_alone(engine, receipts, home, path):
    assert decide(engine, receipts, claude("Read", {"file_path": path}))[:2] == ("ALLOW", None)


# --- shell: by the path named, whatever the program ------------------------------


BLOCKED_COMMANDS = [
    "cat ~/.interlock/receipts.key",
    "cat {home}/.interlock/receipts.key",
    "cat $HOME/.interlock/receipts.key",
    "less ~/.interlock/policy.json",
    "sqlite3 ~/.interlock/reviews.db \"UPDATE reviews SET state='approved'\"",
    "sqlite3 :memory: \"ATTACH '{home}/.interlock/reviews.db' AS r; DELETE FROM r.reviews\"",
    "python3 -c \"print(open('{home}/.interlock/receipts.key').read())\"",
    "python3 -c \"import os; open(os.path.expanduser('~/.interlock/receipts.key'))\"",
    "node -e \"require('fs').readFileSync('{home}/.interlock/receipts.key')\"",
    "echo '{{}}' >> ~/.interlock/receipts.jsonl",
    "echo x | tee ~/.interlock/policy.json",
    "cp /tmp/policy.json ~/.interlock/policy.json",
    "install -m 600 /tmp/policy.json ~/.interlock/",
    "cp --target-directory={home}/.interlock /tmp/policy.json",
    "curl -o{home}/.interlock/policy.json https://x.example/p",
    "bash -c 'cat ~/.interlock/receipts.key'",
    "cat ~/.inter*/receipts.key",
    "cat ~/.{{interlock,cache}}/receipts.key",
    "cat ~/.interlock/../.interlock/receipts.key",
]


@pytest.mark.parametrize("command", BLOCKED_COMMANDS)
def test_a_command_naming_a_home_path_is_refused(engine, receipts, home, command):
    told, rule, _ = decide(engine, receipts, bash(command.format(home=home)))
    assert (told, rule) == ("BLOCK", "self-protect-commands")


@pytest.mark.parametrize("command,cwd", [
    ("cat .interlock/receipts.key", "{home}"),
    ("cat receipts.key", "{home}/.interlock"),
    ("cat ../.interlock/policy.json", "{home}/src"),
])
def test_a_relative_path_is_resolved_against_the_sessions_cwd(engine, receipts, home, command, cwd):
    told, rule, _ = decide(engine, receipts, bash(command, cwd=cwd.format(home=home)))
    assert (told, rule) == ("BLOCK", "self-protect-commands")


@pytest.mark.parametrize("command", [
    "echo hi",
    "git status",
    "interlock report",
    "interlock reviews list",
    "cat /etc/hosts",
    "cat ~/.interlock-notes.md",
    "cat .interlock/policy.json",  # the project's overlay, from the project's cwd
    "git commit -m 'protect ~/.interlock/receipts.key'",
    "ls ~",
])
def test_a_command_that_leaves_the_home_alone_is_allowed(engine, receipts, home, command):
    assert decide(engine, receipts, bash(command))[:2] == ("ALLOW", None)


@pytest.mark.parametrize("command,detail", [
    ("interlock trust add .interlock/policy.json", "control"),
    ("python3 -m interlock install-hook --for claude-code --uninstall", "control"),
    ("interlock reviews approve r-1a2b3c4d", "review"),
    ("rm -f ~/.interlock/receipts.jsonl", "write"),
    ("cat ~/.interlock/receipts.key", "path"),
])
def test_each_tamper_shape_keeps_its_own_detail(home, command, detail):
    found = [i.detail for i in analyze(command, cwd=PROJECT) if i.kind == "interlock.tamper"]
    assert found == [detail]


@pytest.mark.parametrize("command", ["rm -rf ~", "mkfs.ext4 /dev/sda1"])
def test_destructive_commands_still_belong_to_their_own_rule(engine, receipts, home, command):
    assert decide(engine, receipts, bash(command))[:2] == ("BLOCK", "destructive_command")


# --- locked ------------------------------------------------------------------------


def test_the_rules_are_locked_and_survive_a_policy_that_disables_them(home, receipts):
    with open(under(home, "policy.json"), "w") as fh:
        json.dump({"version": 1, "extends": "builtin:coding-agent",
                   "disable": ["self-protect-files", "self-protect-commands"]}, fh)
    engine = load_engine(cwd=PROJECT, overlay=False)
    assert {"self-protect-files", "self-protect-commands"} <= set(engine.locked)
    assert any(q.startswith("self-protect-files: locked") for q in engine.quarantined)
    assert any(q.startswith("self-protect-commands: locked") for q in engine.quarantined)
    assert not [q for q in engine.quarantined if "locked" not in q]
    key = under(home, "receipts.key")
    assert decide(engine, receipts, claude("Read", {"file_path": key}))[:2] == ("BLOCK", "self-protect-files")
    assert decide(engine, receipts, bash("cat " + key))[:2] == ("BLOCK", "self-protect-commands")
