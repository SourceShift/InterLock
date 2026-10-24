"""Destructive-command guard: block irreversible destructive shell commands.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (routine relative-path cleanup gets no opinion), each destructive
fragment the pattern declares, a value the parser could only partly read
(asked about, unless it also blocks), non-string and non-dict input that must
be skipped rather than crashed on, and end-to-end verdicts through the engine.
"""
import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.destructive_command_guard import (
    PATTERN,
    POLICY_ID,
    destructive_command_guard,
)


def _event(**args):
    return SensorEvent(action="run", args=args)


# --- the block path ---------------------------------------------------------


def test_root_wipe_is_blocked():
    decision = destructive_command_guard()(_event(cmd="rm -rf / --no-preserve-root"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = destructive_command_guard()(_event(cmd="rm -rf / --no-preserve-root"))
    assert decision is not None
    assert decision.reason == "destructive_command: cmd"


def test_reason_names_whichever_argument_matched():
    decision = destructive_command_guard()(_event(program="bash", cmd="mkfs.ext4 /dev/sda1"))
    assert decision is not None
    assert decision.reason == "destructive_command: cmd"


def test_first_matching_argument_wins():
    decision = destructive_command_guard()(_event(a="dd if=/dev/zero of=/dev/sda", b="rm -rf /"))
    assert decision is not None
    assert decision.reason == "destructive_command: a"


# --- each destructive fragment the pattern declares -------------------------


def test_each_declared_destructive_fragment_is_blocked():
    payloads = (
        "rm -rf /",                      # root wipe, end-of-string
        "rm -rf / --no-preserve-root",   # root wipe with flag
        "mkfs.ext4 /dev/sda1",           # reformat a device
        "mkfs /dev/sdb",                 # bare mkfs
        "dd if=/dev/zero of=/dev/sda",   # raw-disk overwrite
        ":(){ :|:& };:",                 # fork bomb
        "cat img > /dev/sda",            # redirect onto a raw disk
        "chmod -R 777 /",                # world-writable whole tree
    )
    guard = destructive_command_guard()
    for payload in payloads:
        decision = guard(_event(cmd=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- the allow path ---------------------------------------------------------


def test_relative_path_remove_gets_no_opinion():
    assert destructive_command_guard()(_event(cmd="rm -rf ./build")) is None


def test_ordinary_command_gets_no_opinion():
    assert destructive_command_guard()(_event(cmd="ls -la /tmp")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = destructive_command_guard()
    assert guard(_event(cmd="make clean", cwd="/srv/app", force=True)) is None


def test_empty_args_get_no_opinion():
    assert destructive_command_guard()(SensorEvent(action="run", args={})) is None


def test_absolute_delete_of_a_named_path_is_not_a_root_wipe():
    # rm -rf /tmp/x removes a path, not the root filesystem - no opinion here.
    assert destructive_command_guard()(_event(cmd="rm -rf /tmp/x")) is None


# --- a value the parser could only partly read --------------------------------


@pytest.mark.parametrize("payload", ['echo "unterminated', "ls 'src", "make && echo $(date",
                                     "bash -c 'rm -r -f /"])  # the act the quote hides is asked about
def test_a_partly_read_value_with_no_critical_intent_escalates(payload):
    decision = destructive_command_guard()(_event(cmd=payload))
    assert decision is not None and decision.verdict is Verdict.ESCALATE
    assert decision.reason == "destructive_command: cmd could not be fully read"
    assert decision.policy_id == POLICY_ID
    assert decision.attributed_to == "cmd"


@pytest.mark.parametrize("payload", ['rm -fr / && echo "x', "rm -rf ~ 'x", 'rm -rf / && echo "x',
                                     'sudo rm -r -f ~ && echo "x'])
def test_a_critical_intent_in_a_partly_read_value_still_blocks(payload):
    decision = destructive_command_guard()(_event(cmd=payload))
    assert decision is not None and decision.verdict is Verdict.BLOCK
    assert decision.reason == "destructive_command: cmd"


def test_a_later_value_that_blocks_beats_an_earlier_unreadable_one():
    decision = destructive_command_guard()(_event(note="it's", cmd="rm -fr /"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.reason == "destructive_command: cmd"


@pytest.mark.parametrize("payload", ["git commit -m \"it's done\"", "echo 'a' \"b\" $(date)"])
def test_a_fully_read_value_with_no_match_is_still_no_opinion(payload):
    assert destructive_command_guard()(_event(cmd=payload)) is None


def test_parse_false_keeps_the_raw_check_alone_and_never_escalates():
    assert destructive_command_guard(parse=False)(_event(cmd='echo "x')) is None


def test_keys_scope_the_scan_to_the_named_arguments():
    guard = destructive_command_guard(keys=["command"])
    assert guard(_event(command="git status", description="Show the repo's status")) is None
    assert guard(_event(command="ls", description="rm -rf /")) is None
    assert guard(_event(command="rm -rf /")).verdict is Verdict.BLOCK
    assert guard(_event(command='echo "x')).verdict is Verdict.ESCALATE


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = destructive_command_guard()
    assert guard(_event(cmd=None, retries=3)) is None
    assert guard(_event(options={"cmd": "rm -rf /"})) is None
    assert guard(_event(argv=["rm", "-rf", "/"])) is None


def test_non_dict_args_get_no_opinion():
    assert destructive_command_guard()(SensorEvent(action="run", args=None)) is None
    assert destructive_command_guard()(SensorEvent(action="run", args="rm -rf /")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "cmd" is reached.
    decision = destructive_command_guard()(_event(retries=3, cmd="rm -rf /"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "destructive_command"
    assert PATTERN.search("rm -rf / --no-preserve-root") is not None
    assert PATTERN.search("rm -rf ./build") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[destructive_command_guard()])

    malicious = SensorEvent(action="run", args={"cmd": "rm -rf / --no-preserve-root"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="run", args={"cmd": "rm -rf ./build"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW

    unreadable = SensorEvent(action="run", args={"cmd": "rm -rf './build"})
    assert engine.evaluate(unreadable).verdict is Verdict.ESCALATE
