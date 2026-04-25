"""Signal/kill guard: block sandboxed code that signals, kills or forks.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (in-sandbox code gets no opinion), each signalling entry point the pattern
declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.signal_kill_guard import (
    PATTERN,
    POLICY_ID,
    signal_kill_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_os_fork_is_blocked():
    event = SensorEvent(action="exec_code", args={"code": "import os; os.fork()"})
    decision = signal_kill_guard()(event)
    assert decision is not None
    assert isinstance(decision, Decision)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    event = SensorEvent(action="exec_code", args={"code": "import os; os.kill(1, 9)"})
    decision = signal_kill_guard()(event)
    assert decision is not None
    assert decision.reason == "signal_kill: code"


def test_reason_names_whichever_argument_matched():
    event = _event(program="calc", code="os.abort()")
    decision = signal_kill_guard()(event)
    assert decision is not None
    assert decision.reason == "signal_kill: code"


def test_first_matching_argument_wins():
    event = _event(a="os._exit(0)", b="os.fork()")
    decision = signal_kill_guard()(event)
    assert decision is not None
    assert decision.reason == "signal_kill: a"


def test_each_declared_entry_point_is_blocked():
    payloads = (
        "os.kill(1337, signal.SIGKILL)",
        "os.abort()",
        "signal.SIGTERM",
        "os._exit(1)",
        "os.fork()",
    )
    guard = signal_kill_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_signal_embedded_mid_code_is_caught():
    code = "x = 1\nimport os\nos.kill(os.getpid(), 9)\n"
    decision = signal_kill_guard()(_event(code=code))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_benign_arithmetic_gets_no_opinion():
    event = SensorEvent(action="exec_code", args={"code": "y = max(1, 2)"})
    assert signal_kill_guard()(event) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = signal_kill_guard()
    assert guard(_event(code="sum(range(10))", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert signal_kill_guard()(SensorEvent(action="exec_code", args={})) is None


def test_mentioning_signal_module_without_calling_gets_no_opinion():
    # The bare module name is not a signal call; only the call sites are.
    assert signal_kill_guard()(_event(code="import signal")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = signal_kill_guard()
    assert guard(_event(code=123)) is None
    assert guard(_event(code=None, timeout=30)) is None
    assert guard(_event(code={"nested": "os.fork()"})) is None
    assert guard(_event(code=["os.fork()"])) is None


def test_non_dict_args_get_no_opinion():
    assert signal_kill_guard()(SensorEvent(action="exec_code", args=None)) is None
    assert signal_kill_guard()(SensorEvent(action="exec_code", args="os.fork()")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = signal_kill_guard()(_event(timeout=30, code="os.fork()"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "signal_kill"
    assert PATTERN.search("import os; os.fork()") is not None
    assert PATTERN.search("y = max(1, 2)") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[signal_kill_guard()])

    malicious = SensorEvent(action="exec_code", args={"code": "import os; os.fork()"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "y = max(1, 2)"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
