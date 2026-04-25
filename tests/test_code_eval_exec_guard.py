"""Code eval/exec guard: block a code argument calling a dynamic-execution builtin.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (a comprehension with no builtin gets no opinion), each builtin the pattern
declares, non-string and non-dict input that must be skipped rather than crashed
on, and end-to-end verdicts through the engine.
"""
from typing import Any

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.code_eval_exec_guard import (
    PATTERN,
    POLICY_ID,
    code_eval_exec_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_exec_payload_is_blocked():
    decision = code_eval_exec_guard()(_event(code="exec(base64.b64decode(payload))"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = code_eval_exec_guard()(_event(code="exec(base64.b64decode(payload))"))
    assert decision is not None
    assert decision.reason == "code_eval_exec: code"


def test_reason_names_whichever_argument_matched():
    decision = code_eval_exec_guard()(
        _event(lang="python", snippet="eval(user_input)")
    )
    assert decision is not None
    assert decision.reason == "code_eval_exec: snippet"


def test_first_matching_argument_wins():
    decision = code_eval_exec_guard()(_event(a="exec(x)", b="compile(y, '', 'exec')"))
    assert decision is not None
    assert decision.reason == "code_eval_exec: a"


def test_each_declared_builtin_is_blocked():
    payloads = (
        "exec('import os')",                    # exec
        "eval('1 + 1')",                        # eval
        "compile(src, '<s>', 'exec')",          # compile
        "mod = __import__('subprocess')",       # __import__
    )
    guard = code_eval_exec_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_call_embedded_mid_script_is_caught():
    script = "import os\npayload = os.environ['P']\nexec(payload)\n"
    decision = code_eval_exec_guard()(_event(code=script))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_comprehension_gets_no_opinion():
    assert code_eval_exec_guard()(_event(code="x = [i*i for i in range(5)]")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = code_eval_exec_guard()
    assert guard(_event(code="total = sum(values)", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert code_eval_exec_guard()(SensorEvent(action="exec_code", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = code_eval_exec_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"body": "exec(payload)"})) is None
    assert guard(_event(argv=["exec(payload)"])) is None


def test_non_dict_args_get_no_opinion():
    # Deliberately out-of-contract: a caller may hand the sensor anything, and
    # the guard must return no opinion rather than raise.
    none_args: Any = None
    str_args: Any = "exec(payload)"
    assert code_eval_exec_guard()(SensorEvent(action="exec_code", args=none_args)) is None
    assert code_eval_exec_guard()(SensorEvent(action="exec_code", args=str_args)) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = code_eval_exec_guard()(_event(retries=3, code="exec(payload)"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "code_eval_exec"
    assert PATTERN.search("exec(base64.b64decode(payload))") is not None
    assert PATTERN.search("x = [i*i for i in range(5)]") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[code_eval_exec_guard()])

    malicious = SensorEvent(
        action="exec_code", args={"code": "exec(base64.b64decode(payload))"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(
        action="exec_code", args={"code": "x = [i*i for i in range(5)]"}
    )
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
