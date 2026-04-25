"""Dynamic-import abuse guard: block a string argument reaching a module dynamically.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (a plain index-guarded solution with no import machinery), each primitive
the pattern declares, non-string and non-dict input that must be skipped rather
than crashed on, and end-to-end verdicts through the engine.
"""
from typing import Any

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.dynamic_import_guard import (
    PATTERN,
    POLICY_ID,
    dynamic_import_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_dynamic_import_payload_is_blocked():
    decision = dynamic_import_guard()(
        _event(code="importlib.import_module('o'+'s').system('id')")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = dynamic_import_guard()(
        _event(code="importlib.import_module('o'+'s').system('id')")
    )
    assert decision is not None
    assert decision.reason == "dynamic_import: code"


def test_reason_names_whichever_argument_matched():
    decision = dynamic_import_guard()(
        _event(lang="python", snippet="__import__('subprocess').run(cmd)")
    )
    assert decision is not None
    assert decision.reason == "dynamic_import: snippet"


def test_first_matching_argument_wins():
    decision = dynamic_import_guard()(
        _event(a="importlib.import_module('os')", b="__import__('subprocess')")
    )
    assert decision is not None
    assert decision.reason == "dynamic_import: a"


def test_each_declared_primitive_is_blocked():
    payloads = (
        "importlib.import_module('os')",        # importlib attribute
        "mod = __import__('subprocess')",       # __import__ builtin
        "imp.load_source('m', 'payload.py')",   # removed imp.load_* helper
    )
    guard = dynamic_import_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_primitive_embedded_mid_script_is_caught():
    script = (
        "import base64\n"
        "name = base64.b64decode(blob).decode()\n"
        "m = importlib.import_module(name)\n"
    )
    decision = dynamic_import_guard()(_event(code=script))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_plain_import_gets_no_opinion():
    assert dynamic_import_guard()(_event(code="import json")) is None


def test_two_sum_solution_gets_no_opinion():
    solution = (
        "def two_sum(nums, target):\n"
        "    seen = {}\n"
        "    for i, n in enumerate(nums):\n"
        "        if target - n in seen:\n"
        "            return [seen[target - n], i]\n"
        "        seen[n] = i\n"
    )
    assert dynamic_import_guard()(_event(code=solution)) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = dynamic_import_guard()
    assert guard(_event(code="total = sum(values)", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert dynamic_import_guard()(SensorEvent(action="exec_code", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = dynamic_import_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"code": "importlib.import_module('os')"})) is None
    assert guard(_event(argv=["importlib.import_module('os')"])) is None


def test_non_dict_args_get_no_opinion():
    # Deliberately out-of-contract: a caller may hand the sensor anything, and
    # the guard must return no opinion rather than raise.
    none_args: Any = None
    str_args: Any = "importlib.import_module('os')"
    assert dynamic_import_guard()(SensorEvent(action="exec_code", args=none_args)) is None
    assert dynamic_import_guard()(SensorEvent(action="exec_code", args=str_args)) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = dynamic_import_guard()(
        _event(retries=3, code="importlib.import_module('os')")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "dynamic_import"
    assert PATTERN.search("importlib.import_module('os')") is not None
    assert PATTERN.search("__import__('os')") is not None
    assert PATTERN.search("import json") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[dynamic_import_guard()])

    malicious = SensorEvent(
        action="exec_code",
        args={"code": "importlib.import_module('o'+'s').system('id')"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "import json"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
