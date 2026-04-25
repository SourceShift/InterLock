"""Code filesystem guard: block a code argument that reaches the filesystem.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (code with no filesystem call gets no opinion), each entry point the
pattern declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from typing import Any

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.code_filesystem_guard import (
    PATTERN,
    POLICY_ID,
    code_filesystem_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_open_payload_is_blocked():
    decision = code_filesystem_guard()(_event(code="open('/etc/passwd').read()"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = code_filesystem_guard()(_event(code="open('/etc/passwd').read()"))
    assert decision is not None
    assert decision.reason == "code_filesystem: code"


def test_reason_names_whichever_argument_matched():
    decision = code_filesystem_guard()(
        _event(lang="python", snippet="shutil.rmtree('/tmp/work')")
    )
    assert decision is not None
    assert decision.reason == "code_filesystem: snippet"


def test_first_matching_argument_wins():
    decision = code_filesystem_guard()(
        _event(a="open('x')", b="pathlib.Path('y').write_text('z')")
    )
    assert decision is not None
    assert decision.reason == "code_filesystem: a"


def test_each_declared_entry_point_is_blocked():
    payloads = (
        "data = open('secret.txt').read()",          # open(
        "os.remove('/tmp/x')",                       # os.remove
        "os.unlink('/tmp/x')",                       # os.unlink
        "os.rmdir('/tmp/d')",                        # os.rmdir
        "os.system('cat /etc/passwd')",              # os.system
        "shutil.copy('/a', '/b')",                   # shutil.
        "pathlib.Path('/tmp').mkdir()",              # pathlib.Path
    )
    guard = code_filesystem_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_call_embedded_mid_script_is_caught():
    script = "import os\nguard = True\nhandle = open('/etc/shadow')\n"
    decision = code_filesystem_guard()(_event(code=script))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_str_methods_get_no_opinion():
    assert code_filesystem_guard()(_event(code="s = 'hello'.upper()")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = code_filesystem_guard()
    assert guard(_event(code="total = sum(values)", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert code_filesystem_guard()(SensorEvent(action="exec_code", args={})) is None


def test_similar_names_do_not_match():
    # ``reopen(`` is not the builtin, and ``os.systemx`` is not the attribute;
    # the word-boundary anchors must keep both out.
    guard = code_filesystem_guard()
    assert guard(_event(code="handle = reopen('f')")) is None
    assert guard(_event(code="os.systemx()")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = code_filesystem_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"body": "open('/etc/passwd')"})) is None
    assert guard(_event(argv=["open('/etc/passwd')"])) is None


def test_non_dict_args_get_no_opinion():
    # Deliberately out-of-contract: a caller may hand the sensor anything, and
    # the guard must return no opinion rather than raise.
    none_args: Any = None
    str_args: Any = "open('/etc/passwd')"
    assert code_filesystem_guard()(SensorEvent(action="exec_code", args=none_args)) is None
    assert code_filesystem_guard()(SensorEvent(action="exec_code", args=str_args)) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = code_filesystem_guard()(_event(retries=3, code="os.remove('/tmp/x')"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "code_filesystem"
    assert PATTERN.search("open('/etc/passwd').read()") is not None
    assert PATTERN.search("s = 'hello'.upper()") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[code_filesystem_guard()])

    malicious = SensorEvent(
        action="exec_code", args={"code": "open('/etc/passwd').read()"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "s = 'hello'.upper()"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
