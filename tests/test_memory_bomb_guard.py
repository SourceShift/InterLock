"""Memory-bomb guard: block giant allocations before they exhaust memory.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (an ordinary hundred-element allocation gets no opinion), each bomb
fragment the pattern declares, non-string and non-dict input that must be
skipped rather than crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.memory_bomb_guard import (
    PATTERN,
    POLICY_ID,
    memory_bomb_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_repeated_power_of_ten_is_blocked():
    decision = memory_bomb_guard()(_event(code="data = 'x' * 10 ** 9"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = memory_bomb_guard()(_event(code="data = 'x' * 10 ** 9"))
    assert decision is not None
    assert decision.reason == "memory_bomb: code"


def test_reason_names_whichever_argument_matched():
    decision = memory_bomb_guard()(_event(source="ok", payload="[0] * 10 ** 8"))
    assert decision is not None
    assert decision.reason == "memory_bomb: payload"


def test_first_matching_argument_wins():
    decision = memory_bomb_guard()(
        _event(a="bytearray(10 ** 9)", b="[0] * 10 ** 9")
    )
    assert decision is not None
    assert decision.reason == "memory_bomb: a"


# --- each bomb fragment the pattern declares --------------------------------


def test_each_declared_bomb_fragment_is_blocked():
    payloads = (
        "[0] * 10 ** 7",              # low end of the power range
        "'x' * 10 ** 9",              # string repeat bomb
        "[0] * 100000000",            # bare multi-digit count
        "bytearray(10 ** 9)",         # bytearray bomb
        "list(range(10 ** 8))",       # range bomb
    )
    guard = memory_bomb_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_bomb_fragment_matches_regardless_of_spacing():
    decision = memory_bomb_guard()(_event(code="'x'*10**7"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_ordinary_allocation_gets_no_opinion():
    assert memory_bomb_guard()(_event(code="data = [0] * 100")) is None


def test_small_bytearray_and_range_get_no_opinion():
    guard = memory_bomb_guard()
    assert guard(_event(code="bytearray(1024)")) is None
    assert guard(_event(code="list(range(1000))")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = memory_bomb_guard()
    assert guard(_event(code="print('hi')", cwd="/srv/app", retries=3)) is None


def test_empty_args_get_no_opinion():
    assert memory_bomb_guard()(SensorEvent(action="exec_code", args={})) is None


def test_single_digit_power_is_not_a_bomb():
    # 10 ** 6 is a million elements - large, but below the declared threshold.
    assert memory_bomb_guard()(_event(code="[0] * 10 ** 6")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = memory_bomb_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"code": "[0] * 10 ** 9"})) is None
    assert guard(_event(argv=["[0] * 10 ** 9"])) is None


def test_non_dict_args_get_no_opinion():
    assert memory_bomb_guard()(SensorEvent(action="exec_code", args=None)) is None
    assert (
        memory_bomb_guard()(SensorEvent(action="exec_code", args="[0] * 10 ** 9"))
        is None
    )


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = memory_bomb_guard()(_event(retries=3, code="[0] * 10 ** 9"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "memory_bomb"
    assert PATTERN.search("data = 'x' * 10 ** 9") is not None
    assert PATTERN.search("data = [0] * 100") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[memory_bomb_guard()])

    malicious = SensorEvent(
        action="exec_code", args={"code": "data = 'x' * 10 ** 9"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "data = [0] * 100"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
