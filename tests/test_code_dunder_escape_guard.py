"""Sandbox dunder-escape guard: block code that walks the Python object graph.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (ordinary code gets no opinion), each escape route the pattern
declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.code_dunder_escape_guard import (
    PATTERN,
    POLICY_ID,
    code_dunder_escape_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_subclasses_walk_is_blocked():
    event = SensorEvent(
        action="exec_code",
        args={"code": "().__class__.__bases__[0].__subclasses__()"},
    )
    decision = code_dunder_escape_guard()(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    event = SensorEvent(
        action="exec_code",
        args={"code": "().__class__.__bases__[0].__subclasses__()"},
    )
    decision = code_dunder_escape_guard()(event)
    assert decision is not None
    assert decision.reason == "code_dunder_escape: code"


def test_reason_names_whichever_argument_matched():
    event = _event(source="print(1)", code="f.__globals__['os']")
    decision = code_dunder_escape_guard()(event)
    assert decision is not None
    assert decision.reason == "code_dunder_escape: code"


def test_first_matching_argument_wins():
    event = _event(a="x.__subclasses__()", b="y.__builtins__")
    decision = code_dunder_escape_guard()(event)
    assert decision is not None
    assert decision.reason == "code_dunder_escape: a"


# --- the allow path ---------------------------------------------------------


def test_ordinary_code_gets_no_opinion():
    event = SensorEvent(action="exec_code", args={"code": "result = sum(range(10))"})
    assert code_dunder_escape_guard()(event) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = code_dunder_escape_guard()
    assert guard(
        _event(code="total = sum(range(10))", timeout=5, dry_run=True)
    ) is None


def test_empty_args_get_no_opinion():
    assert code_dunder_escape_guard()(SensorEvent(action="exec_code", args={})) is None


# --- each escape route the pattern declares ---------------------------------


def test_each_declared_escape_route_is_blocked():
    payloads = (
        "f.__globals__['os'].system('id')",                     # function globals
        "x.__builtins__['__import__']('os')",                   # real builtins
        "''.__class__.__mro__[1].__subclasses__()",             # MRO walk
        "().__class__.__bases__[0].__subclasses__()",           # base walk
        "obj.__subclasses__()",                                 # subclass enum
        "__import__('os').system('id')",                        # direct import
    )
    guard = code_dunder_escape_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_bare_class_attribute_is_not_an_escape_by_itself():
    # ``__class__`` alone is ordinary introspection; the pattern requires the
    # ``__bases__`` pairing before it calls the climb an escape.
    assert code_dunder_escape_guard()(_event(code="print(obj.__class__.__name__)")) is None


def test_escape_embedded_mid_source_is_caught():
    decision = code_dunder_escape_guard()(
        _event(code="import math\nbase = ().__class__.__bases__[0]\nprint(base)")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = code_dunder_escape_guard()
    assert guard(_event(code=None, timeout=30)) is None
    assert guard(_event(options={"code": "x.__subclasses__()"})) is None
    assert guard(_event(code_args=["x.__globals__"])) is None


def test_non_dict_args_get_no_opinion():
    # args is typed Dict[str, Any]; these deliberately violate it to prove the
    # guard skips odd input instead of crashing on it.
    assert code_dunder_escape_guard()(SensorEvent(action="exec_code", args=None)) is None  # type: ignore[arg-type]
    assert (
        code_dunder_escape_guard()(SensorEvent(action="exec_code", args="__subclasses__()"))  # type: ignore[arg-type]
        is None
    )


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = code_dunder_escape_guard()(_event(timeout=30, code="().__class__.__subclasses__()"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "code_dunder_escape"
    assert PATTERN.search("().__class__.__bases__[0].__subclasses__()") is not None
    assert PATTERN.search("result = sum(range(10))") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[code_dunder_escape_guard()])

    malicious = SensorEvent(
        action="exec_code",
        args={"code": "().__class__.__bases__[0].__subclasses__()"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "result = sum(range(10))"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
