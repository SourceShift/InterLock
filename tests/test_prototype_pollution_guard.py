"""Prototype-pollution guard: block argument values carrying a pollutable key.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (ordinary config keys get no opinion), each of the three declared
spellings, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.prototype_pollution_guard import (
    PATTERN,
    POLICY_ID,
    prototype_pollution_guard,
)


def _event(**args):
    return SensorEvent(action="merge_config", args=args)


def _event_with_odd_args(args: Any) -> SensorEvent:
    # The robustness tests deliberately hand the guard a non-dict ``args``;
    # the cast documents that this is intended, not a typing mistake.
    return SensorEvent(action="merge_config", args=cast("Any", args))


# --- the block path ---------------------------------------------------------


def test_proto_key_is_blocked():
    decision = prototype_pollution_guard()(
        _event(key="__proto__", value="polluted")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = prototype_pollution_guard()(
        _event(key="__proto__", value="polluted")
    )
    assert decision is not None
    assert decision.reason == "prototype_pollution: key"


def test_reason_names_whichever_argument_matched():
    decision = prototype_pollution_guard()(
        _event(key="theme", patch='{"__proto__": {"isAdmin": true}}')
    )
    assert decision is not None
    assert decision.reason == "prototype_pollution: patch"


def test_first_matching_argument_wins():
    decision = prototype_pollution_guard()(
        _event(a="__proto__", b="constructor.prototype")
    )
    assert decision is not None
    assert decision.reason == "prototype_pollution: a"


def test_each_declared_spelling_is_blocked():
    payloads = (
        "__proto__",              # literal magic key
        "constructor.prototype",  # the same chain via the constructor
        "prototype[",             # indexed assignment onto a prototype
    )
    guard = prototype_pollution_guard()
    for payload in payloads:
        decision = guard(_event(key=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_json_encoded_body_embedding_the_key_is_caught():
    decision = prototype_pollution_guard()(
        _event(body='{"__proto__":{"polluted":true}}')
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_ordinary_config_keys_get_no_opinion():
    assert (
        prototype_pollution_guard()(
            _event(key="theme", value="dark")
        )
        is None
    )


def test_clean_multi_argument_call_gets_no_opinion():
    guard = prototype_pollution_guard()
    assert guard(_event(key="theme", value="dark", scope="user")) is None


def test_the_word_prototype_alone_is_not_a_match():
    # Only the ``constructor.prototype`` spelling is pollutable, not any use
    # of the word.
    assert prototype_pollution_guard()(_event(note="a prototype draft")) is None


def test_case_variant_is_not_a_match():
    # JS property keys are case-sensitive: __PROTO__ is a different key.
    assert prototype_pollution_guard()(_event(key="__PROTO__")) is None


def test_empty_args_get_no_opinion():
    assert (
        prototype_pollution_guard()(SensorEvent(action="merge_config", args={}))
        is None
    )


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = prototype_pollution_guard()
    assert guard(_event(key=None, size=42)) is None
    assert guard(_event(patch={"__proto__": {}})) is None
    assert guard(_event(keys=["__proto__"])) is None


def test_non_dict_args_get_no_opinion():
    guard = prototype_pollution_guard()
    assert guard(_event_with_odd_args(None)) is None
    assert guard(_event_with_odd_args("__proto__")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "key" is reached.
    decision = prototype_pollution_guard()(_event(size=42, key="__proto__"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "prototype_pollution"
    assert PATTERN.search("__proto__") is not None
    assert PATTERN.search("constructor.prototype") is not None
    assert PATTERN.search("prototype[") is not None
    assert PATTERN.search("theme") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[prototype_pollution_guard()])

    malicious = SensorEvent(
        action="merge_config",
        args={"key": "__proto__", "value": "polluted"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(
        action="merge_config",
        args={"key": "theme", "value": "dark"},
    )
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
