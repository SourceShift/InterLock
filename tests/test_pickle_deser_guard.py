"""Unsafe-deserialization guard: block pickle/marshal/yaml.load entry points.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (a safe ``json.loads`` gets no opinion), each deserializer the pattern
declares, the ``yaml.load(..., Loader=...)`` escape hatch, non-string and
non-dict input that must be skipped rather than crashed on, and end-to-end
verdicts through the engine.
"""
from typing import Any

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.pickle_deser_guard import (
    PATTERN,
    POLICY_ID,
    pickle_deser_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_pickle_payload_is_blocked():
    decision = pickle_deser_guard()(
        _event(code="import pickle; pickle.loads(untrusted)")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = pickle_deser_guard()(
        _event(code="import pickle; pickle.loads(untrusted)")
    )
    assert decision is not None
    assert decision.reason == "pickle_deser: code"


def test_reason_names_whichever_argument_matched():
    decision = pickle_deser_guard()(
        _event(lang="python", snippet="marshal.loads(blob)")
    )
    assert decision is not None
    assert decision.reason == "pickle_deser: snippet"


def test_first_matching_argument_wins():
    decision = pickle_deser_guard()(
        _event(a="pickle.loads(x)", b="marshal.loads(y)")
    )
    assert decision is not None
    assert decision.reason == "pickle_deser: a"


def test_each_declared_deserializer_is_blocked():
    payloads = (
        "pickle.loads(data)",                        # pickle
        "cPickle.loads(data)",                       # cPickle
        "marshal.loads(data)",                       # marshal
        "yaml.load(open('c.yaml'))",                 # bare yaml.load
    )
    guard = pickle_deser_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_call_embedded_mid_script_is_caught():
    script = "import pickle\nobj = pickle.loads(request.body)\n"
    decision = pickle_deser_guard()(_event(code=script))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_safe_json_deserialization_gets_no_opinion():
    assert pickle_deser_guard()(_event(code="import json; json.loads(data)")) is None


def test_yaml_load_with_safe_loader_gets_no_opinion():
    assert pickle_deser_guard()(
        _event(code="yaml.load(stream, Loader=yaml.SafeLoader)")
    ) is None


def test_yaml_loader_lookahead_keys_on_the_token_not_its_safety():
    # The lookahead suppresses the match on the ``Loader`` keyword itself, so an
    # explicit loader of any kind is out of scope for this rule - UnsafeLoader
    # included. That is the pattern's declared scope; this pins the behaviour so
    # it cannot drift silently.
    assert pickle_deser_guard()(
        _event(code="yaml.load(stream, Loader=UnsafeLoader)")
    ) is None


def test_unrelated_lookup_gets_no_opinion():
    guard = pickle_deser_guard()
    assert guard(_event(code="obj = mapping.loads['key']", lang="python")) is None


def test_empty_args_get_no_opinion():
    assert pickle_deser_guard()(SensorEvent(action="exec_code", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = pickle_deser_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"body": "pickle.loads(x)"})) is None
    assert guard(_event(argv=["pickle.loads(x)"])) is None


def test_non_dict_args_get_no_opinion():
    # Deliberately out-of-contract: a caller may hand the sensor anything, and
    # the guard must return no opinion rather than raise.
    none_args: Any = None
    str_args: Any = "pickle.loads(x)"
    assert pickle_deser_guard()(SensorEvent(action="exec_code", args=none_args)) is None
    assert pickle_deser_guard()(SensorEvent(action="exec_code", args=str_args)) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = pickle_deser_guard()(_event(retries=3, code="pickle.loads(x)"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "pickle_deser"
    assert PATTERN.search("pickle.loads(untrusted)") is not None
    assert PATTERN.search("import json; json.loads(data)") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[pickle_deser_guard()])

    malicious = SensorEvent(
        action="exec_code", args={"code": "import pickle; pickle.loads(untrusted)"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(
        action="exec_code", args={"code": "import json; json.loads(data)"}
    )
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
