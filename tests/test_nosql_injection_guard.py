"""NoSQL operator-injection guard: block query operators smuggled into args.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (an ordinary scalar filter gets no opinion), each operator the pattern
declares, the JSON-quoted-key shape a real payload uses, non-string and
non-dict input that must be skipped rather than crashed on, and end-to-end
verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.nosql_injection_guard import (
    PATTERN,
    POLICY_ID,
    nosql_injection_guard,
)


def _event(**args):
    return SensorEvent(action="query", args=args)


# --- the block path ---------------------------------------------------------


def test_json_operator_payload_is_blocked():
    decision = nosql_injection_guard()(
        _event(filter='{"password": {"$gt": ""}}')
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = nosql_injection_guard()(
        _event(filter='{"password": {"$gt": ""}}')
    )
    assert decision is not None
    assert decision.reason == "nosql_injection: filter"


def test_reason_names_whichever_argument_matched():
    decision = nosql_injection_guard()(
        _event(collection="users", where='{"$ne": null}')
    )
    assert decision is not None
    assert decision.reason == "nosql_injection: where"


def test_first_matching_argument_wins():
    decision = nosql_injection_guard()(
        _event(a='{"$or": []}', b='{"$where": "1"}')
    )
    assert decision is not None
    assert decision.reason == "nosql_injection: a"


# --- each operator the pattern declares -------------------------------------


def test_each_declared_operator_is_blocked():
    payloads = (
        '{"$where": "this.password"}',   # server-side JS predicate
        '{"$gt": ""}',                   # greater-than wildcard
        '{"$ne": null}',                 # not-equal wildcard
        '{"$regex": "^a"}',              # regex scan
        '{"$or": [{"a": 1}]}',           # boolean tree
        '{"$in": ["admin"]}',            # membership list
        "{'$gt': ''}",                   # single-quoted JSON key
        "$gt: ''",                       # bare operator, colon
        "$ne=1",                         # bare operator, equals
    )
    guard = nosql_injection_guard()
    for payload in payloads:
        decision = guard(_event(filter=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- the allow path ---------------------------------------------------------


def test_plain_scalar_filter_gets_no_opinion():
    assert nosql_injection_guard()(_event(filter="name equals Amir")) is None


def test_dollar_free_text_gets_no_opinion():
    assert nosql_injection_guard()(_event(query="total > 100 and paid = true")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = nosql_injection_guard()
    assert guard(_event(collection="users", filter="active", limit=10)) is None


def test_empty_args_get_no_opinion():
    assert nosql_injection_guard()(SensorEvent(action="query", args={})) is None


def test_similar_but_distinct_operators_are_not_matched():
    # $gte / $nin are not in the declared set; the \b anchor keeps $gt/$in from
    # matching inside them (here they lack a binding colon anyway).
    guard = nosql_injection_guard()
    assert guard(_event(filter="balance $gte 10")) is None
    assert guard(_event(filter="role $nin blocked")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = nosql_injection_guard()
    assert guard(_event(filter=None, limit=5, flag=True)) is None
    assert guard(_event(filter={"password": {"$gt": ""}})) is None
    assert guard(_event(filter=['{"$gt": ""}'])) is None


def test_non_dict_args_get_no_opinion():
    assert nosql_injection_guard()(SensorEvent(action="query", args=None)) is None
    assert nosql_injection_guard()(SensorEvent(action="query", args='{"$gt": ""}')) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "filter" is reached.
    decision = nosql_injection_guard()(
        _event(limit=10, filter='{"password": {"$gt": ""}}')
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "nosql_injection"
    assert PATTERN.search('{"password": {"$gt": ""}}') is not None
    assert PATTERN.search("name equals Amir") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[nosql_injection_guard()])

    malicious = SensorEvent(
        action="query", args={"filter": '{"password": {"$gt": ""}}'}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="query", args={"filter": "name equals Amir"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
