"""SQL-injection guard: block a query argument carrying SQL-injection syntax.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (an ordinary query gets no opinion), each payload shape the pattern
declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.sql_injection_guard import (
    PATTERN,
    POLICY_ID,
    sql_injection_guard,
)


def _event(**args):
    return SensorEvent(action="query", args=args)


# --- the block path ---------------------------------------------------------


def test_stacked_drop_table_payload_is_blocked():
    event = SensorEvent(
        action="query",
        args={"sql": "select * from users where id = 1 OR '1'='1'; drop table users;--"},
    )
    decision = sql_injection_guard()(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    event = SensorEvent(
        action="query",
        args={"sql": "select * from users where id = 1 OR '1'='1'; drop table users;--"},
    )
    decision = sql_injection_guard()(event)
    assert decision is not None
    assert decision.reason == "sql_injection: sql"


def test_reason_names_whichever_argument_matched():
    event = _event(query="select 1", sql="1 union select password from users")
    decision = sql_injection_guard()(event)
    assert decision is not None
    assert decision.reason == "sql_injection: sql"


def test_first_matching_argument_wins():
    event = _event(a="x' or 1=1", b="1; drop table t")
    decision = sql_injection_guard()(event)
    assert decision is not None
    assert decision.reason == "sql_injection: a"


# --- the allow path ---------------------------------------------------------


def test_ordinary_query_gets_no_opinion():
    event = SensorEvent(action="query", args={"sql": "select name from users where id = 5"})
    assert sql_injection_guard()(event) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = sql_injection_guard()
    assert guard(
        _event(sql="select id from orders where status = 'paid'", limit=50, dry_run=True)
    ) is None


def test_empty_args_get_no_opinion():
    assert sql_injection_guard()(SensorEvent(action="query", args={})) is None


# --- payload shapes the pattern declares ------------------------------------


def test_each_declared_payload_shape_is_blocked():
    payloads = (
        "select * from users where name = '' or 1",   # quote-break OR
        "1; drop table users",                        # statement stacking
        "1 union select password from users",          # union data exfil
        "select 1 -- comment",                        # line comment truncation
        "select /* hidden */ 1",                      # block comment
        "exec xp_cmdshell 'whoami'",                  # MSSQL command execution
    )
    guard = sql_injection_guard()
    for payload in payloads:
        decision = guard(_event(sql=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_case_insensitive_keywords_are_caught():
    decision = sql_injection_guard()(_event(sql="1 UNION SELECT password FROM users"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_injection_embedded_mid_value_is_caught():
    decision = sql_injection_guard()(
        _event(sql="select * from t where a = 1 union select secret from keys")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = sql_injection_guard()
    assert guard(_event(sql=None, limit=30)) is None
    assert guard(_event(options={"sql": "1 union select x"})) is None
    assert guard(_event(sql_args=["1; drop table t"])) is None


def test_non_dict_args_get_no_opinion():
    assert sql_injection_guard()(SensorEvent(action="query", args=None)) is None
    assert sql_injection_guard()(SensorEvent(action="query", args="1; drop table t")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "sql" is reached.
    decision = sql_injection_guard()(_event(limit=30, sql="1; drop table users"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "sql_injection"
    assert PATTERN.search("1 union select x") is not None
    assert PATTERN.search("select name from users") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[sql_injection_guard()])

    malicious = SensorEvent(
        action="query",
        args={"sql": "select * from users where id = 1 OR '1'='1'; drop table users;--"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="query", args={"sql": "select name from users where id = 5"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
