"""LDAP-injection guard: block smuggled LDAP filter clauses in arguments.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (an ordinary filter value gets no opinion, including one containing the
legitimate bare metacharacters ``*`` and parentheses), each injection fragment
the pattern declares, non-string and non-dict input that must be skipped rather
than crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.ldap_injection_guard import (
    PATTERN,
    POLICY_ID,
    ldap_injection_guard,
)


def _event(**args):
    return SensorEvent(action="ldap_search", args=args)


# --- the block path ---------------------------------------------------------


def test_tautology_rewrite_is_blocked():
    decision = ldap_injection_guard()(_event(filter="uid=*)(objectClass=*"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = ldap_injection_guard()(_event(filter="uid=*)(objectClass=*"))
    assert decision is not None
    assert decision.reason == "ldap_injection: filter"


def test_reason_names_whichever_argument_matched():
    decision = ldap_injection_guard()(
        _event(base_dn="ou=people", filter="uid=*)(objectClass=*")
    )
    assert decision is not None
    assert decision.reason == "ldap_injection: filter"


def test_first_matching_argument_wins():
    decision = ldap_injection_guard()(_event(a="(|(uid=a)(uid=b))", b="uid=*)(objectClass=*"))
    assert decision is not None
    assert decision.reason == "ldap_injection: a"


# --- each injection fragment the pattern declares ---------------------------


def test_each_declared_injection_fragment_is_blocked():
    payloads = (
        "uid=*)(objectClass=*",           # tautology: close, reopen, match-all
        "*)(uid=*",                       # wildcard terminating an assertion
        ")(cn=admin",                     # assertion closed, another opened
        "(|(uid=alice)(uid=bob))",        # explicit union
        "(&(uid=alice)(pw=x))",           # explicit intersection
        "objectClass=*",                  # match-all clause on its own
        "OBJECTCLASS=*",                  # same clause, folded case
    )
    guard = ldap_injection_guard()
    for payload in payloads:
        decision = guard(_event(filter=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- the allow path ---------------------------------------------------------


def test_ordinary_filter_gets_no_opinion():
    assert ldap_injection_guard()(_event(filter="uid=amir")) is None


def test_wildcard_search_gets_no_opinion():
    # A trailing wildcard is ordinary LDAP filter syntax, not injection.
    assert ldap_injection_guard()(_event(filter="uid=amir*")) is None


def test_balanced_equality_filter_gets_no_opinion():
    # Parentheses that the caller legitimately opened and closed are fine.
    assert ldap_injection_guard()(_event(filter="(uid=amir)")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = ldap_injection_guard()
    assert guard(_event(filter="(cn=Alice Smith)", base_dn="ou=people,dc=example,dc=com")) is None


def test_empty_args_get_no_opinion():
    assert ldap_injection_guard()(SensorEvent(action="ldap_search", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = ldap_injection_guard()
    assert guard(_event(filter=None, limit=3)) is None
    assert guard(_event(options={"filter": "uid=*)(objectClass=*"})) is None
    assert guard(_event(filters=["uid=*)(objectClass=*"])) is None


def test_non_dict_args_get_no_opinion():
    assert ldap_injection_guard()(SensorEvent(action="ldap_search", args=None)) is None
    assert ldap_injection_guard()(SensorEvent(action="ldap_search", args="uid=amir")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "filter" is reached.
    decision = ldap_injection_guard()(_event(limit=3, filter="uid=*)(objectClass=*"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "ldap_injection"
    assert PATTERN.search("uid=*)(objectClass=*") is not None
    assert PATTERN.search("uid=amir") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[ldap_injection_guard()])

    malicious = SensorEvent(action="ldap_search", args={"filter": "uid=*)(objectClass=*"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="ldap_search", args={"filter": "uid=amir"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
