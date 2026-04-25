"""SSTI guard: block server-side template-injection syntax in arguments.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (ordinary values get no opinion), each template dialect the pattern
declares, non-string / non-dict input that must be skipped rather than crashed
on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.ssti_guard import PATTERN, POLICY_ID, ssti_guard


def _event(**args):
    return SensorEvent(action="render", args=args)


# --- the block path ---------------------------------------------------------


def test_template_expression_is_blocked():
    decision = ssti_guard()(_event(name="{{7*7}}{{config.items()}}"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = ssti_guard()(_event(name="{{7*7}}{{config.items()}}"))
    assert decision is not None
    assert decision.reason == "ssti: name"


def test_reason_names_whichever_argument_matched():
    decision = ssti_guard()(_event(title="hello", body="{% import os %}"))
    assert decision is not None
    assert decision.reason == "ssti: body"


def test_first_matching_argument_wins():
    decision = ssti_guard()(_event(a="${process.env}", b="{{config}}"))
    assert decision is not None
    assert decision.reason == "ssti: a"


# --- each dialect the pattern declares --------------------------------------


def test_each_declared_template_dialect_is_blocked():
    payloads = (
        "{{7*7}}",                    # Jinja2 / Twig expression
        "{{config.items()}}",         # Jinja2 attribute access
        "{% import os %}",            # Jinja2 statement
        "${process.env.SECRET}",      # JS template literal / JSP
        "#{7*7}",                     # Ruby / CoffeeScript interpolation
        "prefix {{ x }} suffix",      # embedded, not anchored
    )
    guard = ssti_guard()
    for payload in payloads:
        decision = guard(_event(name=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- the allow path ---------------------------------------------------------


def test_plain_name_gets_no_opinion():
    assert ssti_guard()(SensorEvent(action="render", args={"name": "Amir"})) is None


def test_plain_text_gets_no_opinion():
    assert ssti_guard()(_event(name="Amir Khakshour", greeting="hello world")) is None


def test_lone_braces_get_no_opinion():
    # A single brace, or a pair with no closing partner, is not an expression.
    assert ssti_guard()(_event(template="total { unmatched")) is None
    assert ssti_guard()(_event(template="price is $5")) is None


def test_empty_args_get_no_opinion():
    assert ssti_guard()(SensorEvent(action="render", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = ssti_guard()
    assert guard(_event(name=None, count=3, ratio=1.5, ok=True)) is None
    assert guard(_event(payload={"name": "{{7*7}}"})) is None
    assert guard(_event(payload=["{{7*7}}"])) is None


def test_non_dict_args_get_no_opinion():
    assert ssti_guard()(SensorEvent(action="render", args=None)) is None
    assert ssti_guard()(SensorEvent(action="render", args="{{7*7}}")) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int/None must be skipped, not abort the scan before "name" is reached.
    decision = ssti_guard()(_event(count=3, name="{{7*7}}"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "ssti"
    assert PATTERN.search("{{7*7}}{{config.items()}}") is not None
    assert PATTERN.search("Amir") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[ssti_guard()])

    malicious = SensorEvent(action="render", args={"name": "{{7*7}}{{config.items()}}"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="render", args={"name": "Amir"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
