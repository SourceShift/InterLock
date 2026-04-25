"""Provenance origin tagging: attach a computed ``__provenance__`` field binding the
event's principal, action and capture time so downstream storage is attributable.

Covers the MODIFY contract (the tag is attached when absent), determinism (identical
envelope yields the identical tag), idempotency (a correctly tagged event yields no
opinion), the abstain path that must return None rather than crash, and end-to-end
merge through the engine - where abstention surfaces as the default ALLOW.
"""
import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.provenance_origin_tag import (
    DEFAULT_SECRET,
    FIELD,
    POLICY_ID,
    provenance_origin_tag,
)


def _event(action="http_post", principal="agent-7", ts=1700000000.0, **args):
    return SensorEvent(action=action, args=args, principal=principal, ts=ts)


def _tag_of(guard, event):
    """Run the rule and return the tag it would attach, or None."""
    decision = guard(event)
    return None if decision is None else decision.modified_args[FIELD]


# --- the modify contract: attach when absent --------------------------------


def test_absent_tag_is_attached_as_modify():
    decision = provenance_origin_tag()(_event(url="https://api.x/y", data="hello"))
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert decision.reason == "provenance_tag"
    assert FIELD in decision.modified_args
    assert isinstance(decision.modified_args[FIELD], str)


def test_tag_records_principal_action_and_time():
    # The tag is the attribution triple, verbatim.
    decision = provenance_origin_tag()(
        _event(action="wire_transfer", principal="agent-7", ts=1700000000.0)
    )
    assert decision.modified_args[FIELD] == "agent-7|wire_transfer|1700000000"


def test_modify_carries_only_the_tag_field():
    # The tag is additive: the original args are neither rewritten nor dropped.
    decision = provenance_origin_tag()(_event(url="https://api.x/y", data="hello"))
    assert set(decision.modified_args) == {FIELD}


def test_tag_is_attached_even_for_an_event_with_no_args():
    decision = provenance_origin_tag()(_event())
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert FIELD in decision.modified_args


def test_ts_is_truncated_to_whole_seconds():
    # int() is specified: sub-second capture jitter must not change the tag.
    guard = provenance_origin_tag()
    a = _tag_of(guard, _event(ts=1700000000.1))
    b = _tag_of(guard, _event(ts=1700000000.9))
    assert a is not None
    assert a == b


# --- determinism ------------------------------------------------------------


def test_same_content_yields_the_same_tag_twice():
    guard = provenance_origin_tag()
    first = _tag_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    second = _tag_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    assert first is not None
    assert first == second


def test_principal_is_part_of_the_tag():
    # Two principals acting identically at the same instant must not share a tag -
    # otherwise the record is not attributable.
    guard = provenance_origin_tag()
    a = _tag_of(guard, _event(principal="agent-7"))
    b = _tag_of(guard, _event(principal="agent-9"))
    assert a is not None
    assert a != b


def test_action_and_time_are_part_of_the_tag():
    guard = provenance_origin_tag()
    base = _tag_of(guard, _event(action="http_get", ts=1700000000.0))
    assert base is not None
    assert base != _tag_of(guard, _event(action="http_post", ts=1700000000.0))
    assert base != _tag_of(guard, _event(action="http_get", ts=1700000001.0))


def test_tag_is_independent_of_args():
    # Derived from the envelope, not the payload: a replayed call with different
    # args under the same identity still carries the same origin tag.
    guard = provenance_origin_tag()
    a = _tag_of(guard, _event(payee="acme", amount="10"))
    b = _tag_of(guard, _event(payee="other", amount="999999"))
    assert a is not None
    assert a == b


# --- idempotency: correct tag present -> no opinion -------------------------


def test_correctly_tagged_event_gets_no_opinion():
    guard = provenance_origin_tag()
    event = _event(url="https://api.x/y", data="hello")

    # First pass attaches the tag...
    decision = guard(event)
    assert decision is not None and decision.verdict is Verdict.MODIFY
    # ...merge it the way the engine would...
    event.args.update(decision.modified_args)
    # ...and re-evaluating the same, now-tagged event is a no-op.
    assert guard(event) is None


def test_stale_wrong_tag_is_replaced():
    # A bogus stored tag does not fool the rule: it recomputes and MODIFYs.
    guard = provenance_origin_tag()
    event = _event(data="hello", **{FIELD: "attacker|http_post|0"})
    decision = guard(event)
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args[FIELD] != "attacker|http_post|0"
    assert decision.modified_args[FIELD] == "agent-7|http_post|1700000000"


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_dict_args_get_no_opinion():
    guard = provenance_origin_tag()
    assert guard(SensorEvent(action="http_post", args=None)) is None
    assert guard(SensorEvent(action="http_post", args="not a dict")) is None
    assert guard(SensorEvent(action="http_post", args=42)) is None


@pytest.mark.parametrize("bad_ts", [None, "not-a-time", object()])
def test_unreadable_ts_is_skipped_not_crashed(bad_ts):
    # int(ts) cannot be taken, so the origin is unknowable: decline, do not raise.
    guard = provenance_origin_tag()
    assert guard(SensorEvent(action="http_post", args={"a": 1}, ts=bad_ts)) is None


def test_nested_and_non_str_values_do_not_crash_and_are_stable():
    guard = provenance_origin_tag()
    args = {"nested": {"a": [1, 2, {"b": None}]}, "n": 7, "flag": True}
    first = _tag_of(guard, SensorEvent(action="write", args=dict(args), ts=1.0))
    second = _tag_of(guard, SensorEvent(action="write", args=dict(args), ts=1.0))
    assert first is not None
    assert first == second


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "provenance_tag"
    assert FIELD == "__provenance__"
    assert DEFAULT_SECRET == b"interlock"


# --- end to end through the engine ------------------------------------------


def test_engine_attaches_tag_for_fresh_event():
    engine = PolicyEngine(rules=[provenance_origin_tag()])
    decision = engine.evaluate(_event(url="https://api.x/y", data="hello"))
    assert decision.verdict is Verdict.MODIFY
    assert FIELD in decision.modified_args
    assert decision.modified_args[FIELD] == "agent-7|http_post|1700000000"


def test_engine_falls_through_to_allow_for_an_untaggable_event():
    # With a non-dict args the rule abstains, so the engine's default ALLOW is what
    # surfaces - the allow path of the allow/modify spectrum.
    engine = PolicyEngine(rules=[provenance_origin_tag()])
    decision = engine.evaluate(SensorEvent(action="write", args=None))
    assert decision.verdict is Verdict.ALLOW
