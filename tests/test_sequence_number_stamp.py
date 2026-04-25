"""Monotonic per-rule sequence stamp: attach a ``__seq__`` ordinal to every
event's args so downstream storage can order and attribute what a rule observed.
Covers the MODIFY contract (an ordinal is attached when absent), monotonicity
(distinct content takes strictly increasing values), determinism (identical
content stamps identically every time), idempotency (a correctly stamped event
yields no opinion), the robustness paths that must return None rather than
crash, and end-to-end flow through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.sequence_number_stamp import (
    DEFAULT_SECRET,
    FIELD,
    POLICY_ID,
    sequence_number_stamp,
)


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


def _seq_of(guard, event):
    """Run the rule and return the ordinal it would attach, or None."""
    decision = guard(event)
    return None if decision is None else decision.modified_args[FIELD]


# --- the modify contract: attach when absent --------------------------------


def test_absent_stamp_is_attached_as_modify():
    decision = sequence_number_stamp()(_event(url="https://api.x/y", data="hello"))
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert FIELD in decision.modified_args
    assert isinstance(decision.modified_args[FIELD], int)
    assert not isinstance(decision.modified_args[FIELD], bool)


def test_modify_carries_only_the_stamp_field():
    # The stamp is additive: the original args are not rewritten or dropped.
    decision = sequence_number_stamp()(_event(url="https://api.x/y", data="hello"))
    assert set(decision.modified_args) == {FIELD}


def test_first_ordinal_is_one():
    # The counter starts at 0 and the first observed event takes 1.
    assert _seq_of(sequence_number_stamp(), _event(url="u")) == 1


def test_stamp_is_attached_even_for_an_event_with_no_args():
    # An empty args dict is still stampable: the action name is the content.
    decision = sequence_number_stamp()(_event())
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args[FIELD] == 1


# --- monotonicity: distinct content takes strictly increasing ordinals -------


def test_new_content_gets_strictly_increasing_ordinals():
    guard = sequence_number_stamp()
    seqs = [_seq_of(guard, _event(url="u/{}".format(i))) for i in range(5)]
    assert seqs == [1, 2, 3, 4, 5]


def test_appending_the_counter_observations_are_ordered():
    # A store reading these back knows arrival order from __seq__ alone, with no
    # dependence on ts.
    guard = sequence_number_stamp()
    a = _seq_of(guard, _event(url="u/a"))
    b = _seq_of(guard, _event(url="u/b"))
    c = _seq_of(guard, _event(url="u/c"))
    assert a < b < c


def test_each_rule_instance_counts_independently():
    # The sequence is per rule, not a shared process-global counter.
    first_rule = sequence_number_stamp()
    second_rule = sequence_number_stamp()
    assert _seq_of(first_rule, _event(url="u")) == 1
    assert _seq_of(second_rule, _event(url="u")) == 1


# --- determinism ------------------------------------------------------------


def test_same_content_yields_the_same_ordinal_twice():
    # Re-observing identical content must not consume a new ordinal.
    guard = sequence_number_stamp()
    first = _seq_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    second = _seq_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    assert first is not None
    assert first == second


def test_argument_order_does_not_change_the_ordinal():
    # Dict insertion order is not stable across construction paths; the content
    # key is sorted, so two events with the same pairs in different orders agree.
    guard = sequence_number_stamp()
    a = _seq_of(guard, SensorEvent(action="write", args={"a": 1, "b": 2}))
    b = _seq_of(guard, SensorEvent(action="write", args={"b": 2, "a": 1}))
    assert a is not None
    assert a == b


def test_action_name_is_part_of_the_identity():
    # The same args under a different action are a different observation.
    guard = sequence_number_stamp()
    a = _seq_of(guard, _event(action="http_get", data="hello"))
    b = _seq_of(guard, _event(action="http_post", data="hello"))
    assert a is not None
    assert a != b


def test_secret_does_not_change_the_ordinal():
    # The secret parameter is accepted for interface uniformity but unused.
    a = _seq_of(sequence_number_stamp(b"secret-a"), _event(url="u"))
    b = _seq_of(sequence_number_stamp(b"secret-b"), _event(url="u"))
    assert a == b == 1


# --- idempotency: correct ordinal present -> no opinion ----------------------


def test_correctly_stamped_event_gets_no_opinion():
    guard = sequence_number_stamp()
    event = _event(url="https://api.x/y", data="hello")

    # First pass attaches the ordinal...
    decision = guard(event)
    assert decision is not None and decision.verdict is Verdict.MODIFY
    # ...merge it the way the engine would...
    event.args.update(decision.modified_args)
    # ...and re-evaluating the same, now-stamped event is a no-op.
    assert guard(event) is None


def test_stamp_field_is_excluded_from_identity():
    # If the stamp were part of its own identity, re-evaluating a stamped event
    # would look like new content. It is excluded, so no new ordinal is minted.
    guard = sequence_number_stamp()
    stamped = _event(url="u", **{FIELD: 1})
    assert guard(stamped) is None


def test_stale_stamp_is_replaced():
    # A bogus stored ordinal does not fool the rule: it re-stamps.
    guard = sequence_number_stamp()
    event = _event(url="u", **{FIELD: 999})
    decision = guard(event)
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args[FIELD] == 1


def test_boolean_stamp_is_not_mistaken_for_ordinal_one():
    # True == 1 in Python; a forged boolean must not be accepted as the stamp.
    guard = sequence_number_stamp()
    decision = guard(_event(url="u", **{FIELD: True}))
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args[FIELD] == 1


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_dict_args_get_no_opinion():
    guard = sequence_number_stamp()
    assert guard(SensorEvent(action="http_post", args=None)) is None
    assert guard(SensorEvent(action="http_post", args="not a dict")) is None
    assert guard(SensorEvent(action="http_post", args=42)) is None


def test_nested_and_non_str_values_do_not_crash_and_are_stable():
    guard = sequence_number_stamp()
    args = {"nested": {"a": [1, 2, {"b": None}]}, "n": 7, "flag": True}
    first = _seq_of(guard, SensorEvent(action="write", args=dict(args)))
    second = _seq_of(guard, SensorEvent(action="write", args=dict(args)))
    assert first is not None
    assert first == second


def test_mixed_key_types_are_stringified_not_crashed():
    # str and int keys would be unorderable as keys; stringifying them keeps the
    # rule alive and the identity stable.
    guard = sequence_number_stamp()
    a = _seq_of(guard, SensorEvent(action="write", args={"a": 1, 2: "b"}))
    b = _seq_of(guard, SensorEvent(action="write", args={"a": 1, 2: "b"}))
    assert a is not None
    assert a == b


def test_unrepr_able_value_is_skipped_not_crashed():
    class Hostile:
        def __repr__(self):
            raise RuntimeError("boom")

    guard = sequence_number_stamp()
    assert guard(SensorEvent(action="write", args={"x": Hostile()})) is None


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "sequence_stamp"
    assert FIELD == "__seq__"
    assert DEFAULT_SECRET == b"interlock"


# --- end to end through the engine ------------------------------------------


def test_engine_stamps_a_fresh_event():
    engine = PolicyEngine(rules=[sequence_number_stamp()])
    decision = engine.evaluate(_event(url="https://api.x/y", data="hello"))
    assert decision.verdict is Verdict.MODIFY
    assert FIELD in decision.modified_args
    assert decision.modified_args[FIELD] == 1


def test_engine_merges_the_stamp_over_the_original_args():
    # The MODIFY must not drop the args the policy is inspecting downstream.
    engine = PolicyEngine(rules=[sequence_number_stamp()])
    event = _event(url="https://api.x/y", data="hello")
    decision = engine.evaluate(event)
    merged = dict(event.args)
    merged.update(decision.modified_args)
    assert merged["url"] == "https://api.x/y"
    assert merged[FIELD] == 1


def test_engine_advances_the_ordinal_across_events():
    engine = PolicyEngine(rules=[sequence_number_stamp()])
    seqs = [
        engine.evaluate(_event(url="u/{}".format(i))).modified_args[FIELD]
        for i in range(3)
    ]
    assert seqs == [1, 2, 3]


def test_engine_falls_through_to_allow_for_an_unstampable_event():
    # With args that cannot be fingerprinted the rule abstains, so the engine's
    # default ALLOW is what surfaces - the block side of the allow/block spectrum.
    engine = PolicyEngine(rules=[sequence_number_stamp()])
    decision = engine.evaluate(SensorEvent(action="write", args=None))
    assert decision.verdict is Verdict.ALLOW
