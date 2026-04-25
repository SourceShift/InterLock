"""Per-event content digest stamp: attach a SHA-256 fingerprint to every event's
args so downstream storage is tamper-evident. Covers the MODIFY contract (a stamp
is attached when absent), determinism (identical content stamps identically),
tamper sensitivity (a changed arg changes the stamp), idempotency (a correctly
stamped event yields no opinion), the robustness paths that must return None
rather than crash, and end-to-end evaluation through the engine."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.content_digest_stamp import (
    DEFAULT_SECRET,
    FIELD,
    POLICY_ID,
    content_digest_stamp,
)


def _event(action="http_post", **args):
    return SensorEvent(action=action, args=args)


def _stamp_of(guard, event):
    """Run the rule and return the digest it would attach, or None."""
    decision = guard(event)
    return None if decision is None else decision.modified_args[FIELD]


# --- the modify contract: attach when absent --------------------------------


def test_absent_digest_is_attached_as_modify():
    decision = content_digest_stamp()(_event(url="https://api.x/y", data="hello"))
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.policy_id == POLICY_ID
    assert FIELD in decision.modified_args
    assert isinstance(decision.modified_args[FIELD], str)
    # A SHA-256 digest is 64 hex characters.
    assert len(decision.modified_args[FIELD]) == 64


def test_modify_carries_only_the_digest_field():
    # The stamp is additive: the original args are not rewritten or dropped.
    decision = content_digest_stamp()(_event(url="https://api.x/y", data="hello"))
    assert set(decision.modified_args) == {FIELD}


def test_digest_is_attached_even_for_an_event_with_no_args():
    # An empty args dict is still digestible: the action name alone is the message.
    decision = content_digest_stamp()(_event())
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert FIELD in decision.modified_args


# --- determinism ------------------------------------------------------------


def test_same_content_yields_the_same_digest_twice():
    guard = content_digest_stamp()
    first = _stamp_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    second = _stamp_of(guard, _event(url="https://api.x/y", data="hello", n=3))
    assert first is not None
    assert first == second


def test_argument_order_does_not_change_the_digest():
    # Dict insertion order is not stable across construction paths; the message
    # is sorted, so two events with the same pairs in different orders agree.
    guard = content_digest_stamp()
    a = _stamp_of(guard, SensorEvent(action="write", args={"a": 1, "b": 2}))
    b = _stamp_of(guard, SensorEvent(action="write", args={"b": 2, "a": 1}))
    assert a is not None
    assert a == b


def test_action_name_is_part_of_the_digested_message():
    # An event replayed under a different action must not carry a valid stamp.
    guard = content_digest_stamp()
    a = _stamp_of(guard, _event(action="http_get", data="hello"))
    b = _stamp_of(guard, _event(action="http_post", data="hello"))
    assert a is not None
    assert a != b


# --- tamper sensitivity -----------------------------------------------------


def test_changing_an_arg_value_changes_the_digest():
    # The whole point: an edit to the args after capture is detectable.
    guard = content_digest_stamp()
    original = _stamp_of(guard, _event(payee="acme", amount="10"))
    tampered = _stamp_of(guard, _event(payee="acme", amount="1000000"))
    assert original is not None
    assert original != tampered


def test_adding_an_arg_changes_the_digest():
    guard = content_digest_stamp()
    before = _stamp_of(guard, _event(payee="acme"))
    after = _stamp_of(guard, _event(payee="acme", extra="injected"))
    assert before is not None
    assert before != after


# --- idempotency: correct digest present -> no opinion -----------------------


def test_correctly_stamped_event_gets_no_opinion():
    guard = content_digest_stamp()
    event = _event(url="https://api.x/y", data="hello")

    # First pass attaches the stamp...
    decision = guard(event)
    assert decision is not None and decision.verdict is Verdict.MODIFY
    # ...merge it in the way the engine would...
    event.args.update(decision.modified_args)
    # ...and re-evaluating the same, now-stamped event is a no-op.
    assert guard(event) is None


def test_stale_wrong_digest_is_replaced():
    # A bogus stored stamp does not fool the rule: it recomputes and MODIFYs.
    guard = content_digest_stamp()
    event = _event(data="hello", **{FIELD: "0" * 64})
    decision = guard(event)
    assert decision is not None
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args[FIELD] != "0" * 64


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_dict_args_get_no_opinion():
    guard = content_digest_stamp()
    assert guard(SensorEvent(action="http_post", args=None)) is None
    assert guard(SensorEvent(action="http_post", args="not a dict")) is None
    assert guard(SensorEvent(action="http_post", args=42)) is None


def test_unorderable_keys_are_skipped_not_crashed():
    # str and int keys cannot be sorted against each other; the rule declines
    # rather than raising mid-flight.
    guard = content_digest_stamp()
    assert guard(SensorEvent(action="write", args={"a": 1, 2: "b"})) is None


def test_nested_and_non_str_values_do_not_crash_and_are_stable():
    guard = content_digest_stamp()
    args = {"nested": {"a": [1, 2, {"b": None}]}, "n": 7, "flag": True}
    first = _stamp_of(guard, SensorEvent(action="write", args=dict(args)))
    second = _stamp_of(guard, SensorEvent(action="write", args=dict(args)))
    assert first is not None
    assert first == second


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "content_digest"
    assert FIELD == "__digest__"
    assert DEFAULT_SECRET == b"interlock"


# --- end to end through the engine ------------------------------------------


def test_engine_attaches_digest_for_fresh_event():
    engine = PolicyEngine(rules=[content_digest_stamp()])
    decision = engine.evaluate(_event(url="https://api.x/y", data="hello"))
    assert decision.verdict is Verdict.MODIFY
    assert FIELD in decision.modified_args


def test_engine_falls_through_to_allow_for_an_undigestible_event():
    # With args that cannot be digested the rule abstains, so the engine's
    # default ALLOW is what surfaces - the allow path of the spectrum.
    engine = PolicyEngine(rules=[content_digest_stamp()])
    decision = engine.evaluate(SensorEvent(action="write", args={"a": 1, 2: "b"}))
    assert decision.verdict is Verdict.ALLOW
