"""duplicate_call_loop_guard: allow path (repeats within limit), block path
(over limit), reset on a different call, argument-order normalisation, per-rule
state isolation, odd-input safety, and engine integration."""
import pytest
from typing import Any, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.duplicate_call_loop_guard import (
    POLICY_ID,
    duplicate_call_loop_guard,
)


def _event(action: Any = "read_file", args: Any = None):
    if args is None:
        args = {"path": "/etc/hosts"}
    return SensorEvent(action=action, args=args)


# --- allow path -------------------------------------------------------------


def test_two_identical_calls_return_none():
    rule = duplicate_call_loop_guard(limit=2)
    assert rule(_event()) is None  # 1st
    assert rule(_event()) is None  # 2nd, still within the run


def test_single_call_is_never_a_loop():
    rule = duplicate_call_loop_guard(limit=1)
    assert rule(_event()) is None


def test_limit_is_inclusive_at_the_boundary():
    # The Nth repeat passes; only the (N+1)th is refused.
    rule = duplicate_call_loop_guard(limit=3)
    assert rule(_event()) is None
    assert rule(_event()) is None
    assert rule(_event()) is None


# --- block path -------------------------------------------------------------


def test_third_identical_call_blocks():
    rule = duplicate_call_loop_guard(limit=2)
    assert rule(_event()) is None
    assert rule(_event()) is None

    decision = rule(_event())
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "repeated call" in decision.reason


def test_every_call_past_limit_keeps_blocking():
    rule = duplicate_call_loop_guard(limit=1)
    assert rule(_event()) is None
    for _ in range(5):
        assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


# --- reset on a different call ---------------------------------------------


def test_different_call_resets_the_run():
    rule = duplicate_call_loop_guard(limit=2)
    assert rule(_event()) is None
    assert rule(_event()) is None

    # A different call breaks the streak: the counter restarts, so the call that
    # would have blocked is now the first of a fresh run.
    assert rule(_event(action="write_file")) is None
    assert rule(_event()) is None  # same as the original again, but run reset


def test_alternating_calls_never_block():
    # An agent that keeps varying its calls is moving, not stuck.
    rule = duplicate_call_loop_guard(limit=1)
    for _ in range(10):
        assert rule(_event(action="read_file")) is None
        assert rule(_event(action="write_file")) is None


def test_block_clears_after_a_different_call():
    rule = duplicate_call_loop_guard(limit=2)
    assert rule(_event()) is None
    assert rule(_event()) is None
    assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK

    assert rule(_event(action="write_file")) is None
    assert rule(_event()) is None  # fresh run for the original signature


# --- argument-order normalisation ------------------------------------------


def test_arg_order_does_not_make_a_call_different():
    rule = duplicate_call_loop_guard(limit=2)
    a = _event(args={"a": 1, "b": 2})
    b = _event(args={"b": 2, "a": 1})
    assert rule(a) is None
    assert rule(b) is None
    assert cast(Decision, rule(a)).verdict is Verdict.BLOCK


def test_different_args_are_a_different_call():
    rule = duplicate_call_loop_guard(limit=1)
    assert rule(_event(args={"path": "/a"})) is None
    assert rule(_event(args={"path": "/b"})) is None  # different signature


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_fresh_run_state():
    first = duplicate_call_loop_guard(limit=2)
    assert first(_event()) is None
    assert first(_event()) is None
    assert cast(Decision, first(_event())).verdict is Verdict.BLOCK

    second = duplicate_call_loop_guard(limit=2)
    # A brand-new rule starts from zero even though `first` is tripped.
    assert second(_event()) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_are_skipped_not_crashed():
    rule = duplicate_call_loop_guard(limit=1)
    for _ in range(5):
        assert rule(_event(args=cast(Any, "not-a-dict"))) is None


def test_nested_and_odd_argument_values_do_not_crash():
    rule = duplicate_call_loop_guard(limit=1)
    odd = {"nested": {"a": [1, 2, {"b": None}]}, "num": 3, "none": None}
    assert rule(_event(args=odd)) is None
    decision = rule(_event(args=odd))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_non_str_action_does_not_crash():
    rule = duplicate_call_loop_guard(limit=1)
    assert rule(_event(action=cast(Any, 12345))) is None
    assert cast(Decision, rule(_event(action=cast(Any, 12345)))).verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_allows_repeats_then_blocks_over_limit():
    engine = PolicyEngine(rules=[duplicate_call_loop_guard(limit=2)])

    assert engine.evaluate(_event()).verdict is Verdict.ALLOW
    assert engine.evaluate(_event()).verdict is Verdict.ALLOW

    third = engine.evaluate(_event())
    assert third.verdict is Verdict.BLOCK
    assert third.policy_id == POLICY_ID


# --- the durable run --------------------------------------------------------
#
# A hook host runs one process per tool call, so every test here builds a FRESH
# rule object over the same state file: that is what the next invocation sees.
# Without the file each process sees the call as the first of its run, which is
# why the in-process guard can never fire there.


def _state(tmp_path):
    return str(tmp_path / "loop" / "loop.db")


def test_a_state_file_carries_the_run_to_the_next_process(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=2, state=path)(_event())
    duplicate_call_loop_guard(limit=2, state=path)(_event())   # run is 2
    third = duplicate_call_loop_guard(limit=2, state=path)
    assert cast(Decision, third(_event())).verdict is Verdict.BLOCK


def test_a_different_call_in_a_later_process_resets_the_run(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=1, state=path)(_event())
    duplicate_call_loop_guard(limit=1, state=path)(_event(action="write_file"))
    back = duplicate_call_loop_guard(limit=1, state=path)
    assert back(_event()) is None          # the run restarted at one


def test_argument_order_does_not_break_the_durable_run(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=1, state=path)(
        _event(args={"a": 1, "b": 2}))
    second = duplicate_call_loop_guard(limit=1, state=path)
    assert cast(Decision, second(_event(args={"b": 2, "a": 1}))).verdict is Verdict.BLOCK


def test_each_scope_keeps_its_own_run(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=1, state=path)(
        SensorEvent(action="read_file", args={"p": "/x"}, span_id="run-1"))
    other = duplicate_call_loop_guard(limit=1, state=path)
    assert other(SensorEvent(action="read_file", args={"p": "/x"},
                             span_id="run-2")) is None


def test_the_state_file_stores_a_digest_not_the_arguments(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=1, state=path)(
        _event(args={"path": "/secret/do-not-store"}))
    blob = open(path, "rb").read()
    assert b"/secret/do-not-store" not in blob


def test_a_state_file_bounds_the_scopes(tmp_path):
    path = _state(tmp_path)
    duplicate_call_loop_guard(limit=1, state=path, max_scopes=1)(
        SensorEvent(action="read_file", args={"p": "/x"}, span_id="run-1"))
    nxt = duplicate_call_loop_guard(limit=1, state=path, max_scopes=1)
    nxt(SensorEvent(action="read_file", args={"p": "/x"}, span_id="run-2"))
    later = duplicate_call_loop_guard(limit=1, state=path, max_scopes=1)
    assert later(SensorEvent(action="read_file", args={"p": "/x"},
                             span_id="run-1")) is None


def test_no_state_file_is_written_until_a_call_arrives(tmp_path):
    path = tmp_path / "loop" / "loop.db"
    duplicate_call_loop_guard(limit=2, state=str(path))
    assert not path.exists()          # `interlock policy check` must not write


def test_a_corrupt_state_file_falls_back_instead_of_raising(tmp_path):
    path = tmp_path / "loop" / "loop.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a sqlite database\n" * 64)
    rule = duplicate_call_loop_guard(limit=1, state=str(path))
    assert rule(_event()) is None      # warned, then counted in memory
    assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


@pytest.mark.parametrize("state", ["relative.db", "", "   "])
def test_the_rule_refuses_a_state_path_it_cannot_trust(state):
    with pytest.raises(ValueError):
        duplicate_call_loop_guard(limit=2, state=state)


@pytest.mark.parametrize("max_scopes", [0, -1, True])
def test_the_rule_refuses_a_max_scopes_it_cannot_use(max_scopes):
    with pytest.raises(ValueError):
        duplicate_call_loop_guard(limit=2, max_scopes=max_scopes)
