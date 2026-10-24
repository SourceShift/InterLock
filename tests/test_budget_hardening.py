"""Hardening contract for the stateful budget and rate rules.

Covers the gaps the original suites did not: a numeric cost that cannot be
added up (NaN, infinity, negative, too large) is refused without poisoning or
refunding the running total; the factory rejects a budget, limit, or window it
cannot compare against; a token event stamped in the future cannot rewind a
principal's rolling window while a genuinely old one still ages out; and every
closure-owned counter adds exactly under concurrent calls because its
read-modify-write is locked.
"""
import threading
import time

import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.call_rate_limiter import (
    POLICY_ID as CALL_RATE_POLICY_ID,
    call_rate_limiter,
)
from interlock.detectors.cost_budget_guard import (
    POLICY_ID as COST_POLICY_ID,
    cost_budget_guard,
)
from interlock.detectors.egress_rate_limiter import (
    POLICY_ID as EGRESS_POLICY_ID,
    egress_rate_limiter,
)
from interlock.detectors.token_budget_guard import (
    POLICY_ID as TOKEN_POLICY_ID,
    estimate_event_tokens,
    token_budget_guard,
)
from interlock.detectors.tool_budget_limiter import (
    POLICY_ID as TOOL_POLICY_ID,
    tool_budget_limiter,
)
from interlock.detectors.write_action_limiter import (
    POLICY_ID as WRITE_POLICY_ID,
    write_action_limiter,
)

# "x" * 50 -> ceil(50 / 4) = 13 tokens under the default chars-per-token ratio.
CHARGED = estimate_event_tokens({"text": "x" * 50})


def _cost_event(cost, action="pay"):
    return SensorEvent(action=action, args={"cost": cost})


def _token_event(ts, principal="agent-1", text="x" * 50):
    return SensorEvent(
        action="call", args={"text": text}, principal=principal, ts=ts
    )


# --- a cost must be finite, non-negative, and addable -----------------------


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf"), -1, -100.0],
    ids=["nan", "inf", "-inf", "negative-int", "negative-float"],
)
def test_malformed_cost_blocks_and_leaves_prior_spend_intact(bad):
    rule = cost_budget_guard(budget=5)

    assert rule(_cost_event(1)) is None

    decision = rule(_cost_event(bad))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == COST_POLICY_ID
    # The reason names the offending value and the policy.
    assert str(bad) in decision.reason
    assert COST_POLICY_ID in decision.reason

    # The malformed event added nothing: 1 + 3 = 4 still fits under 5 ...
    assert rule(_cost_event(3)) is None
    # ... and one more charge takes the honest total over it.
    assert rule(_cost_event(2)) is not None


def test_malformed_cost_first_does_not_poison_the_total():
    rule = cost_budget_guard(budget=5)
    assert rule(_cost_event(float("nan"))) is not None
    # A NaN total would make every later comparison false and never block.
    assert rule(_cost_event(5)) is None
    assert rule(_cost_event(0.1)) is not None


def test_unrepresentably_large_cost_is_refused_not_raised():
    rule = cost_budget_guard(budget=5)
    assert rule(_cost_event(1)) is None
    decision = rule(_cost_event(10**400))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    # No OverflowError escaped and the total survived: 1 + 3 still fits.
    assert rule(_cost_event(3)) is None


def test_non_numeric_costs_still_count_as_zero():
    rule = cost_budget_guard(budget=1)
    for zero in (None, "lots", True, False, {"nested": [1, 2]}, [1, 2]):
        assert rule(_cost_event(zero)) is None
    # None of those advanced the total, so a 1.0 charge still lands on it.
    assert rule(_cost_event(1.0)) is None


def test_non_dict_args_still_counts_as_zero():
    rule = cost_budget_guard(budget=1)
    assert rule(SensorEvent(action="pay", args="cost=99")) is None
    assert rule(_cost_event(1.0)) is None


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf"), -1, -0.5, True],
    ids=["nan", "inf", "-inf", "negative-int", "negative-float", "bool"],
)
def test_malformed_budget_is_refused_at_construction(bad):
    with pytest.raises(ValueError):
        cost_budget_guard(budget=bad)


def test_zero_budget_is_allowed():
    # Non-negative includes zero: everything positive is over it.
    rule = cost_budget_guard(budget=0)
    assert rule(_cost_event(0)) is None
    assert rule(_cost_event(0.1)) is not None


# --- the token window validates its knobs and clamps the future -------------


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), 0, 0.0, -1, -0.5, True],
    ids=["nan", "inf", "zero-int", "zero-float", "negative-int", "negative-float", "bool"],
)
def test_malformed_token_limit_is_refused_at_construction(bad):
    with pytest.raises(ValueError):
        token_budget_guard(limit=bad)


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), 0, 0.0, -1, -0.5, True],
    ids=["nan", "inf", "zero-int", "zero-float", "negative-int", "negative-float", "bool"],
)
def test_malformed_token_window_is_refused_at_construction(bad):
    with pytest.raises(ValueError):
        token_budget_guard(window_s=bad)


def test_future_timestamp_cannot_rewind_the_window():
    rule = token_budget_guard(limit=CHARGED + 1, window_s=60)
    now = time.time()

    assert rule(_token_event(now)) is None
    # One day ahead would trim the real charge out of a 60s window; the clamp
    # keeps it, so the two charges together exceed the limit.
    decision = rule(_token_event(now + 86_400))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == TOKEN_POLICY_ID


def test_old_timestamp_still_ages_out_normally():
    rule = token_budget_guard(limit=CHARGED + 1, window_s=60)
    assert rule(_token_event(0.0)) is None
    # 100s later the first charge has genuinely left the window: no block.
    assert rule(_token_event(100.0)) is None


def test_future_timestamp_clamp_matches_the_clock():
    wait = "x" * 50
    rule = token_budget_guard(limit=estimate_event_tokens({"t": wait}) + 1, window_s=3600)
    # A far-future stamp is pulled back to now, where the prior charge lives.
    assert rule(_token_event(time.time(), text=wait)) is None
    assert rule(_token_event(time.time() + 86_400, text=wait)) is not None


# --- concurrent counters add exactly ----------------------------------------


def _race(workers):
    """Run *workers* concurrently, released together, and wait for all."""
    barrier = threading.Barrier(len(workers))

    def run(worker):
        barrier.wait(timeout=10)
        worker()

    threads = [threading.Thread(target=run, args=(worker,)) for worker in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()


def test_concurrent_cost_charges_are_not_lost():
    threads_count, per_thread = 8, 100
    rule = cost_budget_guard(budget=threads_count * per_thread)
    barrier = threading.Barrier(threads_count)
    unexpected_blocks = []
    results_lock = threading.Lock()

    def charge():
        blocked = 0
        for _ in range(per_thread):
            barrier.wait(timeout=10)
            if rule(_cost_event(1)) is not None:
                blocked += 1
        with results_lock:
            unexpected_blocks.append(blocked)

    _race([charge] * threads_count)

    # Exactly N*M unit charges fit on the inclusive boundary; none was lost.
    assert unexpected_blocks == [0] * threads_count
    assert rule(_cost_event(1)) is not None


_LIMITERS = [
    pytest.param(
        call_rate_limiter,
        lambda: SensorEvent(action="run_tool", principal="p"),
        CALL_RATE_POLICY_ID,
        id="call_rate",
    ),
    pytest.param(
        egress_rate_limiter,
        lambda: SensorEvent(action="http_post", principal="p"),
        EGRESS_POLICY_ID,
        id="egress_rate",
    ),
    pytest.param(
        write_action_limiter,
        lambda: SensorEvent(action="write_file", principal="p"),
        WRITE_POLICY_ID,
        id="write_action",
    ),
    pytest.param(
        tool_budget_limiter,
        lambda: SensorEvent(action="run_tool", principal="p"),
        TOOL_POLICY_ID,
        id="tool_budget",
    ),
]


@pytest.mark.parametrize("factory, event_factory, policy_id", _LIMITERS)
@pytest.mark.parametrize(
    "bad",
    [0, -1, True, float("nan"), 2.0, "3", None],
    ids=["zero", "negative", "bool", "nan", "float", "string", "none"],
)
def test_limiter_rejects_a_malformed_limit(factory, event_factory, policy_id, bad):
    with pytest.raises(ValueError):
        factory(limit=bad)


@pytest.mark.parametrize("factory, event_factory, policy_id", _LIMITERS)
def test_limiter_still_blocks_on_the_call_after_the_limit(
    factory, event_factory, policy_id
):
    rule = factory(limit=2)
    assert rule(event_factory()) is None
    assert rule(event_factory()) is None
    decision = rule(event_factory())
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == policy_id


@pytest.mark.parametrize("factory, event_factory, policy_id", _LIMITERS)
def test_concurrent_limiter_increments_are_not_lost(
    factory, event_factory, policy_id
):
    threads_count, per_thread = 8, 25
    rule = factory(limit=threads_count * per_thread)
    barrier = threading.Barrier(threads_count)
    unexpected_blocks = []
    results_lock = threading.Lock()

    def call():
        blocked = 0
        for _ in range(per_thread):
            barrier.wait(timeout=10)
            if rule(event_factory()) is not None:
                blocked += 1
        with results_lock:
            unexpected_blocks.append(blocked)

    _race([call] * threads_count)

    assert unexpected_blocks == [0] * threads_count
    assert rule(event_factory()) is not None


# --- well-formed events keep today's verdict --------------------------------


def test_engine_still_allows_then_blocks():
    engine = PolicyEngine(rules=[cost_budget_guard(budget=1.0)])
    assert engine.evaluate(_cost_event(0.6)).verdict is Verdict.ALLOW
    assert engine.evaluate(_cost_event(0.4)).verdict is Verdict.ALLOW
    assert engine.evaluate(_cost_event(0.1)).verdict is Verdict.BLOCK
