"""Per-principal egress rate limiter: the under-limit allow path, the over-limit
block path, per-principal and per-rule isolation, odd-input safety, and engine
integration. Every test asserts on a return value; none is vacuous.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.egress_rate_limiter import (
    POLICY_ID,
    egress_rate_limiter,
)


def _event(action, principal="agent-1", args=None):
    return SensorEvent(
        action=action,
        args=args if args is not None else {},
        principal=principal,
    )


# --- allow path: calls up to the limit return no opinion --------------------


def test_first_calls_under_limit_return_no_opinion():
    rule = egress_rate_limiter(limit=2)
    assert rule(_event("http_post")) is None
    assert rule(_event("fetch")) is None


def test_the_limitth_call_still_passes_strict_greater_than():
    # limit=1 means exactly one egress call is covered: the 1st passes, the 2nd
    # does not. Proves the boundary is `count > limit`, not `count >= limit`.
    rule = egress_rate_limiter(limit=1)
    assert rule(_event("upload")) is None


def test_every_egress_action_shares_the_principals_budget():
    # The counter is per principal, not per action: mixing egress verbs from one
    # principal still consumes the same budget.
    rule = egress_rate_limiter(limit=2)
    assert rule(_event("http_post")) is None
    assert rule(_event("upload")) is None
    decision = rule(_event("send"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- block path: past the limit ---------------------------------------------


def test_over_limit_call_is_blocked():
    rule = egress_rate_limiter(limit=2)
    assert rule(_event("http_post")) is None
    assert rule(_event("http_post")) is None
    decision = rule(_event("http_post"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.policy_id == "egress_rate"
    assert decision.reason == "egress_rate: limit 2 exceeded"


def test_every_call_after_the_limit_is_also_blocked():
    rule = egress_rate_limiter(limit=2)
    for _ in range(2):
        assert rule(_event("http_post")) is None
    for _ in range(3):
        decision = rule(_event("http_post"))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


# --- isolation: principal, non-egress, and per-factory-call state -----------


def test_other_principals_have_their_own_budget():
    # Spending one principal's budget must not consume another's: the counter is
    # keyed by event.principal.
    rule = egress_rate_limiter(limit=1)
    assert rule(_event("http_post", principal="agent-1")) is None
    assert rule(_event("http_post", principal="agent-1")) is not None
    assert rule(_event("http_post", principal="agent-2")) is None


def test_non_egress_actions_do_not_consume_budget():
    rule = egress_rate_limiter(limit=1)
    for _ in range(5):
        assert rule(_event("read_file")) is None
    # The reads spent nothing: the first egress call still passes.
    assert rule(_event("http_post")) is None
    assert rule(_event("http_post")) is not None


def test_second_rule_has_a_fresh_counter():
    first = egress_rate_limiter(limit=2)
    for _ in range(3):
        first(_event("http_post"))

    second = egress_rate_limiter(limit=2)
    # The first rule is still tripped, yet the second is untouched: state lives
    # in the closure, not in a module global.
    assert second(_event("http_post")) is None
    assert second(_event("http_post")) is None
    assert second(_event("http_post")) is not None


# --- odd input: skip, never raise -------------------------------------------


def test_non_str_principal_is_ignored():
    rule = egress_rate_limiter(limit=1)
    for bad in (None, 3, ["agent-1"], {"id": 1}):
        assert rule(_event("http_post", principal=bad)) is None, bad  # type: ignore[arg-type]
    # The skipped events did not consume the budget.
    assert rule(_event("http_post", principal="agent-1")) is None
    assert rule(_event("http_post", principal="agent-1")) is not None


def test_missing_or_hostile_args_do_not_matter():
    rule = egress_rate_limiter(limit=1)
    assert rule(SensorEvent(action="http_post", args=None, principal="a")) is None  # type: ignore[arg-type]
    assert rule(
        SensorEvent(
            action="fetch",
            args={"nested": [1, {"x": None}]},
            principal="a",
        )
    ) is not None


# --- engine integration -----------------------------------------------------


def test_engine_allows_first_then_blocks_second():
    engine = PolicyEngine(rules=[egress_rate_limiter(limit=1)])

    first = engine.evaluate(_event("http_post"))
    assert first.verdict is Verdict.ALLOW

    second = engine.evaluate(_event("http_post"))
    assert second.verdict is Verdict.BLOCK
    assert second.policy_id == POLICY_ID
