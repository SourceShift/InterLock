"""token_budget_guard: allow path (within budget), block path (at the ceiling),
per-principal keying over a rolling window, window expiry, refill, odd-input
safety, the event token stamp, receipt plumbing, and engine integration."""
from typing import Any, cast

from interlock import Blocked, Decision, PolicyEngine, SensorEvent, Verdict, guard, install
from interlock.detectors.token_budget_guard import (
    ANON,
    POLICY_ID,
    estimate_event_tokens,
    token_budget_guard,
)
from interlock.receipt import set_sink
from interlock.sink import InMemorySink
from interlock.tokens import estimate_tokens

# "x" * 50 -> ceil(50 / 4) = 13 tokens under the default ratio.
CHARGED = estimate_tokens("x" * 50)


def _event(principal: Any = "agent-1", text="x" * 50, ts: float = 0.0, action="call"):
    return SensorEvent(action=action, args={"prompt": text}, principal=principal, ts=ts)


# --- allow path -------------------------------------------------------------


def test_calls_within_budget_return_none():
    rule = token_budget_guard(limit=200, window_s=3600)
    # 15 * 13 = 195 < 200: still under the ceiling.
    for _ in range(15):
        assert rule(_event()) is None


def test_non_text_call_spends_nothing():
    rule = token_budget_guard(limit=1, window_s=3600)
    # A call with no string argument estimates 0 tokens and is never blocked.
    for _ in range(5):
        assert rule(SensorEvent(action="ping", args={"n": 3})) is None


# --- block path -------------------------------------------------------------


def test_call_that_reaches_the_ceiling_blocks():
    rule = token_budget_guard(limit=200, window_s=3600)
    for _ in range(15):
        assert rule(_event()) is None

    decision = rule(_event())  # 195 + 13 = 208 >= 200
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "200" in decision.reason


def test_every_call_past_the_ceiling_keeps_blocking():
    rule = token_budget_guard(limit=20, window_s=3600)
    assert rule(_event()) is None  # 13 < 20
    for _ in range(5):
        assert cast(Decision, rule(_event())).verdict is Verdict.BLOCK


def test_budget_is_inclusive_at_the_ceiling():
    # A single call that lands exactly on the limit is the one refused.
    rule = token_budget_guard(limit=CHARGED, window_s=3600)
    decision = rule(_event())
    assert decision is not None and decision.verdict is Verdict.BLOCK


# --- per-principal keying ---------------------------------------------------


def test_each_principal_has_its_own_window():
    rule = token_budget_guard(limit=20, window_s=3600)
    assert rule(_event(principal="a")) is None
    assert rule(_event(principal="b")) is None  # b unaffected by a's charge
    assert cast(Decision, rule(_event(principal="a"))).verdict is Verdict.BLOCK


def test_anonymous_caller_is_still_budgeted():
    rule = token_budget_guard(limit=20, window_s=3600)
    assert rule(_event(principal=None)) is None
    # A non-string principal shares the "<anon>" bucket, so it is capped too.
    assert cast(Decision, rule(_event(principal=42))).verdict is Verdict.BLOCK


def test_factory_calls_have_independent_windows():
    spent = token_budget_guard(limit=20, window_s=3600)
    fresh = token_budget_guard(limit=20, window_s=3600)
    assert spent(_event()) is None
    assert fresh(_event()) is None  # a second rule has its own window
    assert cast(Decision, spent(_event())).verdict is Verdict.BLOCK


# --- rolling window ---------------------------------------------------------


def test_charges_age_out_of_the_window():
    rule = token_budget_guard(limit=20, window_s=60)
    assert rule(_event(ts=0.0)) is None  # 13 < 20
    # 100s later the first charge has left the 60s window, so the cap resets.
    assert rule(_event(ts=100.0)) is None


def test_charges_inside_the_window_still_count():
    rule = token_budget_guard(limit=20, window_s=60)
    assert rule(_event(ts=0.0)) is None
    # 30s later the first charge is still inside the window: 13 + 13 >= 20.
    assert cast(Decision, rule(_event(ts=30.0))).verdict is Verdict.BLOCK


# --- refill -----------------------------------------------------------------


def test_refill_credits_tokens_back():
    rule = token_budget_guard(limit=20, window_s=3600, refill=lambda p, elapsed: 20)
    assert rule(_event(ts=0.0)) is None
    # The credit wipes the earlier charge: 13 - 20 -> 0, then + 13 = 13 < 20.
    assert rule(_event(ts=10.0)) is None


def test_raising_or_odd_refill_is_ignored():
    def boom(principal, elapsed):
        raise RuntimeError("no refill for you")

    for bad in (boom, lambda p, e: "lots", lambda p, e: True, lambda p, e: None):
        rule = token_budget_guard(limit=20, window_s=3600, refill=bad)
        assert rule(_event(ts=0.0)) is None
        # The unusable refill credits nothing, so the cap still trips.
        assert cast(Decision, rule(_event(ts=10.0))).verdict is Verdict.BLOCK


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    rule = token_budget_guard(limit=20, window_s=3600)
    event = SensorEvent(action="call", args=cast(Any, "prompt=hello"))
    assert rule(event) is None


def test_estimate_event_tokens_walks_nested_text():
    args = {"messages": [{"role": "user", "content": "x" * 40}]}
    # "user" (4 chars -> 1) + "x"*40 (40 chars -> 10).
    assert estimate_event_tokens(args) == 11
    assert estimate_event_tokens(None) == 0
    assert estimate_event_tokens("not a dict") == 0


# --- the event token stamp --------------------------------------------------


def test_rule_stamps_the_estimate_on_the_event():
    rule = token_budget_guard(limit=200, window_s=3600)
    event = _event()
    rule(event)
    assert getattr(event, "tokens", None) == CHARGED


# --- receipt plumbing -------------------------------------------------------


def test_receipt_carries_the_token_estimate():
    sink = InMemorySink()
    set_sink(sink)
    install(rules=[token_budget_guard(limit=1000, window_s=3600)])

    @guard()
    def think(prompt):
        return prompt

    think("x" * 50)
    set_sink(None)

    call_receipt = sink.receipts[0]
    assert call_receipt.tokens == CHARGED
    assert '"tokens":{}'.format(CHARGED) in call_receipt.to_json()


def test_receipts_without_an_estimate_omit_the_field():
    sink = InMemorySink()
    set_sink(sink)
    install(rules=[])  # no token-accounting rule -> no estimate

    @guard()
    def think(prompt):
        return prompt

    think("x" * 50)
    set_sink(None)

    assert sink.receipts[0].tokens is None
    assert "tokens" not in sink.receipts[0].to_json()
    assert sink.verify() is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_the_call_that_reaches_the_ceiling():
    engine = PolicyEngine(rules=[token_budget_guard(limit=200, window_s=3600)])

    for _ in range(15):
        assert engine.evaluate(_event()).verdict is Verdict.ALLOW

    blocked = engine.evaluate(_event())
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID


def test_guard_raises_blocked_at_the_ceiling():
    install(rules=[token_budget_guard(limit=200, window_s=3600)])

    @guard()
    def call(prompt: str) -> str:
        return prompt

    for _ in range(15):
        call("x" * 50)
    try:
        call("x" * 50)
    except Blocked as exc:
        assert exc.decision.policy_id == POLICY_ID
    else:  # pragma: no cover - the guard must trip by now
        raise AssertionError("guard never tripped")
