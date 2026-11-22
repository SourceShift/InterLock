"""token_budget_guard: allow path (within budget), block path (past the ceiling),
per-principal keying over a rolling window, window expiry, refill, odd-input
safety, the event token stamp, receipt plumbing, and engine integration."""
import pytest
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

    decision = rule(_event())  # 195 + 13 = 208 > 200
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
    # A call that lands exactly on the limit passes, as in the other budget
    # rules; the next one takes the window over it and is refused.
    rule = token_budget_guard(limit=CHARGED, window_s=3600)
    assert rule(_event()) is None
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
    # 30s later the first charge is still inside the window: 13 + 13 > 20.
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


# --- the durable window -----------------------------------------------------
#
# A hook host runs one process per tool call, so every test here builds a FRESH
# rule object over the same state file: that is what the next invocation sees.


def _state(tmp_path):
    return str(tmp_path / "tokens" / "tokens.db")


def test_a_state_file_carries_the_window_to_the_next_process(tmp_path):
    # Two charges of 13 tokens each against a limit of 20: no single process
    # sees both, so only the ledger can refuse the second.
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=3600, state=path)(_event(ts=1_000.0))
    second = token_budget_guard(limit=20, window_s=3600, state=path)
    assert cast(Decision, second(_event(ts=2_000.0))).verdict is Verdict.BLOCK


def test_a_durable_charge_ages_out_of_the_window(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=100, state=path)(_event(ts=1_000.0))
    # 200s later the charge is outside (now - 100, now]: allowance is back.
    later = token_budget_guard(limit=20, window_s=100, state=path)
    assert later(_event(ts=1_200.0)) is None


def test_the_window_boundary_is_half_open(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=100, state=path)(_event(ts=1_000.0))
    # Exactly window_s old: the charge has left the half-open window.
    boundary = token_budget_guard(limit=20, window_s=100, state=path)
    assert boundary(_event(ts=1_100.0)) is None


def test_a_state_file_keeps_principals_apart(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=3600, state=path)(_event(ts=1_000.0))
    other = token_budget_guard(limit=20, window_s=3600, state=path)
    assert other(_event(principal="agent-2", ts=1_000.0)) is None


def test_a_durable_window_ends_up_blocking_until_the_charges_age_out(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=100, state=path)(_event(ts=1_000.0))
    blocked = token_budget_guard(limit=20, window_s=100, state=path)
    assert cast(Decision, blocked(_event(ts=1_050.0))).verdict is Verdict.BLOCK
    freed = token_budget_guard(limit=20, window_s=100, state=path)
    assert freed(_event(ts=1_500.0)) is None


def test_the_state_file_stores_counts_not_text(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=3600, state=path)(
        _event(text="the quick brown fox jumps", ts=1_000.0))
    assert b"the quick brown fox" not in open(path, "rb").read()


def test_a_state_file_bounds_the_scopes(tmp_path):
    path = _state(tmp_path)
    token_budget_guard(limit=20, window_s=3600, state=path, max_scopes=1)(
        _event(principal="agent-1", ts=1_000.0))
    nxt = token_budget_guard(limit=20, window_s=3600, state=path, max_scopes=1)
    nxt(_event(principal="agent-2", ts=1_000.0))       # evicts agent-1
    back = token_budget_guard(limit=20, window_s=3600, state=path, max_scopes=1)
    assert back(_event(principal="agent-1", ts=1_000.0)) is None


def test_no_state_file_is_written_until_a_call_arrives(tmp_path):
    path = tmp_path / "tokens" / "tokens.db"
    token_budget_guard(limit=20, state=str(path))
    assert not path.exists()          # `interlock policy check` must not write


def test_a_corrupt_state_file_falls_back_instead_of_raising(tmp_path):
    path = tmp_path / "tokens" / "tokens.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a sqlite database\n" * 64)
    rule = token_budget_guard(limit=20, window_s=3600, state=str(path))
    assert rule(_event(ts=1_000.0)) is None            # warned, then in memory
    assert cast(Decision, rule(_event(ts=1_000.0))).verdict is Verdict.BLOCK


def test_refill_and_state_are_refused_together(tmp_path):
    with pytest.raises(ValueError):
        token_budget_guard(limit=20, refill=lambda principal, elapsed: 5,
                           state=_state(tmp_path))


@pytest.mark.parametrize("state", ["relative.db", "", "   "])
def test_the_rule_refuses_a_state_path_it_cannot_trust(state):
    with pytest.raises(ValueError):
        token_budget_guard(limit=20, state=state)


@pytest.mark.parametrize("max_scopes", [0, -1, True])
def test_the_rule_refuses_a_max_scopes_it_cannot_use(max_scopes):
    with pytest.raises(ValueError):
        token_budget_guard(limit=20, max_scopes=max_scopes)
