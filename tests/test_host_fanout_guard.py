"""host_fanout_guard: the under-limit allow path, the block path on the
(limit+1)th distinct host, the repeat-host exemption, per-rule state isolation,
odd-input safety, and engine integration. Every test asserts on a return value;
none is vacuous.
"""
from typing import Optional, cast

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.host_fanout_guard import (
    POLICY_ID,
    host_fanout_guard,
)


def _event(
    action: str = "http_post",
    url: Optional[str] = "https://a.example/x",
    principal: str = "agent-1",
):
    args = {} if url is None else {"url": url}
    return SensorEvent(action=action, args=args, principal=principal)


# --- allow path: distinct hosts up to the limit return no opinion -----------


def test_two_distinct_hosts_under_limit_return_none():
    rule = host_fanout_guard(limit=2)
    assert rule(_event(url="https://hostA.example/x")) is None
    assert rule(_event(url="https://hostB.example/y")) is None


def test_limit_is_reached_exactly_not_exceeded():
    # limit=1 means exactly one distinct host is covered: the 1st passes, the
    # 2nd distinct host does not. Proves the boundary is `len(seen) >= limit`,
    # not `> limit`.
    rule = host_fanout_guard(limit=1)
    assert rule(_event(url="https://only.example/")) is None
    decision = rule(_event(url="https://other.example/"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- block path: the (limit+1)th distinct host ------------------------------


def test_third_distinct_host_is_blocked():
    rule = host_fanout_guard(limit=2)
    assert rule(_event(url="https://hostA.example/x")) is None
    assert rule(_event(url="https://hostB.example/y")) is None

    decision = rule(_event(url="https://hostC.example/z"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.policy_id == "host_fanout"
    assert decision.reason == "host_fanout_guard: too many distinct hosts"


def test_every_further_new_host_stays_blocked():
    # Once tripped, the guard does not open back up for the next new host.
    rule = host_fanout_guard(limit=2)
    assert rule(_event(url="https://a.example/")) is None
    assert rule(_event(url="https://b.example/")) is None
    for host in ("https://c.example/", "https://d.example/", "https://e.example/"):
        decision = rule(_event(url=host))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


# --- repeat hosts never count ----------------------------------------------


def test_repeating_a_seen_host_is_always_allowed():
    # limit=2 is fully consumed by hostA/hostB. Re-hitting either is a retry,
    # not a new destination, so it must return None even though the set is full.
    rule = host_fanout_guard(limit=2)
    assert rule(_event(url="https://hostA.example/x")) is None
    assert rule(_event(url="https://hostB.example/y")) is None
    assert rule(_event(url="https://hostA.example/other/path")) is None
    assert rule(_event(url="https://hostB.example/y")) is None
    # A brand-new host is still the one that trips it.
    assert cast(Decision, rule(_event(url="https://hostC.example/z"))).verdict is Verdict.BLOCK


def test_repeats_do_not_consume_headroom():
    # Distinctness, not call count: 10 calls to one host leave room for a 2nd
    # distinct host under limit=2.
    rule = host_fanout_guard(limit=2)
    for _ in range(10):
        assert rule(_event(url="https://hostA.example/x")) is None
    assert rule(_event(url="https://hostB.example/y")) is None
    assert cast(Decision, rule(_event(url="https://hostC.example/z"))).verdict is Verdict.BLOCK


def test_same_host_by_case_port_and_path_collapses_to_one():
    # Host identity is the hostname only: scheme, case, port and path differ,
    # but this is one destination, so limit=1 is not exceeded.
    rule = host_fanout_guard(limit=1)
    assert rule(_event(url="https://HostA.example:443/x")) is None
    assert rule(_event(url="http://hosta.example/y")) is None
    assert rule(_event(url="https://HOSTA.EXAMPLE:8443/deep/path?q=1")) is None
    # A genuinely different host still trips it.
    assert cast(Decision, rule(_event(url="https://hostB.example/"))).verdict is Verdict.BLOCK


# --- state isolation between rules -----------------------------------------


def test_second_factory_call_has_a_fresh_set():
    first = host_fanout_guard(limit=1)
    assert first(_event(url="https://a.example/")) is None
    assert cast(Decision, first(_event(url="https://b.example/"))).verdict is Verdict.BLOCK

    second = host_fanout_guard(limit=1)
    # The first rule is tripped; the second owns its own set and is untouched.
    assert second(_event(url="https://a.example/")) is None
    assert cast(Decision, second(_event(url="https://b.example/"))).verdict is Verdict.BLOCK


# --- odd input: skip, never raise -------------------------------------------


def test_non_egress_action_returns_none_without_counting():
    rule = host_fanout_guard(limit=1)
    for _ in range(5):
        assert rule(_event(action="read_file", url="https://a.example/")) is None
    # The reads recorded nothing; the first egress host is still the 1st.
    assert rule(_event(url="https://a.example/")) is None
    assert cast(Decision, rule(_event(url="https://b.example/"))).verdict is Verdict.BLOCK


def test_missing_or_unusable_url_is_skipped():
    rule = host_fanout_guard(limit=1)
    # None url, non-str url, relative URL with no authority, and args=None all
    # bring no host this rule can name; each returns None and records nothing.
    assert rule(_event(action="http_post", url=None)) is None
    assert rule(SensorEvent(action="fetch", args={"url": 123}, principal="a")) is None
    assert rule(SensorEvent(action="fetch", args={"url": ["https://a"]}, principal="a")) is None
    assert rule(SensorEvent(action="fetch", args={"url": "/relative/path"}, principal="a")) is None
    assert rule(SensorEvent(action="fetch", args=None, principal="a")) is None  # type: ignore[arg-type]
    assert rule(SensorEvent(action="fetch", args="notadict", principal="a")) is None  # type: ignore[arg-type]
    # Ceiling is intact: the first real host passes, the second distinct blocks.
    assert rule(_event(url="https://a.example/")) is None
    assert cast(Decision, rule(_event(url="https://b.example/"))).verdict is Verdict.BLOCK


def test_hostile_args_do_not_raise():
    rule = host_fanout_guard(limit=2)
    assert rule(SensorEvent(action="send", args={"url": {"nested": 1}}, principal="a")) is None
    # A malformed IPv6 authority makes urlparse raise; the rule must swallow it.
    assert rule(SensorEvent(action="send", args={"url": "http://[::1"}, principal="a")) is None
    assert rule(SensorEvent(action="send", args={"url": "http://"}, principal="a")) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_the_limit_plus_first_distinct_host():
    limit = 2
    engine = PolicyEngine(rules=[host_fanout_guard(limit=limit)])

    for index in range(limit):
        decision = engine.evaluate(_event(url="https://host{}.example/".format(index)))
        assert decision.verdict is Verdict.ALLOW

    # The (limit+1)th distinct host is the one the engine refuses.
    blocked = engine.evaluate(_event(url="https://host{}.example/".format(limit)))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID


def test_engine_allows_a_repeat_after_reaching_the_limit():
    engine = PolicyEngine(rules=[host_fanout_guard(limit=2)])
    assert engine.evaluate(_event(url="https://a.example/")).verdict is Verdict.ALLOW
    assert engine.evaluate(_event(url="https://b.example/")).verdict is Verdict.ALLOW
    # Revisiting a known host is still ALLOW; only a new one would block.
    assert engine.evaluate(_event(url="https://a.example/retry")).verdict is Verdict.ALLOW
