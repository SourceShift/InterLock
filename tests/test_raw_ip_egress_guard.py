"""raw_ip_egress_guard: block path (any bare IP literal), allow path (named
hosts), non-egress safety, odd-input safety, and engine integration."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.raw_ip_egress_guard import (
    DESTINATION_KEYS,
    EGRESS_ACTIONS,
    POLICY_ID,
    raw_ip_egress_guard,
)


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- block path -------------------------------------------------------------


def test_public_ip_literal_blocks():
    # The technique's headline case: a public IP defeats a DNS-rebinding
    # allowlist just as a private one defeats an SSRF allowlist.
    detector = raw_ip_egress_guard()
    decision = detector(_event(args={"url": "https://93.184.216.34/collect"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.reason.startswith("raw_ip_egress: ")


def test_private_ip_literal_blocks_too():
    detector = raw_ip_egress_guard()
    for url in ("http://10.0.0.5/", "http://127.0.0.1:8080/steal", "http://169.254.169.254/latest/meta-data/"):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK


def test_ipv6_literal_blocks():
    detector = raw_ip_egress_guard()
    decision = detector(_event(args={"url": "http://[2001:db8::1]:8080/x"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_bare_host_without_scheme_blocks():
    # urlparse cannot resolve a hostname without a scheme; the guard splits by
    # hand so a scheme-less literal is still caught.
    detector = raw_ip_egress_guard()
    decision = detector(_event(args={"host": "93.184.216.34"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_destination_read_from_every_supported_key():
    detector = raw_ip_egress_guard()
    for key in DESTINATION_KEYS:
        decision = detector(_event(args={key: "http://93.184.216.34/"}))
        assert decision is not None, key
        assert decision.verdict is Verdict.BLOCK


def test_every_egress_action_is_guarded():
    detector = raw_ip_egress_guard()
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"url": "http://93.184.216.34/"}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- allow path -------------------------------------------------------------


def test_named_host_returns_none():
    # A named host is the allowlist's business, not ours: no opinion.
    detector = raw_ip_egress_guard()
    assert detector(_event(args={"url": "https://example.com/collect"})) is None


def test_named_host_with_port_and_path_returns_none():
    detector = raw_ip_egress_guard()
    assert detector(_event(args={"url": "https://api.example.com:8443/v1/collect"})) is None


def test_non_egress_action_returns_none_even_with_blocked_url():
    detector = raw_ip_egress_guard()
    assert detector(_event(action="read_file", args={"url": "https://93.184.216.34/"})) is None


def test_missing_url_returns_none():
    detector = raw_ip_egress_guard()
    assert detector(_event(args={"body": "hello"})) is None


def test_blank_url_returns_none():
    detector = raw_ip_egress_guard()
    assert detector(_event(args={"url": "   "})) is None


def test_unparseable_host_returns_none():
    # Not a valid IP literal (octets out of range), not a vettable destination.
    detector = raw_ip_egress_guard()
    assert detector(_event(args={"url": "http://999.999.999.999/"})) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = raw_ip_egress_guard()
    event = SensorEvent(action="http_post", args=cast(Any, "https://93.184.216.34/"))
    assert detector(event) is None


def test_non_str_destination_is_skipped_and_does_not_crash():
    detector = raw_ip_egress_guard()
    event = _event(args={"url": 42, "nested": {"url": "https://93.184.216.34/"}})
    assert detector(event) is None


def test_first_usable_key_wins():
    detector = raw_ip_egress_guard()
    # A blank "url" is not usable, so "endpoint" supplies the destination.
    decision = detector(_event(args={"url": "", "endpoint": "https://93.184.216.34/"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_raw_ip_and_allows_named_host():
    engine = PolicyEngine(rules=[raw_ip_egress_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "https://93.184.216.34/collect"})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "https://example.com/collect"})
    )
    assert allowed.verdict is Verdict.ALLOW
