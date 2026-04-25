"""private_ip_egress_guard: block path (private/loopback/link-local IP literals),
allow path (public IP and domain names), non-egress safety, and engine
integration for the SSRF guard."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.private_ip_egress_guard import (
    EGRESS_ACTIONS,
    POLICY_ID,
    private_ip_egress_guard,
)


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- block path -------------------------------------------------------------


def test_loopback_ip_blocks():
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"url": "http://127.0.0.1:8080/steal"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.reason.startswith("private_ip_egress: ")


def test_rfc1918_private_ip_blocks():
    detector = private_ip_egress_guard()
    for url in ("http://10.0.0.5/", "http://192.168.1.10:9200/_search", "http://172.16.4.4/"):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK


def test_link_local_metadata_endpoint_blocks():
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"url": "http://169.254.169.254/latest/meta-data/"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_ipv6_loopback_blocks():
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"url": "http://[::1]:8080/"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_destination_read_from_a_non_url_key_blocks():
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"endpoint": "http://127.0.0.1/admin"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_every_egress_action_is_guarded():
    detector = private_ip_egress_guard()
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"url": "http://127.0.0.1/"}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- allow path -------------------------------------------------------------


def test_public_domain_returns_none():
    # A domain name is not an IP literal: the allowlist's job, so no opinion.
    detector = private_ip_egress_guard()
    assert detector(_event(args={"url": "https://api.example.com/v1"})) is None


def test_public_ip_returns_none():
    detector = private_ip_egress_guard()
    assert detector(_event(args={"url": "https://93.184.216.34/resource"})) is None


def test_non_egress_action_returns_none_even_with_blocked_url():
    detector = private_ip_egress_guard()
    assert detector(_event(action="read_file", args={"url": "http://127.0.0.1/"})) is None


def test_missing_url_returns_none():
    detector = private_ip_egress_guard()
    assert detector(_event(args={"body": "hello"})) is None


def test_blank_url_returns_none():
    detector = private_ip_egress_guard()
    assert detector(_event(args={"url": "   "})) is None


def test_unparseable_host_returns_none():
    # Not an IP literal, not a vettable destination: no opinion, no crash.
    detector = private_ip_egress_guard()
    assert detector(_event(args={"url": "http://999.999.999.999/"})) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = private_ip_egress_guard()
    event = SensorEvent(action="http_post", args=cast(Any, "http://127.0.0.1/"))
    assert detector(event) is None


def test_non_str_destination_is_skipped_and_does_not_crash():
    detector = private_ip_egress_guard()
    event = _event(args={"url": 42, "nested": {"url": "http://127.0.0.1/"}})
    assert detector(event) is None


def test_first_usable_key_wins():
    detector = private_ip_egress_guard()
    # A blank "url" is not usable, so "endpoint" supplies the destination.
    decision = detector(_event(args={"url": "", "endpoint": "http://127.0.0.1/"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_private_egress_and_allows_public():
    engine = PolicyEngine(rules=[private_ip_egress_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "http://127.0.0.1:8080/steal"})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "https://api.example.com/v1"})
    )
    assert allowed.verdict is Verdict.ALLOW
