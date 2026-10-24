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


def test_every_special_scheme_spelling_blocks_the_metadata_literal():
    # WHATWG skips any run of / and \ after a special scheme; each spelling
    # reaches 169.254.169.254 in a client, so each must reach this guard as
    # the literal rather than as a bare host:port or an empty value.
    detector = private_ip_egress_guard()
    for url in (
        r"http:/\169.254.169.254/",
        r"http:\169.254.169.254",
        "http:///169.254.169.254/",
        r"https:\\169.254.169.254/",
        "http:169.254.169.254",
        "HTTP://169.254.169.254/",
        "ws://169.254.169.254/",
        "wss://169.254.169.254/",
        "ftp://169.254.169.254/",
        "http://user@169.254.169.254/",
        "http:user@169.254.169.254",
    ):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK, url


def test_legacy_and_mapped_literal_spellings_block():
    # These already reached ip_literal; the new parse must keep them intact.
    detector = private_ip_egress_guard()
    for url in (
        "http://0x7f.1/",
        "http:2130706433",
        "http://0177.0.0.1/",
        "http://[::ffff:169.254.169.254]/",
    ):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK, url


def test_ipv6_loopback_blocks():
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"url": "http://[::1]:8080/"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_backslash_differential_blocks_the_runtime_host():
    # urlparse reads userinfo "169.254.169.254\" and host api.example.com; a
    # runtime ends the authority at the backslash and reaches the metadata IP.
    detector = private_ip_egress_guard()
    decision = detector(
        _event(args={"url": r"http://169.254.169.254\@api.example.com/latest"})
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "url"


def test_carrier_grade_nat_blocks():
    # RFC 6598 reaches cloud metadata services even on interpreters where
    # ipaddress does not call it private.
    detector = private_ip_egress_guard()
    decision = detector(_event(args={"url": "http://100.64.0.1/latest/meta-data"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert "carrier-grade NAT" in decision.reason


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


def test_benign_backslash_counterpart_returns_none():
    # The inverse spelling: the runtime host is the public name, so there is
    # no literal for this guard to refuse.
    detector = private_ip_egress_guard()
    assert detector(
        _event(args={"url": r"http://api.example.com\@169.254.169.254/x"})
    ) is None


def test_forbidden_host_code_points_and_out_of_range_port_return_none():
    # WHATWG rejects these, so there is no literal for this guard to classify
    # and it must not guess at one.
    detector = private_ip_egress_guard()
    for url in (
        "http://169.254.169.254:70000/",
        "http://[::ffff:169.254.169.254]:70000/",
        "http://169.254.169.254<.example/",
        "http://169.254.169.254^/",
        "http://169.254.169.254|/",
    ):
        assert detector(_event(args={"url": url})) is None, url


def test_file_path_is_not_a_network_authority():
    # file: is not a special scheme: `file:169.254.169.254` is a path, not an
    # authority, so the special-scheme skip must not overreach into a block.
    detector = private_ip_egress_guard()
    assert detector(_event(args={"url": "file:169.254.169.254"})) is None


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
