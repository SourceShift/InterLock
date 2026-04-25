"""url_scheme_guard: block path (file/gopher/ftp/dict/data and blank schemes),
allow path (http and https), non-egress safety, odd-input safety, and engine
integration for the egress scheme allowlist."""
from typing import Any, cast

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.url_scheme_guard import (
    EGRESS_ACTIONS,
    POLICY_ID,
    url_scheme_guard,
)


def _event(action="http_post", args=None):
    return SensorEvent(action=action, args=args or {})


# --- block path -------------------------------------------------------------


def test_file_scheme_blocks():
    detector = url_scheme_guard()
    decision = detector(_event(args={"url": "file:///etc/passwd"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.reason.startswith("url_scheme: ")


def test_dangerous_schemes_all_block():
    detector = url_scheme_guard()
    for url in (
        "gopher://internal:70/_POST /x",
        "ftp://files.example.com/dump.tgz",
        "dict://127.0.0.1:2628/show:databases",
        "data:text/html;base64,PHNjcmlwdD4=",
        "file://localhost/etc/shadow",
    ):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK, url
        assert decision.policy_id == POLICY_ID, url


def test_blank_scheme_blocks():
    # A present destination whose parsed scheme is empty: a real egress path
    # with an unvetted scheme, so it blocks rather than slipping through.
    detector = url_scheme_guard()
    for url in ("//api.example.com/v1", "api.example.com/v1"):
        decision = detector(_event(args={"url": url}))
        assert decision is not None, url
        assert decision.verdict is Verdict.BLOCK, url


def test_destination_read_from_a_non_url_key_blocks():
    detector = url_scheme_guard()
    decision = detector(_event(args={"endpoint": "ftp://files.example.com/x"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_scheme_match_is_case_insensitive():
    # "HTTP" is still http: the allowlist compares lower-cased schemes.
    detector = url_scheme_guard()
    assert detector(_event(args={"url": "HTTP://api.example.com/v1"})) is None


def test_every_egress_action_is_guarded():
    detector = url_scheme_guard()
    for action in EGRESS_ACTIONS:
        decision = detector(_event(action=action, args={"url": "file:///etc/passwd"}))
        assert decision is not None, action
        assert decision.verdict is Verdict.BLOCK


# --- allow path -------------------------------------------------------------


def test_https_returns_none():
    detector = url_scheme_guard()
    assert detector(_event(args={"url": "https://api.example.com"})) is None


def test_http_returns_none():
    detector = url_scheme_guard()
    assert detector(_event(args={"url": "http://api.example.com/v1"}) ) is None


def test_non_egress_action_returns_none_even_with_blocked_url():
    detector = url_scheme_guard()
    assert detector(_event(action="read_file", args={"url": "file:///etc/passwd"})) is None


def test_missing_url_returns_none():
    detector = url_scheme_guard()
    assert detector(_event(args={"body": "hello"})) is None


def test_blank_url_returns_none():
    detector = url_scheme_guard()
    assert detector(_event(args={"url": "   "})) is None


def test_unparseable_url_returns_none():
    # Malformed IPv6 brackets raise in urlparse: no opinion, no crash.
    detector = url_scheme_guard()
    assert detector(_event(args={"url": "http://[::1"})) is None


# --- odd-input safety -------------------------------------------------------


def test_non_dict_args_does_not_crash():
    detector = url_scheme_guard()
    event = SensorEvent(action="http_post", args=cast(Any, "file:///etc/passwd"))
    assert detector(event) is None


def test_non_str_destination_is_skipped_and_does_not_crash():
    detector = url_scheme_guard()
    event = _event(args={"url": 42, "nested": {"url": "file:///etc/passwd"}})
    assert detector(event) is None


def test_first_usable_key_wins():
    detector = url_scheme_guard()
    # A blank "url" is not usable, so "endpoint" supplies the destination.
    decision = detector(_event(args={"url": "", "endpoint": "ftp://files.example.com"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_file_scheme_and_allows_https():
    engine = PolicyEngine(rules=[url_scheme_guard()])

    blocked = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "file:///etc/passwd"})
    )
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(
        SensorEvent(action="http_post", args={"url": "https://api.example.com"})
    )
    assert allowed.verdict is Verdict.ALLOW
