"""MCP transport guard: per-transport allow/deny, the stdio exception list
(including "refused before launch"), the transport-named refusal reason, and the
fail-closed default for a launch whose transport cannot be determined.

The guard's whole job is to refuse a *transport*, so every test that expects a
refusal asserts the reason names the transport - and, just as importantly, that
it never names the value that triggered it (the value is attacker-influenced;
the reason is durable).
"""
import pytest

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_transport_guard import (
    CONNECT_ACTIONS,
    POLICY_ID,
    mcp_transport_guard,
)


def _connect(args=None, action="mcp.connect"):
    return SensorEvent(action=action, args={} if args is None else args)


# --- allow: a transport in the allow set is left alone -----------------------


def test_allow_a_listed_transport():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    assert guard(_connect({"transport": "stdio", "command": "uvx"})) is None


def test_allow_http_when_http_is_listed():
    guard = mcp_transport_guard(allow={"http"})
    assert guard(_connect({"transport": "http", "url": "https://mcp.example/sse"})) is None


def test_allow_is_membership_not_absence_of_opinion():
    # One guard: the listed transport passes and an unlisted one does not, so
    # the None is the allowlist, not a rule that never fires.
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    assert guard(_connect({"transport": "stdio", "command": "uvx"})) is None
    assert guard(_connect({"transport": "http", "url": "https://evil.example"})) is not None


def test_transport_read_from_the_type_alias():
    # mcp_inventory spells the same field `transport` or `type`; both mean the
    # transport, so an adapter that uses either is judged the same.
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    assert guard(_connect({"type": "stdio", "command": "uvx"})) is None


def test_transport_derived_from_a_url_is_http():
    # No explicit transport, but a url present means http (mcp_inventory's own
    # heuristic); an http-only policy must not admit it by silence.
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"url": "https://mcp.example/sse"}))
    assert decision is not None and "http" in decision.reason


def test_transport_derived_from_a_command_is_stdio():
    guard = mcp_transport_guard(allow={"http"})
    decision = guard(_connect({"command": "uvx", "args": ["server"]}))
    assert decision is not None and "stdio" in decision.reason


# --- refuse: a transport not in the allow set --------------------------------


def test_denied_http_transport_is_refused_with_a_transport_named_reason():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "http", "url": "https://mcp.example/v1"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "http" in decision.reason
    assert decision.attributed_to == "transport"


def test_denied_sse_transport_names_sse():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "sse", "url": "https://mcp.example/sse"}))
    assert decision is not None and "sse" in decision.reason


def test_the_launch_action_is_also_guarded():
    # Refusing a transport is most useful *before* the server starts, which is
    # the `mcp.launch` spelling of the same decision.
    assert "mcp.launch" in CONNECT_ACTIONS
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "http", "url": "https://evil.example"},
                              action="mcp.launch"))
    assert decision is not None and "http" in decision.reason


# --- stdio: the command/args exception list ----------------------------------


def test_stdio_off_list_refused():
    # A stdio launcher whose command is not on the exception list is refused
    # before it can be started.
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "stdio", "command": "curl"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert "stdio" in decision.reason


def test_stdio_refusal_does_not_quote_the_command():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "stdio", "command": "curl --token secret"}))
    assert decision is not None
    assert "curl" not in decision.reason
    assert "secret" not in decision.reason


def test_stdio_exception_matches_the_basename():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    assert guard(
        _connect({"transport": "stdio", "command": "/usr/local/bin/uvx"})
    ) is None


def test_stdio_exception_pair_requires_the_args():
    # A (command, args) exception is the "this exact invocation was reviewed"
    # form: the argv must start with the reviewed args.
    guard = mcp_transport_guard(
        allow={"stdio"},
        stdio_exceptions=[("uvx", ["server-filesystem", "/srv"])],
    )
    reviewed = _connect({
        "transport": "stdio",
        "command": "uvx",
        "args": ["server-filesystem", "/srv", "--readonly"],
    })
    assert guard(reviewed) is None
    other = _connect({
        "transport": "stdio",
        "command": "uvx",
        "args": ["server-filesystem", "/etc"],
    })
    assert guard(other) is not None


def test_blank_stdio_command_is_refused():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    assert guard(_connect({"transport": "stdio", "command": "   "})) is not None


# --- out of scope: non-connect traffic is left alone -------------------------


def test_non_connect_action_has_no_opinion():
    guard = mcp_transport_guard(allow={"http"})
    assert guard(SensorEvent(action="run_shell", args={"cmd": "ls"})) is None
    assert guard(SensorEvent(action="mcp.call", args={"transport": "sse"})) is None


# --- fail-closed: a launch that cannot prove its transport --------------------


def test_launch_without_a_transport_is_refused():
    guard = mcp_transport_guard(allow={"stdio", "http", "sse"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert "(unknown)" in decision.reason


def test_unknown_transport_is_refused_without_naming_the_value():
    guard = mcp_transport_guard(allow={"stdio", "http", "sse"}, stdio_exceptions=["uvx"])
    decision = guard(_connect({"transport": "quic\nsmuggled"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert "quic" not in decision.reason
    assert "smuggled" not in decision.reason


def test_non_dict_args_is_refused_not_raised():
    guard = mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])
    decision = guard(SensorEvent(action="mcp.connect", args=["not", "a", "dict"]))
    assert decision is not None and decision.verdict is Verdict.BLOCK


def test_empty_allow_list_refuses_every_transport():
    # A policy that names nothing admits nothing - the allowlist that fails to
    # load must not fabricate coverage.
    guard = mcp_transport_guard(allow="", stdio_exceptions=["uvx"])
    assert guard(_connect({"transport": "http", "url": "https://x/y"})) is not None


# --- integration: it composes with the engine -------------------------------


def test_guard_blocks_through_the_engine():
    engine = PolicyEngine(rules=[mcp_transport_guard(allow={"stdio"}, stdio_exceptions=["uvx"])])
    blocked = engine.evaluate(_connect({"transport": "http", "url": "https://evil.example"}))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID
    allowed = engine.evaluate(_connect({"transport": "stdio", "command": "uvx"}))
    assert allowed.verdict is Verdict.ALLOW
