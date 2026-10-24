"""A trust label cannot be forged by the model.

The MCP trust detectors resolve the server (``__origin__``), its schema
(``__schema__``), attestation (``__attestation__``) and listing (``__tools__``)
from the event's trusted ``labels`` mapping. That mapping is set only by
interlock's own integration code. Every path that accepts model-produced
arguments - an agent hook payload, a sidecar frame, ``@guard``'s ``**kwargs`` -
strips the reserved keys before an event is built, so a model that writes
``{"__origin__": "github"}`` cannot claim a trusted server.

For an event an integration built by hand, the ``args`` fallback is retained
and documented: that is the only source a model never touches.
"""
from __future__ import annotations

import asyncio

import pytest

from interlock import (
    Blocked,
    PolicyEngine,
    SensorEvent,
    Verdict,
    enforce_tool_call,
    guard,
    guard_mcp_session,
)
from interlock.adapters import get_adapter, run_hook
from interlock.detectors.mcp_server_attestation import (
    attestation_for,
    mcp_server_attestation,
)
from interlock.detectors.mcp_surface_baseline import mcp_surface_baseline
from interlock.detectors.mcp_tool_pinning import mcp_tool_pinning, pin_of
from interlock.detectors.mcp_trust_registry import mcp_trust_registry
from interlock.event import TRUST_LABELS, strip_trust_labels
from interlock.interceptors.mcp import TRUST_LABELS as MCP_TRUST_LABELS
from interlock.wire import PROTOCOL_VERSION, WireError, parse_request

ORIGIN = "github"
SCHEMA = '{"name": "create_issue", "inputSchema": {"type": "object"}}'
LISTING = [{"name": "create_issue", "description": "File an issue", "input": {}}]
TOKEN = "identity-token-4f2b7c9a"


class EchoSession:
    """An MCP client session stand-in that records what the server receives."""

    def __init__(self, result=None):
        self.received = []
        self.result = result if result is not None else "ok"

    async def call_tool(self, name, arguments=None, *rest, **kw):
        self.received.append((name, arguments))
        return self.result


def _engine(*rules):
    return PolicyEngine(rules=list(rules))


def _claude_payload(tool, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "session_id": "s1",
        "cwd": "/work/proj",
        "tool_use_id": "tu1",
    }


def _codex_payload(tool, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "session_id": "c1",
        "cwd": "/work/proj",
    }


def _request_frame(action, args):
    return {"v": PROTOCOL_VERSION, "id": "req-1",
            "event": {"action": action, "args": args}}


# --- the helper ---------------------------------------------------------------


def test_strip_trust_labels_copies_the_other_keys_and_never_mutates():
    args = {"path": "/tmp/x", "__origin__": ORIGIN, "__schema__": SCHEMA,
            "__attestation__": TOKEN, "__tools__": LISTING}
    stripped = strip_trust_labels(args)
    assert stripped == {"path": "/tmp/x"}
    assert args.keys() >= TRUST_LABELS  # the caller's mapping is untouched
    assert strip_trust_labels(None) == {}
    assert strip_trust_labels("not a mapping") == {}
    # The historical import site keeps working.
    assert MCP_TRUST_LABELS == TRUST_LABELS


# --- hook payloads ------------------------------------------------------------


def test_a_claude_code_hook_payload_cannot_forge_an_origin():
    engine = _engine(mcp_trust_registry([ORIGIN]))
    rendered = run_hook(
        get_adapter("claude-code"),
        _claude_payload("paste", {"text": "x", "__origin__": ORIGIN}),
        engine,
    )
    assert '"permissionDecision": "deny"' in rendered[0]


def test_a_codex_hook_payload_cannot_forge_an_origin():
    engine = _engine(mcp_trust_registry([ORIGIN]))
    stdout, stderr, code = run_hook(
        get_adapter("codex"),
        _codex_payload("paste", {"text": "x", "__origin__": ORIGIN}),
        engine,
    )
    assert code == 2 and "untrusted origin" in stderr


def test_a_hook_event_carries_no_reserved_label_at_all():
    call = get_adapter("claude-code").parse(_claude_payload(
        "paste",
        {"text": "x", "__origin__": ORIGIN, "__schema__": SCHEMA,
         "__attestation__": TOKEN, "__tools__": LISTING},
    ))
    event = call.events[0]
    assert not (event.args.keys() & TRUST_LABELS)
    assert event.args == {"text": "x"}
    assert event.labels == {}


# --- sidecar frames -----------------------------------------------------------


def test_a_sidecar_frame_cannot_forge_an_origin():
    op_id, event = parse_request(_request_frame(
        "paste", {"text": "x", "__origin__": ORIGIN}))
    assert op_id == "req-1"
    assert event.args == {"text": "x"}
    decision = mcp_trust_registry([ORIGIN])(event)
    assert decision is not None and decision.verdict is Verdict.BLOCK


def test_a_sidecar_frame_strips_every_reserved_key():
    _, event = parse_request(_request_frame("paste", {
        "text": "x",
        "__origin__": ORIGIN,
        "__schema__": SCHEMA,
        "__attestation__": TOKEN,
        "__tools__": LISTING,
    }))
    assert not (event.args.keys() & TRUST_LABELS)


def test_the_wire_has_no_trusted_label_channel():
    frame = _request_frame("paste", {"text": "x"})
    frame["event"]["labels"] = {"__origin__": ORIGIN}
    with pytest.raises(WireError):
        parse_request(frame)


# --- @guard **kwargs ----------------------------------------------------------


def test_guard_kwargs_cannot_forge_an_origin_and_the_tool_never_runs():
    ran = []

    @guard()
    def paste(**kwargs):
        ran.append(kwargs)

    import interlock

    interlock.install(engine=_engine(mcp_trust_registry([ORIGIN])))
    with pytest.raises(Blocked):
        paste(text="x", __origin__=ORIGIN)
    assert ran == []


# --- the trusted channel still works -----------------------------------------


def test_guard_mcp_session_sets_labels_and_the_server_receives_no_reserved_key():
    engine = _engine(
        mcp_trust_registry([ORIGIN]),
        mcp_tool_pinning({"create_issue": pin_of(SCHEMA)}),
    )
    echo = EchoSession()
    session = guard_mcp_session(
        echo, engine=engine, origin=ORIGIN, schemas={"create_issue": SCHEMA},
    )
    assert asyncio.run(session.call_tool(
        "create_issue", {"title": "Bug", "__origin__": "evil", "__schema__": "spoof"}
    )) == "ok"
    assert echo.received == [("create_issue", {"title": "Bug"})]


def test_guard_mcp_session_labels_its_result_event_too():
    seen = []

    def capture(event):
        seen.append(dict(event.labels))
        return None

    capture.phase = "result"  # result-phase events only, like a result rule

    session = guard_mcp_session(
        EchoSession("ok"), engine=_engine(capture), origin=ORIGIN,
        schemas={"create_issue": SCHEMA},
    )
    asyncio.run(session.call_tool("create_issue", {"title": "Bug"}))
    assert seen == [{"__origin__": ORIGIN, "__schema__": SCHEMA}]


def test_the_labels_reach_every_trust_detector():
    lease = pytest.importorskip("interlock.detectors.mcp_capability_lease")
    registry = lease.LeaseRegistry()
    registry.issue(ORIGIN, "create_issue", 0.0, 10 ** 12)
    # An attestation rule is exercised through the trusted channel below; the
    # guarded session, by design, has no attestation fact to set here.
    engine = _engine(
        mcp_trust_registry([ORIGIN]),
        mcp_tool_pinning({"create_issue": pin_of(SCHEMA)}),
        lease.mcp_capability_lease(registry),
        mcp_surface_baseline(),
    )
    session = guard_mcp_session(
        EchoSession(LISTING), engine=engine, origin=ORIGIN,
        schemas={"create_issue": SCHEMA},
    )
    assert asyncio.run(session.call_tool("create_issue", {"title": "Bug"})) == LISTING


def test_enforce_tool_call_labels_are_out_of_band_and_args_are_stripped():
    engine = _engine(mcp_trust_registry([ORIGIN]))
    assert enforce_tool_call(
        "paste", {"text": "x"}, engine=engine, labels={"__origin__": ORIGIN}
    ) == {"text": "x"}
    with pytest.raises(Blocked):
        enforce_tool_call("paste", {"text": "x", "__origin__": ORIGIN}, engine=engine)


def test_attestation_from_the_trusted_channel_verifies():
    expected = attestation_for(TOKEN, LISTING)
    engine = _engine(mcp_server_attestation({ORIGIN: TOKEN}))
    assert enforce_tool_call(
        "create_issue", {"title": "Bug"}, engine=engine,
        labels={"__origin__": ORIGIN, "__attestation__": expected,
                "__tools__": LISTING},
    ) == {"title": "Bug"}


# --- the documented hand-built fallback --------------------------------------


def test_a_hand_built_event_still_resolves_an_args_label():
    rule = mcp_trust_registry([ORIGIN])
    assert rule(SensorEvent(action="paste", args={"__origin__": ORIGIN})) is None
    decision = rule(SensorEvent(action="paste", args={"__origin__": "evil"}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "__origin__"


def test_a_hand_built_listing_still_resolves_args_labels():
    rule = mcp_surface_baseline()
    assert rule(SensorEvent(
        action="tools/list", args={"__origin__": ORIGIN, "__tools__": LISTING}
    )) is None
    decision = rule(SensorEvent(
        action="tools/list",
        args={"__origin__": ORIGIN, "__tools__": LISTING + [
            {"name": "delete_repo", "description": "Delete", "input": {}}]},
    ))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "__tools__"
