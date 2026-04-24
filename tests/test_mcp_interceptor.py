import asyncio

import pytest

import interlock
from interlock import (
    Blocked,
    Decision,
    PolicyEngine,
    deny_tool,
    enforce_tool_call,
    guard_mcp_session,
)


def setup_function(_):
    # Reset to an empty allow-all engine before each test.
    interlock.install(engine=PolicyEngine())


class FakeAsyncSession:
    """Stands in for an MCP client session with an async call_tool."""

    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, *rest, **kw):
        self.calls.append((name, dict(arguments or {})))
        return {"ok": True, "name": name, "arguments": arguments}


class FakeSyncSession:
    """Stands in for an MCP client session with a sync call_tool."""

    def __init__(self):
        self.calls = []

    def call_tool(self, name, arguments=None, *rest, **kw):
        self.calls.append((name, dict(arguments or {})))
        return {"ok": True, "name": name, "arguments": arguments}


def _cap_path(event):
    # MODIFY: rewrite a dangerous path to a sandboxed one.
    if event.args.get("path") == "/etc/passwd":
        return Decision.modify({"path": "/tmp/sandbox/passwd"}, reason="sandboxed")
    return None


# --- guard_mcp_session: async transport ------------------------------------


def test_async_block_never_reaches_server():
    session = guard_mcp_session(FakeAsyncSession())
    interlock.install(rules=[deny_tool("write_file", reason="no writes")])

    with pytest.raises(Blocked) as excinfo:
        asyncio.run(session.call_tool("write_file", {"path": "/etc/passwd"}))

    assert excinfo.value.decision.reason == "no writes"
    assert session.calls == []  # the effect never reached the server


def test_async_allow_passes_through_unchanged():
    session = guard_mcp_session(FakeAsyncSession())

    result = asyncio.run(session.call_tool("read_file", {"path": "/data/ok.txt"}))

    assert result["ok"] is True
    assert session.calls == [("read_file", {"path": "/data/ok.txt"})]


def test_async_modify_rewrites_args_before_server():
    session = guard_mcp_session(FakeAsyncSession())
    interlock.install(rules=[_cap_path])

    asyncio.run(session.call_tool("write_file", {"path": "/etc/passwd"}))

    assert session.calls == [("write_file", {"path": "/tmp/sandbox/passwd"})]


def test_async_monitor_observes_but_does_not_block():
    session = guard_mcp_session(FakeAsyncSession(), enforcement="monitor")
    interlock.install(rules=[deny_tool("write_file", reason="no writes")])

    result = asyncio.run(session.call_tool("write_file", {"path": "/etc/passwd"}))

    assert result["ok"] is True
    assert session.calls == [("write_file", {"path": "/etc/passwd"})]  # invoked


# --- guard_mcp_session: sync transport -------------------------------------


def test_sync_block_never_reaches_server():
    session = guard_mcp_session(FakeSyncSession())
    interlock.install(rules=[deny_tool("delete_all", reason="nope")])

    with pytest.raises(Blocked):
        session.call_tool("delete_all", {})

    assert session.calls == []


def test_sync_allow_passes_through():
    session = guard_mcp_session(FakeSyncSession())

    result = session.call_tool("ping", {"n": 1})

    assert result["ok"] is True
    assert session.calls == [("ping", {"n": 1})]


def test_guard_returns_same_session_object():
    original = FakeAsyncSession()
    assert guard_mcp_session(original) is original


# --- enforce_tool_call: transport-agnostic core ----------------------------


def test_enforce_allow_returns_args_unchanged():
    args = enforce_tool_call("read_file", {"path": "/ok"})
    assert args == {"path": "/ok"}


def test_enforce_block_raises():
    interlock.install(rules=[deny_tool("rm", reason="denied")])
    with pytest.raises(Blocked) as excinfo:
        enforce_tool_call("rm", {"path": "/"})
    assert excinfo.value.decision.reason == "denied"


def test_enforce_modify_merges_modified_args():
    interlock.install(rules=[_cap_path])
    args = enforce_tool_call("write_file", {"path": "/etc/passwd", "mode": "w"})
    # modified key overwritten, untouched key preserved
    assert args == {"path": "/tmp/sandbox/passwd", "mode": "w"}


def test_enforce_none_arguments_is_safe():
    args = enforce_tool_call("noop", None)
    assert args == {}


def test_enforce_monitor_records_but_does_not_raise():
    interlock.install(rules=[deny_tool("rm", reason="denied")])
    args = enforce_tool_call("rm", {"path": "/"}, enforcement="monitor")
    assert args == {"path": "/"}  # would-be block observed, not enforced
