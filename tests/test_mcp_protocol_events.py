"""MCP protocol events are not tool calls from a server named "mcp".

Protocol methods (``mcp.connect``, ``mcp.read_resource``, ``mcp.sampling``,
``tools/list``) have their own detectors. Their dotted names used to be read as
server-qualified tool names, so the trust registry and the lease rule saw a call
from a server called ``mcp``: an engine holding both the server allowlist and
the trust registry blocked every connect, and a lease rule blocked every
resource read. A protocol event names its server only through an explicit
``__origin__`` label, never through its method name.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_capability_lease import LeaseRegistry, mcp_capability_lease
from interlock.detectors.mcp_server_allowlist import mcp_server_allowlist
from interlock.detectors.mcp_trust_registry import mcp_trust_registry

PROTOCOL = ("mcp.connect", "mcp.read_resource", "mcp.sampling", "tools/list")


def _event(action, args=None, ts=100.0):
    return SensorEvent(action=action, args=args or {}, ts=ts)


def test_trust_registry_has_no_opinion_on_unlabelled_protocol_events():
    rule = mcp_trust_registry(["github"])
    for action in PROTOCOL:
        assert rule(_event(action, {"uri": "https://mcp.github.com"})) is None, action


def test_trust_registry_still_gates_a_labelled_protocol_event():
    rule = mcp_trust_registry(["github"])
    assert rule(_event("mcp.read_resource", {"__origin__": "github"})) is None
    blocked = rule(_event("mcp.read_resource", {"__origin__": "pastebin"}))
    assert blocked is not None and blocked.verdict is Verdict.BLOCK


def test_trust_registry_still_blocks_untrusted_and_unattributable_tool_calls():
    rule = mcp_trust_registry(["github"])
    assert rule(_event("github.create_issue")) is None
    assert rule(_event("pastebin.paste")).verdict is Verdict.BLOCK
    assert rule(_event("paste")).verdict is Verdict.BLOCK


def test_connect_passes_an_engine_holding_the_allowlist_and_the_trust_registry():
    engine = PolicyEngine([
        mcp_server_allowlist(["mcp.github.com"]),
        mcp_trust_registry(["github"]),
    ])
    ok = engine.evaluate(_event("mcp.connect", {"uri": "https://mcp.github.com/sse"}))
    assert ok.verdict is Verdict.ALLOW
    bad = engine.evaluate(_event("mcp.connect", {"uri": "https://mcp.evil.example/sse"}))
    assert bad.verdict is Verdict.BLOCK and bad.policy_id == "mcp_server_allowlist"


def test_lease_rule_ignores_listings_and_unlabelled_connects():
    rule = mcp_capability_lease(LeaseRegistry())
    assert rule(_event("tools/list")) is None
    assert rule(_event("tools/list", {"__origin__": "github"})) is None
    assert rule(_event("mcp.connect", {"uri": "https://mcp.github.com"})) is None


def test_lease_rule_still_leases_a_labelled_connect():
    leases = LeaseRegistry()
    rule = mcp_capability_lease(leases)
    connect = _event("mcp.connect", {"uri": "https://mcp.github.com", "__origin__": "github"})
    assert rule(connect).verdict is Verdict.BLOCK
    leases.issue("github", "mcp.connect", issued_at=0.0, expires_at=1000.0)
    assert rule(connect) is None


def test_lease_rule_does_not_infer_a_server_from_a_protocol_method_name():
    rule = mcp_capability_lease(LeaseRegistry())
    assert rule(_event("mcp.read_resource", {"uri": "file:///notes"})) is None
    assert rule(_event("mcp.sampling", {"model": "x"})) is None


def test_lease_rule_still_requires_a_lease_for_a_labelled_resource_read():
    leases = LeaseRegistry()
    rule = mcp_capability_lease(leases)
    labelled = _event("mcp.read_resource", {"__origin__": "github"})
    assert rule(labelled).verdict is Verdict.BLOCK
    leases.issue("github", "mcp.read_resource", issued_at=0.0, expires_at=1000.0)
    assert rule(labelled) is None
