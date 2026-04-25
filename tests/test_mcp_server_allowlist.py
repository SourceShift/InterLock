"""MCP server URI allowlist: host allow/block paths, the fail-closed default for
unparseable URIs, malformed-input handling, and engine integration."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_server_allowlist import (
    POLICY_ID,
    mcp_server_allowlist,
)


def _connect(uri=None, args=None):
    if args is None:
        args = {} if uri is None else {"uri": uri}
    return SensorEvent(action="mcp.connect", args=args)


# --- allow: connect to an allowlisted host ----------------------------------


def test_allow_connect_to_allowlisted_host():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    assert guard(_connect("https://mcp.trusted.io/sse")) is None


def test_allow_is_membership_not_absence_of_opinion():
    # In one guard an approved host passes and an unapproved one does not:
    # proves the None came from the allowlist, not a rule that never blocks.
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    assert guard(_connect("https://mcp.trusted.io/sse")) is None
    assert guard(_connect("https://evil.io/sse")) is not None


def test_allow_ignores_scheme_path_query_and_port():
    # Only the host was reviewed; transport details of the same host must not
    # read as a different server.
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    for uri in (
        "http://mcp.trusted.io/sse",
        "https://mcp.trusted.io:8443/v2/sse?token=abc",
        "wss://mcp.trusted.io/gateway",
    ):
        assert guard(_connect(uri)) is None


def test_host_match_is_case_insensitive():
    # urlparse lowercases the hostname; a capital in the config must not
    # silently disable an otherwise-correct entry.
    guard = mcp_server_allowlist(allowed_hosts={"MCP.Trusted.IO"})
    assert guard(_connect("https://mcp.trusted.io/sse")) is None


def test_adding_a_host_flips_block_to_permit():
    strict = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    widened = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io", "mcp.linear.io"})
    event = _connect("https://mcp.linear.io/sse")
    assert strict(event) is not None
    assert widened(event) is None


# --- block: connect to an unlisted host -------------------------------------


def test_block_connect_to_unlisted_host():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    decision = guard(_connect("https://evil.io/sse"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_server_allowlist"
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_host():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    decision = guard(_connect("https://evil.io/sse"))
    assert decision is not None
    assert decision.reason == "mcp_server_allowlist: evil.io not allowed"


def test_host_match_is_exact_subdomain_is_not_admitted():
    # Allowing "trusted.io" must not admit "mcp.trusted.io" (nor the reverse):
    # a look-alike host is a different server.
    guard = mcp_server_allowlist(allowed_hosts={"trusted.io"})
    assert guard(_connect("https://trusted.io/sse")) is None
    assert guard(_connect("https://mcp.trusted.io/sse")) is not None


def test_userinfo_in_uri_does_not_spoof_the_host():
    # A userinfo segment that looks like an approved host must not launder an
    # unapproved one - urlparse keeps the real host in .hostname.
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    assert guard(_connect("https://mcp.trusted.io@evil.io/sse")) is not None


# --- out of scope: non-connect actions --------------------------------------


def test_non_connect_action_returns_none_even_for_evil_uri():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    for action in ("mcp.call", "github.create_issue", "http.get", "read_file"):
        event = SensorEvent(action=action, args={"uri": "https://evil.io/sse"})
        assert guard(event) is None


# --- fail-closed: no parsable host on a connect -----------------------------


def test_fail_closed_on_missing_uri():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    decision = guard(_connect(args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_fail_closed_on_non_string_uri():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    for uri in (None, 3, ["https://mcp.trusted.io"], {"h": "mcp.trusted.io"}):
        decision = guard(_connect(args={"uri": uri}))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_unparseable_uri():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    for uri in ("", "   ", "not a url", "https://", "http://[::1"):
        decision = guard(_connect(uri))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_empty_allowlist():
    guard = mcp_server_allowlist(allowed_hosts=set())
    decision = guard(_connect("https://mcp.trusted.io/sse"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- malformed input: skip, never raise -------------------------------------


def test_non_mapping_args_are_skipped_not_crashed():
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    for args in (None, 3, ["https://mcp.trusted.io"], "https://mcp.trusted.io"):
        decision = guard(_connect(args=args))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_non_string_action_is_ignored():
    # Only the exact connect action is in scope; any other action - including a
    # non-str one - gets no opinion rather than a spurious block.
    guard = mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})
    assert guard(SensorEvent(action=None, args={"uri": "https://evil.io"})) is None  # type: ignore[arg-type]
    assert guard(SensorEvent(action=3, args={"uri": "https://evil.io"})) is None  # type: ignore[arg-type]


def test_bare_string_config_is_wrapped_not_char_split():
    guard = mcp_server_allowlist(allowed_hosts="mcp.trusted.io")
    assert guard(_connect("https://mcp.trusted.io/sse")) is None
    assert guard(_connect("https://m.sse")) is not None  # not split into chars


def test_non_str_allowlist_entries_are_skipped_not_admitted():
    guard = mcp_server_allowlist(
        allowed_hosts=["mcp.trusted.io", None, 3, ["evil.io"]]  # type: ignore[list-item]
    )
    assert guard(_connect("https://mcp.trusted.io/sse")) is None
    assert guard(_connect("https://evil.io/sse")) is not None


def test_none_config_admits_nothing():
    guard = mcp_server_allowlist(allowed_hosts=None)  # type: ignore[arg-type]
    decision = guard(_connect("https://mcp.trusted.io/sse"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_unlisted_and_allows_listed_connect():
    engine = PolicyEngine(rules=[mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})])

    blocked = engine.evaluate(_connect("https://evil.io/sse"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(_connect("https://mcp.trusted.io/sse"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fails_closed_on_unparseable_connect():
    engine = PolicyEngine(rules=[mcp_server_allowlist(allowed_hosts={"mcp.trusted.io"})])
    decision = engine.evaluate(_connect(args={}))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
