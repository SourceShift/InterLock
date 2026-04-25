"""MCP resource-URI prefix allowlist: allow/block paths, the fail-closed default
for missing or unusable URIs, prefix-boundary handling, malformed input, and
engine integration."""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mcp_resource_uri_guard import (
    POLICY_ID,
    mcp_resource_uri_guard,
)

PREFIXES = {"file:///workspace/", "https://docs.internal/"}


def _read(uri=None, args=None):
    if args is None:
        args = {} if uri is None else {"uri": uri}
    return SensorEvent(action="mcp.read_resource", args=args)


# --- allow: read under an allowlisted prefix --------------------------------


def test_allow_read_under_workspace_prefix():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    assert guard(_read("file:///workspace/a.txt")) is None


def test_allow_read_under_each_configured_prefix():
    # Two different roots, one guard: proves each entry carries its own permit
    # and the None is not the result of a single hard-coded prefix.
    guard = mcp_resource_uri_guard(allowed_prefixes=PREFIXES)
    assert guard(_read("file:///workspace/a.txt")) is None
    assert guard(_read("file:///workspace/nested/dir/b.txt")) is None
    assert guard(_read("https://docs.internal/policies/erp.md")) is None


def test_allow_is_prefix_test_not_absence_of_opinion():
    # In one guard an in-scope read passes and an out-of-scope one does not:
    # proves the None came from the allowlist, not a rule that never blocks.
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    assert guard(_read("file:///workspace/a.txt")) is None
    assert guard(_read("file:///etc/passwd")) is not None


def test_allow_the_prefix_root_itself():
    # The root named in the config is in scope, not only its descendants.
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    assert guard(_read("file:///workspace/")) is None


# --- block: read outside every prefix ---------------------------------------


def test_block_read_outside_prefixes():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    decision = guard(_read("file:///etc/passwd"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "mcp_resource_uri"
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_uri():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    decision = guard(_read("file:///etc/passwd"))
    assert decision is not None
    assert decision.reason == (
        "mcp_resource_uri_guard: file:///etc/passwd outside allowed prefixes"
    )


def test_block_other_scheme_and_host_are_out_of_scope():
    guard = mcp_resource_uri_guard(allowed_prefixes=PREFIXES)
    for uri in (
        "http://docs.internal/policies/erp.md",   # not the allowlisted scheme
        "https://evil.example/x",                 # unlisted host
        "file:///tmp/x",                          # unlisted local root
        "file:///workspace",                      # no trailing slash on the URI
        "file:///workspace-evil/x",               # sibling root, not a child
        "file:///WORKSPACE/a.txt",                # prefix match is case-sensitive
    ):
        decision = guard(_read(uri))
        assert decision is not None, uri
        assert decision.verdict is Verdict.BLOCK, uri


def test_trailing_separator_draws_the_boundary():
    # The separator in the allowlisted entry - not a scheme-aware parse - is
    # what stops a look-alike host from riding in on a shared prefix.
    guard = mcp_resource_uri_guard(allowed_prefixes={"https://docs.internal/"})
    assert guard(_read("https://docs.internal/policies/erp.md")) is None
    assert guard(_read("https://docs.internal.evil.com/policies/erp.md")) is not None


def test_adding_a_prefix_flips_block_to_permit():
    strict = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    widened = mcp_resource_uri_guard(
        allowed_prefixes={"file:///workspace/", "https://docs.internal/"}
    )
    event = _read("https://docs.internal/policies/erp.md")
    assert strict(event) is not None
    assert widened(event) is None


# --- out of scope: non-read actions -----------------------------------------


def test_non_read_action_returns_none_even_for_evil_uri():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    for action in ("mcp.read_prompt", "mcp.call", "mcp.connect", "github.create_issue"):
        event = SensorEvent(action=action, args={"uri": "file:///etc/passwd"})
        assert guard(event) is None


def test_non_string_action_is_ignored():
    # Only the exact read action is in scope; a non-str action gets no opinion
    # rather than a spurious block.
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    assert guard(SensorEvent(action=None, args={"uri": "file:///etc/passwd"})) is None  # type: ignore[arg-type]
    assert guard(SensorEvent(action=3, args={"uri": "file:///etc/passwd"})) is None  # type: ignore[arg-type]


# --- fail-closed: a read with no usable URI ---------------------------------


def test_fail_closed_on_missing_uri():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    decision = guard(_read(args={}))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_fail_closed_on_non_string_uri():
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    for uri in (None, 3, ["file:///workspace/a.txt"], {"u": "file:///workspace/a.txt"}):
        decision = guard(_read(args={"uri": uri}))
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_empty_uri():
    # "" is a str but starts with no non-empty prefix, so it is refused rather
    # than treated as a vacuously-satisfied startswith.
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    decision = guard(_read(""))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_fail_closed_on_empty_allowlist():
    guard = mcp_resource_uri_guard(allowed_prefixes=set())
    decision = guard(_read("file:///workspace/a.txt"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- malformed input: skip, never raise -------------------------------------


def test_non_mapping_args_are_fail_closed_not_crashed():
    # Built directly, not via _read: the helper's default would replace a None
    # args with {} and quietly skip the case under test.
    guard = mcp_resource_uri_guard(allowed_prefixes={"file:///workspace/"})
    for args in (None, 3, ["file:///workspace/a.txt"], "file:///workspace/a.txt"):
        decision = guard(SensorEvent(action="mcp.read_resource", args=args))  # type: ignore[arg-type]
        assert decision is not None
        assert decision.verdict is Verdict.BLOCK


def test_bare_string_config_is_wrapped_not_char_split():
    guard = mcp_resource_uri_guard(allowed_prefixes="file:///workspace/")
    assert guard(_read("file:///workspace/a.txt")) is None
    assert guard(_read("f")) is not None  # not split into single characters


def test_non_str_allowlist_entries_are_skipped_not_admitted():
    guard = mcp_resource_uri_guard(
        allowed_prefixes=["file:///workspace/", None, 3, ["https://docs.internal/"]]  # type: ignore[list-item]
    )
    assert guard(_read("file:///workspace/a.txt")) is None
    assert guard(_read("https://docs.internal/policies/erp.md")) is not None


def test_none_config_admits_nothing():
    guard = mcp_resource_uri_guard(allowed_prefixes=None)  # type: ignore[arg-type]
    decision = guard(_read("file:///workspace/a.txt"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- engine integration -----------------------------------------------------


def test_engine_blocks_unvetted_read_and_allows_vetted_read():
    engine = PolicyEngine(rules=[mcp_resource_uri_guard(allowed_prefixes=PREFIXES)])

    blocked = engine.evaluate(_read("file:///etc/passwd"))
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.policy_id == POLICY_ID

    allowed = engine.evaluate(_read("file:///workspace/a.txt"))
    assert allowed.verdict is Verdict.ALLOW


def test_engine_fails_closed_on_uri_less_read():
    engine = PolicyEngine(rules=[mcp_resource_uri_guard(allowed_prefixes=PREFIXES)])
    decision = engine.evaluate(_read(args={}))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_engine_leaves_non_read_actions_alone():
    # The guard has no opinion about other traffic, so the engine's default
    # ALLOW stands - it does not block what it was never asked to police.
    engine = PolicyEngine(rules=[mcp_resource_uri_guard(allowed_prefixes=PREFIXES)])
    decision = engine.evaluate(
        SensorEvent(action="github.create_issue", args={"uri": "file:///etc/passwd"})
    )
    assert decision.verdict is Verdict.ALLOW
