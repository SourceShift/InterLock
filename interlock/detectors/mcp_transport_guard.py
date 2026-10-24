"""MCP transport guard: refuse an entire MCP transport (stdio, http or sse).

Connecting to an MCP server is a transport decision before it is a server
decision. The existing guards judge *which* server (``mcp_server_allowlist``),
*which* tools (``mcp_tool_pinning``) and *which* resources
(``mcp_resource_uri_guard``); none of them can express "this deployment speaks
stdio and nothing else". A policy that has reviewed its stdio launchers but not
the web of HTTP/SSE endpoints an agent could be pointed at wants to refuse the
whole transport, not enumerate it.

The rule has an opinion only about connect/launch events:

- a transport in ``allow``                       -> None (no opinion)
- a transport not in ``allow``                   -> BLOCK (named transport)
- a stdio launch whose command is on
  ``stdio_exceptions``                           -> None (no opinion)
- any other action                               -> None (out of scope)

The transport is read from ``args["transport"]`` (or its alias ``args["type"]``,
matching :mod:`interlock.mcp_inventory`), falling back to ``"http"`` when a
``url`` is present and ``"stdio"`` when a ``command`` is. Only the three
documented transports are named in a decision; anything else is refused as an
unknown transport, so the *reason* never quotes an attacker-supplied string -
the same "a diagnostic field is not a data-exfiltration surface" rule the rest
of the package follows.

For stdio, a launcher is only permitted when its command matches one of
``stdio_exceptions`` (a bare string matches the command or its basename; a
``(command, args)`` pair also requires those args to be a prefix of the call's
args). A stdio launch that matches nothing is refused before the process is
started, which is the only moment the transport can be stopped cheaply.

Fail-closed where it counts: a connect/launch event whose transport cannot be
determined at all - a non-dict args, no usable transport key, neither url nor
command - is blocked rather than waved through, because a launch that cannot
prove its transport is exactly the case this guard exists to refuse.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Optional, Tuple

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_transport_guard"

# The connect/launch actions an adapter emits before a server is reached. Kept
# to the two names the MCP adapters use so a same-named in-house tool is not
# shadowed.
CONNECT_ACTIONS = frozenset({"mcp.connect", "mcp.launch"})
_connect_actions = canonical_actions(CONNECT_ACTIONS)

# The argument keys that may carry the transport name, tried in this order.
_TRANSPORT_KEYS = ("transport", "type")

# The argument key carrying a stdio launcher's command and its argv.
_COMMAND_KEY = "command"
_URL_KEY = "url"

# The three transports this guard reasons about. Anything else is refused as
# unknown, so a decision can only ever name one of these tokens.
_TRANSPORTS = ("stdio", "http", "sse")

# Transport spellings that mean one of the three above.
_ALIASES = {"streamable-http": "http", "streamable_http": "http"}

# Rendered in the block reason when the transport could not be determined. A
# fixed token, never the value the caller supplied.
_UNKNOWN = "(unknown)"


def _transport(args: Any) -> Optional[str]:
    """The transport named in ``args``, or None when it cannot be determined.

    A non-dict args, a missing/non-str transport key, and a blank value all fall
    through to the url/command heuristic (:mod:`interlock.mcp_inventory` derives
    ``http`` from a url and ``stdio`` from a command the same way). A value that
    is none of the three transports is not returned - it is a transport this
    guard has no vocabulary for, and the caller refuses it as unknown.
    """
    if not isinstance(args, dict):
        return None
    raw = None
    for key in _TRANSPORT_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            raw = value.strip().lower()
            break
    if raw is None:
        if isinstance(args.get(_URL_KEY), str) and args.get(_URL_KEY).strip():
            return "http"
        command = args.get(_COMMAND_KEY)
        if isinstance(command, str) and command.strip():
            return "stdio"
        return None
    raw = _ALIASES.get(raw, raw)
    return raw if raw in _TRANSPORTS else None


def _token(transport: Optional[str]) -> str:
    """The token a decision may name: a documented transport, or ``_UNKNOWN``."""
    return transport if transport in _TRANSPORTS else _UNKNOWN


def _command_of(args: Any) -> Optional[str]:
    return args.get(_COMMAND_KEY) if isinstance(args, dict) else None


def _args_of(args: Any) -> Tuple[str, ...]:
    """The argv a stdio launch declares, as a tuple of strings (best effort)."""
    if not isinstance(args, dict):
        return ()
    argv = args.get("args")
    if isinstance(argv, (list, tuple)):
        return tuple(str(item) for item in argv)
    return ()


def _stdio_allowed(args: Any, exceptions: tuple) -> bool:
    """True when a stdio launch matches one of ``exceptions``.

    An exception is a command string (matched against the declared command and
    its basename) or a ``(command, args)`` pair, which additionally requires the
    declared argv to start with the listed args. A blank command, or one that is
    not a string, matches nothing.
    """
    command = _command_of(args)
    if not isinstance(command, str) or not command.strip():
        return False
    command = command.strip()
    basename = command.rsplit("/", 1)[-1]
    argv = _args_of(args)
    for entry in exceptions:
        if isinstance(entry, str):
            wanted, wanted_args = entry.strip(), ()
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            wanted, wanted_args = entry[0], tuple(entry[1] or ())
            if not isinstance(wanted, str):
                continue
            wanted = wanted.strip()
        else:
            continue
        if not wanted:
            continue
        if wanted != command and wanted != basename:
            continue
        if tuple(str(item) for item in wanted_args) == argv[: len(wanted_args)]:
            return True
    return False


def _as_tuple(entries: Optional[Iterable[Any]]) -> tuple:
    """Collect exception entries, skipping junk so a bad config narrows, not widens."""
    if entries is None:
        return ()
    if isinstance(entries, (str, bytes)):
        return (entries,)
    out = []
    for entry in entries:
        if isinstance(entry, str) or (
            isinstance(entry, (list, tuple)) and len(entry) == 2
        ):
            out.append(entry)
    return tuple(out)


def _as_transports(allow: Optional[Iterable[str]]) -> FrozenSet[str]:
    """Normalize ``allow`` to a set of documented transports.

    A bare string is wrapped rather than iterated character-by-character, and
    unknown spellings are dropped, so a malformed config narrows the allow set
    (refusing more) instead of admitting a transport this guard cannot name.
    """
    if allow is None:
        return frozenset(_TRANSPORTS)
    if isinstance(allow, str):
        items: Iterable[Any] = (allow,)
    else:
        items = allow
    out = set()
    for item in items:
        if isinstance(item, str):
            token = _ALIASES.get(item.strip().lower(), item.strip().lower())
            if token in _TRANSPORTS:
                out.add(token)
    return frozenset(out)


def mcp_transport_guard(
    allow: Iterable[str] = _TRANSPORTS,
    stdio_exceptions: Iterable[Any] = (),
) -> Rule:
    """Rule: permit only the listed transports; refuse the rest.

    Returns None (no opinion) for a connect/launch whose transport is in
    ``allow`` - and, for stdio, only when its command is on
    ``stdio_exceptions`` - and for any action that is not a connect/launch.
    Blocks every other connect/launch: a transport not allowed, a stdio launch
    with no matching exception, or a launch whose transport cannot be
    determined.
    """
    allowed = _as_transports(allow)
    exceptions = _as_tuple(stdio_exceptions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if not action_matches(event.action, _connect_actions):
            return None
        transport = _transport(event.args)
        if transport is not None and transport in allowed:
            # A non-stdio transport in the allow set needs no launcher check;
            # stdio is permitted only for a command on the exception list.
            if transport != "stdio" or _stdio_allowed(event.args, exceptions):
                return None
        return Decision.block(
            "{}: transport {} is not allowed".format(POLICY_ID, _token(transport)),
            policy_id=POLICY_ID,
            attributed_to=_TRANSPORT_KEYS[0],
        )

    return rule
