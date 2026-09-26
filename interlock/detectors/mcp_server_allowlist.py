"""MCP server URI allowlist: block session connects to unvetted servers.

Connecting to an MCP server is the first supply-chain decision an agent makes -
everything the server subsequently advertises, and every tool call it feeds the
model, is downstream of that one ``"mcp.connect"`` event. Once the session is
open, a name- or capability-based policy is already operating behind the
attacker's edge; this Rule closes the gap *before* the effect by permitting
connects only to servers whose host was reviewed.

The rule has an opinion only about connect events:

- ``args["uri"]`` whose host is allowlisted -> None (no opinion)
- ``args["uri"]`` whose host is not         -> BLOCK (unlisted server)
- any non-connect action                     -> None (out of scope)

Host extraction uses ``urllib.parse.urlparse`` and compares only the hostname,
so the scheme, path, query, and port of an approved server do not need to be
enumerated - ``https://mcp.trusted.io/sse`` and
``https://mcp.trusted.io:8443/v2/sse`` are the same reviewed host.

Fail-closed where it counts: a connect event that presents no usable URI - a
missing key, a non-str value, a non-dict args, a value ``urlparse`` cannot even
split (a malformed IPv6 literal raises ``ValueError``), or a string with no
parseable host - is blocked rather than waved through. A connect that cannot
prove its host is exactly the case the allowlist exists to refuse. Non-connect
traffic is left alone, so this guard composes with the tool-level policies
rather than replacing them.

An allowlist that fails to load (None, a non-iterable, or non-str entries)
yields an empty host set, which admits nothing: every connect is blocked. That
is the correct direction for a security control - a config that named nothing
must not silently fabricate coverage.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Optional
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_server_allowlist"

# The only action that opens a session; everything else is out of scope.
_CONNECT_ACTION = "mcp.connect"

# The args key carrying the server URI an adapter is about to connect to.
_URI_KEY = "uri"

# Rendered in the block reason when no host could be parsed from the URI.
_UNKNOWN_HOST = "<unknown>"


def _as_host_frozenset(allowed_hosts: Optional[Iterable[str]]) -> FrozenSet[str]:
    """Collect allowed host names into a frozenset, skipping junk.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the allowlist instead of crashing - or, worse, silently
    admitting single characters. Names are lowercased because DNS hosts are
    case-insensitive and ``urlparse`` already lowercases the hostname it
    returns; normalising both sides keeps the comparison exact without being
    brittle about a stray capital in the config.
    """
    if allowed_hosts is None:
        return frozenset()
    if isinstance(allowed_hosts, str):
        items: Iterable[Any] = (allowed_hosts,)
    else:
        items = allowed_hosts
    return frozenset(host.lower() for host in items if isinstance(host, str))


def _host_of(args: Any) -> Optional[str]:
    """Return the hostname of the URI declared in `args`, or None.

    Args are attacker-influenced and may be anything - None, an int, a list. A
    non-mapping args, a missing key, or a non-str value all mean "no usable URI
    here". ``urlparse`` raises ``ValueError`` on some malformed inputs (an
    unterminated IPv6 literal), and a bare word like ``"not a url"`` parses to
    no host at all; both collapse to None, which the caller blocks. The
    hostname - not the netloc - is returned, so a port on an approved host does
    not read as a different server.
    """
    if not isinstance(args, dict):
        return None
    uri = args.get(_URI_KEY)
    if not isinstance(uri, str):
        return None
    try:
        host = urlparse(uri).hostname
    except ValueError:
        return None
    return host or None


def mcp_server_allowlist(allowed_hosts: Iterable[str]) -> Rule:
    """Rule: permit MCP connects only to hosts in `allowed_hosts`; deny the rest.

    Returns None (no opinion) for a connect whose URI host is allowlisted, and
    for any action that is not ``"mcp.connect"``. Blocks every other connect -
    an unlisted host, or one whose host cannot be parsed at all - so the permit
    branch is a strict membership test and a malformed URI cannot slip through.
    """
    allowed = _as_host_frozenset(allowed_hosts)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != _CONNECT_ACTION:
            return None
        host = _host_of(event.args)
        if host is not None and host in allowed:
            return None
        return Decision.block(
            "{}: {} not allowed".format(
                POLICY_ID, host if host is not None else _UNKNOWN_HOST
            ),
            policy_id=POLICY_ID,
            attributed_to=_URI_KEY,
        )

    return rule
