"""MCP resource-URI prefix allowlist: block resource reads outside vetted roots.

Reading an MCP resource hands the agent whatever bytes live behind a URI, and
the URI itself is selected by the model - so it is attacker-influenced long
before the read happens. ``mcp.read_resource`` is the boundary where that
choice becomes a capability: a resource server will serve ``file:///etc/passwd``
exactly as readily as a workspace document. This Rule constrains the read to a
reviewed set of URI roots, *before* the resource is fetched.

The rule has an opinion only about resource-read events:

- ``args["uri"]`` starting with an allowlisted prefix -> None (no opinion)
- ``args["uri"]`` outside every prefix            -> BLOCK (unvetted root)
- any non-read action                              -> None (out of scope)

Matching is a literal ``str.startswith`` against the configured prefixes rather
than a parse-and-compare of scheme/host/path. The allowlist entry is the whole
boundary the operator reviewed, so nothing about it is inferred: a prefix of
``"file:///workspace/"`` admits ``file:///workspace/a.txt`` and refuses
``file:///workspace-other/a.txt``, because the trailing separator - not a
scheme-aware interpretation - draws the edge. Enumerate the exact roots;
``"https://docs.internal"`` without the trailing slash would also admit
``https://docs.internal.evil.com/``.

Fail-closed where it counts: a read event presenting no usable URI - a missing
key, a non-str value, or a non-dict ``args`` - is blocked rather than waved
through. A read that cannot prove its URI is in scope is exactly the case the
allowlist exists to refuse. Non-read traffic gets no opinion, so this guard
composes with the tool-level policies instead of replacing them.

An allowlist that fails to load (None, a non-iterable, or non-str entries)
yields an empty prefix set, which admits nothing: every read is blocked. That
is the correct direction for a security control - a config that named nothing
must not silently fabricate coverage.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_resource_uri"

# Lead of the block reason. Deliberately the guard's name rather than
# POLICY_ID: the policy id is the stable handle rules are registered under,
# while the reason is human-facing prose naming the technique that refused.
_REASON_LEAD = "mcp_resource_uri_guard"

# The only action that fetches a resource; everything else is out of scope.
_READ_ACTION = "mcp.read_resource"

# The args key carrying the URI a resource read is about to fetch.
_URI_KEY = "uri"

# Rendered in the block reason when the read carried no usable URI.
_MISSING_URI = "<missing>"


def _as_prefix_tuple(allowed_prefixes: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Collect allowed URI prefixes into a tuple, skipping junk.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the allowlist instead of crashing - or, worse, admitting
    single characters. Prefixes are kept verbatim: a URI path is
    case-sensitive, so lowercasing here would change which resources are
    admitted rather than merely how the entry is written. A tuple (rather than
    a set) keeps ``startswith`` a single linear scan without the per-call
    hashing overhead.
    """
    if allowed_prefixes is None:
        return ()
    if isinstance(allowed_prefixes, str):
        items: Iterable[Any] = (allowed_prefixes,)
    else:
        items = allowed_prefixes
    return tuple(prefix for prefix in items if isinstance(prefix, str))


def mcp_resource_uri_guard(allowed_prefixes: Iterable[str]) -> Rule:
    """Rule: permit resource reads only under `allowed_prefixes`; deny the rest.

    Returns None (no opinion) for a read whose URI starts with an allowlisted
    prefix, and for any action that is not ``"mcp.read_resource"``. Blocks every
    other read - an unvetted root, or one whose URI is missing or unusable - so
    the permit branch is a strict prefix test and a malformed read cannot slip
    through. The rule never raises, whatever the event carries.
    """
    prefixes = _as_prefix_tuple(allowed_prefixes)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) != _READ_ACTION:
            return None
        args = getattr(event, "args", None)
        uri = args.get(_URI_KEY) if isinstance(args, dict) else None
        if isinstance(uri, str) and uri.startswith(prefixes):
            return None
        return Decision.block(
            reason="{}: {} outside allowed prefixes".format(
                _REASON_LEAD, uri if isinstance(uri, str) else _MISSING_URI
            ),
            policy_id=POLICY_ID,
        )

    return rule
