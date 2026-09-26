"""MCP server attestation: block a server whose identity changed under its name.

``mcp_server_allowlist`` decides on a hostname and ``mcp_tool_pinning`` on a
tool schema hash. Both compare a value the server *declares* against a value
the operator stored, and neither proves the presenter: a hostname is not an
identity - anything that can answer at that host, or that a misconfigured
client resolves there, presents it - and an unchanged schema string says
nothing about who served it. This Rule holds an *expected identity* per
server and demands that every event from that server present a value matching
it, so a server whose identity has changed fails admission instead of being
treated as the same server.

**What this is, honestly.** With the default :func:`token_verifier` this rule
is string comparison, not attestation. It proves the presenter knows a shared
token, which anything holding that token - a leaked config, a cloned host, a
compromised server - can also present. A genuine attestation requires a root
of trust (a signing key, an mTLS peer certificate, a registry signature) that
this library does not own and cannot supply; ``pyproject.toml`` keeps
``dependencies = []`` precisely so it cannot reach for one and dress the
result up as proof. The deliverable is the seam: a caller who *does* hold a
root of trust passes their own ``verifier=`` to :func:`mcp_server_attestation`
and the rule defers to it entirely - the library compares no strings behind
its back.

The rule has an opinion only about servers with a provisioned identity:

- a server whose presented value verifies against its expectation -> None
- a server that presents a non-matching value - or none at all -> BLOCK
- a server with no expected identity                             -> None (out of scope)

Fail-closed where it counts: an expected server that presents *no* usable
identity - a missing ``__attestation__`` key, a non-str value, a tool listing
that cannot be canonicalized - is blocked like a mismatch. The expectation
was set against a concrete value, and a server that cannot produce that value
has not proven itself; refusing it is the point. Unprovisioned traffic is
left alone, so this guard composes with the allowlist, trust-registry and
pinning rules rather than replacing them. An event that names no server at
all is out of scope for the same reason: this rule judges *presenters*, and
``mcp_trust_registry`` is the rule that refuses an unlabelled call.

The subject is resolved the way ``mcp_trust_registry`` resolves an origin:
an explicit ``args["__origin__"]`` label first (per-call, and not chosen by
the untrusted server), else the prefix of a dotted action name
(``"github.create_issue"`` -> ``"github"``).

**Identity is bound to the tool surface.** The presented value covers a
digest of the server's tool listing, not an opaque token alone, so identity
and surface cannot be swapped independently: a presenter holding the right
token but serving a different tool listing derives a different value and is
blocked. Both sides derive the HMAC-SHA256 of the listing digest under the
identity token (see :func:`attestation_for`), and the digest is
order-independent - entries sorted by tool name, each serialized with sorted
JSON keys - so a harmless re-serialization or reordering by the server yields
the same digest and does not block a healthy deployment. Under the default
verifier this binding is still only a shared-secret construction; an injected
verifier may validate a real signature over the same digest instead, which is
exactly the composition the seam exists for.

A malformed expectation map (None, a non-dict, or non-str entries) yields an
empty map, which makes the rule inert: it expects nothing and passes
everything. That is deliberate, and inherited from ``mcp_tool_pinning``'s pin
map: a config that failed to load is indistinguishable from one that names
nothing, and silently fabricating coverage the operator never supplied would
be worse than being inert. Supply real expectations to enforce.

The rule never raises: args are attacker-influenced and may be any type, and
every reader narrows to ``None`` (unusable) rather than touching a key
blindly. An injected verifier that raises is the caller's own bug and
propagates.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Callable, Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_server_attestation"

# The args key an adapter uses to label a call with its server origin
# (see mcp_trust_registry, which introduced the label).
_ORIGIN_KEY = "__origin__"

# The action-name separator that introduces a dotted origin prefix.
_ORIGIN_SEPARATOR = "."

# The args key carrying the identity value the server presented.
_ATTESTATION_KEY = "__attestation__"

# The args key carrying the tool listing the presented identity is bound to.
_TOOLS_KEY = "__tools__"


def listing_digest(tools: Any) -> Optional[str]:
    """Return the canonical sha256 digest of a server's tool listing, or None.

    Order-independent and re-serialization-stable: entries are sorted by tool
    name and each entry is JSON-serialized with sorted keys, so a server that
    re-orders its listing or re-serializes a tool's schema produces the same
    digest and a healthy deployment is not blocked as drift. A listing that is
    not a list/tuple of mappings, an entry without a non-empty str ``name``,
    or a value JSON cannot render (a set, an object) yields None: unusable,
    which the caller treats as an unproven identity rather than guessing a
    fallback canonicalization the presenter never agreed to.
    """
    if not isinstance(tools, (list, tuple)):
        return None
    rendered = []
    for entry in tools:
        if not isinstance(entry, dict):
            return None
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            return None
        try:
            rendered.append(
                (name, json.dumps(entry, sort_keys=True, separators=(",", ":")))
            )
        except (TypeError, ValueError):
            return None
    rendered.sort()
    return hashlib.sha256(
        "\n".join(body for _, body in rendered).encode("utf-8")
    ).hexdigest()


def _binding(token: str, digest: str) -> str:
    """Return the shared-token binding of `token` over a listing `digest`.

    HMAC-SHA256 with the identity token as the key and the listing digest as
    the message: both sides derive the same value without the token ever
    crossing the wire in the clear.
    """
    return hmac.new(
        token.encode("utf-8"), digest.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def attestation_for(token: str, tools: Any) -> str:
    """Return the identity value a server holding `token` presents for `tools`.

    A config-time helper, not a detector path: it is called to provision an
    expectation, or by an adapter that legitimately holds the token, so it
    stays strict - an unusable listing raises ValueError rather than silently
    binding the token to a digest of whatever it was handed.
    """
    digest = listing_digest(tools)
    if digest is None:
        raise ValueError(
            "unusable tool listing: expected a list of entries each with a"
            " non-empty str 'name'"
        )
    return _binding(token, digest)


def token_verifier(presented: str, expected: str, surface: str) -> bool:
    """Default verifier: bind `expected` to `surface` and compare in constant time.

    ``hmac.compare_digest`` runs over the utf-8 encodings, never the raw strs:
    it raises on a non-ASCII str, ``presented`` is attacker-influenced, and a
    differing length or a shared prefix must fail identically rather than
    raise or shortcut. This is string comparison with timing hygiene, not
    attestation - see the module docstring before relying on it.
    """
    return hmac.compare_digest(
        presented.encode("utf-8"),
        _binding(expected, surface).encode("utf-8"),
    )


def _as_identity_map(identities: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Collect server-name -> identity-token expectations, skipping junk.

    A non-mapping config yields no expectations. A non-str name can never
    equal a resolved origin and a non-str token cannot key a binding, so both
    are skipped: a malformed entry narrows the expectation set instead of
    crashing the rule - and, as with the pin map it mirrors, an empty set
    leaves the rule inert rather than fail-closed on traffic it was never
    told about.
    """
    if not isinstance(identities, dict):
        return {}
    return {
        name: token
        for name, token in identities.items()
        if isinstance(name, str) and isinstance(token, str)
    }


def _labelled_origin(args: Any) -> Optional[str]:
    """Resolve an explicit ``args["__origin__"]`` label, if it is usable.

    Args are attacker-influenced and may be anything - None, an int, a list.
    A non-mapping args, a missing key, or a blank/non-str label all mean "no
    label here", so the caller falls through to the dotted-name source rather
    than treating a malformed label as a refusal on its own.
    """
    if not isinstance(args, dict):
        return None
    origin = args.get(_ORIGIN_KEY)
    if isinstance(origin, str) and origin.strip():
        return origin
    return None


def _dotted_origin(action: Any) -> Optional[str]:
    """Resolve the origin prefix of a dotted action name, if there is one.

    ``"github.create_issue"`` -> ``"github"``. Splitting on the first
    separator keeps the origin a single segment, so ``"github.repo.delete"``
    is still the ``github`` server. A non-str action, or one with no
    separator or an empty prefix (``".evil"``), yields None.
    """
    if not isinstance(action, str):
        return None
    origin, separator, _ = action.partition(_ORIGIN_SEPARATOR)
    if separator and origin:
        return origin
    return None


def _server_of(event: SensorEvent) -> Optional[str]:
    """Resolve the server an event belongs to: explicit label, dotted name."""
    return _labelled_origin(event.args) or _dotted_origin(event.action)


def _presented_identity(args: Any) -> Optional[str]:
    """Return the identity value an event presents, or None if it presents none.

    Args are attacker-influenced and may be anything - None, an int, a list. A
    non-mapping args, a missing key, or a non-str value all mean "no usable
    identity here", which the caller blocks for an expected server.
    """
    if not isinstance(args, dict):
        return None
    presented = args.get(_ATTESTATION_KEY)
    if isinstance(presented, str):
        return presented
    return None


def _presented_surface(args: Any) -> Optional[str]:
    """Return the canonical digest of the listing an event presents, or None.

    The binding covers the tool surface, so the listing travels with the
    identity value and is canonicalized here. A non-mapping args or a listing
    that cannot be canonicalized yields None, which the caller blocks for an
    expected server: a presentation that names no surface has not bound the
    identity to anything.
    """
    if not isinstance(args, dict):
        return None
    return listing_digest(args.get(_TOOLS_KEY))


def mcp_server_attestation(
    identities: Dict[str, str],
    verifier: Callable[[str, str, str], bool] = token_verifier,
) -> Rule:
    """Rule: block any expected server whose presented identity fails to verify.

    Returns None (no opinion) for a server whose presentation verifies, and
    for any server with no provisioned identity. Blocks a server that presents
    a non-matching value - or no usable value, or a tool listing that cannot
    be canonicalized - because the expectation was set against a concrete
    binding and a server that cannot produce it has not proven itself. The
    comparison itself belongs to `verifier` as ``(presented, expected,
    surface) -> bool``; pass your own to check a real attestation (a
    signature, an mTLS peer certificate) instead of a shared token.
    """
    expected = _as_identity_map(identities)

    def rule(event: SensorEvent) -> Optional[Decision]:
        server = _server_of(event)
        if server is None:
            return None
        token = expected.get(server)
        if token is None:
            return None
        presented = _presented_identity(event.args)
        surface = _presented_surface(event.args)
        if (
            presented is not None
            and surface is not None
            and verifier(presented, token, surface)
        ):
            return None
        return Decision.block(
            "{}: unproven identity for {} at {}".format(
                POLICY_ID, server, _ATTESTATION_KEY
            ),
            policy_id=POLICY_ID,
            attributed_to=_ATTESTATION_KEY,
        )

    return rule
