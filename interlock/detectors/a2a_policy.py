"""Agent-to-agent (A2A) policy: allowlist the peers an agent may reach and pin their cards.

An agent-to-agent call is an outbound trust decision on the same footing as an
MCP connect: the peer an agent addresses, and the agent card that peer
advertises, are supply-chain inputs the rest of the run is downstream of. This
module ships the two rules that gate that edge - :func:`a2a_peer_allowlist`
(which peers are reachable) and :func:`a2a_card_guard` (whether a peer's
advertised card changed under review) - and the peer normalisation both of
them, and the declarative ``a2a`` condition, share, so a peer means the same
thing everywhere.

A2A traffic rides a call to the ``"a2a_send"`` action, the peer identifier
under ``args["peer"]`` (a ``scheme://host`` authority, as in
``mcp_server_allowlist``) and, when it advertises one, the agent card under
``args["card"]``.

``a2a_peer_allowlist`` costs a host comparison and follows
``mcp_server_allowlist``'s contract exactly: a peer whose host is allowlisted
is left alone, an unlisted host is blocked, and an a2a event that cannot
present a usable peer - a missing key, a non-str value, a non-dict args, a
value ``urlparse`` cannot split - is blocked rather than waved through. A
malformed allowlist admits nothing.

``a2a_card_guard`` follows ``mcp_surface_baseline``: the first card a peer
advertises is admitted and recorded, a later card with the same reviewed
fields passes, and a card that changed underneath that baseline - a renamed
agent, a rewritten description, a swapped skill set - is blocked. A card the
rule cannot parse from a peer it already admitted is blocked too; one sent
before admission is ignored and records nothing, so a malformed card can never
anchor or reset a baseline.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "a2a_peer_allowlist"
_CARD_POLICY_ID = "a2a_card_guard"

# The action an A2A call rides: one agent sending to another.
_A2A_ACTION = "a2a_send"

# The args key carrying the peer's identifier (a scheme://host authority).
_PEER_KEY = "peer"

# The args key carrying the peer's advertised agent card, when it sends one.
_CARD_KEY = "card"

# The card fields a policy reviews for drift, in a fixed order: the agent's
# identity and what it advertises it can do.
_CARD_FIELDS = ("name", "description", "skills")

# Rendered in a block reason when no peer identity could be parsed.
_UNKNOWN_PEER = "<unknown>"


def peer_host(value: Any) -> Optional[str]:
    """Return the host identity of a peer string, or None if there is none.

    A peer is a ``scheme://host`` authority, but an operator may write either
    the full ``"peer://trusted.example"`` or the bare ``"trusted.example"``.
    Both are normalised through the same parse - the lowercase hostname - so
    the two spellings name the same peer and the port, path, and userinfo of an
    approved peer do not read as a different one, exactly as
    ``mcp_server_allowlist`` treats a reviewed host. ``urlparse`` raises on
    some malformed inputs (an unterminated IPv6 literal); that, a non-str
    value, and a blank string all yield None, which a caller treats as
    unusable.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        host = urlparse(text).hostname
    except ValueError:
        return None
    if host:
        return host.lower()
    # No scheme: a bare authority like "trusted.example" is its own host.
    return text.lower()


def card_digest(card: Any) -> Optional[str]:
    """Return the canonical sha256 of an agent card's reviewed fields, or None.

    Only the fields a policy reviews - ``name``, ``description`` and
    ``skills`` - are hashed, each serialized with sorted JSON keys, so a peer
    that re-serializes or re-orders an otherwise-identical card produces the
    same digest and a healthy deployment is not flagged as drift, while a
    changed name, description or skill set changes it. A card that is not a
    mapping, carries none of those fields, or holds a value JSON cannot render
    (a set, an object) yields None: unusable, which the caller treats as an
    unproven card rather than guessing a fallback the peer never agreed to.
    """
    if not isinstance(card, dict):
        return None
    projection = {field: card[field] for field in _CARD_FIELDS if field in card}
    if not projection:
        return None
    try:
        rendered = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _as_peer_hosts(allowed: Any) -> FrozenSet[str]:
    """Collect allowed peer identities into a frozenset, skipping junk.

    A bare string is wrapped rather than iterated character-by-character, and
    each entry is normalised through :func:`peer_host`, so
    ``"peer://trusted.example"`` and ``"trusted.example"`` collapse to the same
    host and a malformed entry (a non-str, a blank string, a value
    ``urlparse`` cannot split) is skipped rather than crashing the rule - or,
    worse, admitting a fragment of it. A config that is neither a string nor
    iterable yields nothing, which admits nothing.
    """
    if allowed is None:
        return frozenset()
    if isinstance(allowed, str):
        items: Iterable[Any] = (allowed,)
    else:
        try:
            items = list(allowed)
        except TypeError:
            return frozenset()
    return frozenset(
        host for host in (peer_host(item) for item in items) if host is not None
    )


def _expected_digest(expected: Any) -> Optional[str]:
    """A seeded baseline: an already-computed digest string, or a card to hash."""
    if isinstance(expected, str):
        return expected or None
    return card_digest(expected)


def a2a_peer_allowlist(allowed: Iterable[str]) -> Rule:
    """Rule: permit A2A sends only to peers in `allowed`; deny the rest.

    Returns None (no opinion) for an a2a send whose peer host is allowlisted,
    and for any action that is not ``"a2a_send"``. Blocks every other a2a send
    - an unlisted peer, or one whose peer cannot be parsed at all - so the
    permit branch is a strict membership test and a malformed peer cannot slip
    through. Entries in `allowed` may be written as a full ``scheme://host`` or
    as a bare host; both normalise to the same identity.
    """
    permitted = _as_peer_hosts(allowed)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != _A2A_ACTION:
            return None
        host = peer_host(event.args.get(_PEER_KEY)) if isinstance(event.args, dict) else None
        if host is not None and host in permitted:
            return None
        return Decision.block(
            "{}: {} not allowed".format(
                POLICY_ID, host if host is not None else _UNKNOWN_PEER
            ),
            policy_id=POLICY_ID,
            attributed_to=_PEER_KEY,
        )

    return rule


def a2a_card_guard(cards: Optional[Mapping[str, Any]] = None) -> Rule:
    """Rule: admit a peer's first agent card, block any later change to it.

    Returns None on the first parseable card for a peer (admission: the
    reviewed fields are fingerprinted) and on later cards that fingerprint the
    same, however re-serialized. Blocks a later card whose name, description or
    skills changed - the interface the operator reviewed is gone - and a card
    that cannot be parsed from a peer already admitted. Before admission an
    unusable card is ignored and records nothing, so it can anchor or reset no
    baseline; re-admission is a fresh factory call, never a silent slide to the
    new card. An event with no parseable peer is out of scope - the peer
    allowlist owns that refusal.

    ``cards`` optionally seeds baselines up front, mapping a peer (a full
    ``scheme://host`` or a bare host) to either the reviewed card itself or its
    :func:`card_digest`. A malformed seed entry is skipped, so a config that
    failed to load narrows the baselines rather than fabricating coverage.
    """
    baselines: Dict[str, str] = {}
    if isinstance(cards, dict):
        for peer, expected in cards.items():
            host = peer_host(peer)
            digest = _expected_digest(expected)
            if host is not None and digest is not None:
                baselines[host] = digest

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != _A2A_ACTION:
            return None
        args = event.args
        if not isinstance(args, dict):
            return None
        peer = peer_host(args.get(_PEER_KEY))
        if peer is None:
            return None
        digest = card_digest(args.get(_CARD_KEY))
        baseline = baselines.get(peer)
        if digest is None:
            if baseline is None:
                # Before admission an unusable card records nothing: it must
                # not be able to anchor - or reset - a baseline.
                return None
            return Decision.block(
                "{}: unusable agent card for {} (admitted card not"
                " verifiable)".format(_CARD_POLICY_ID, peer),
                policy_id=_CARD_POLICY_ID,
                attributed_to=_CARD_KEY,
            )
        if baseline is None:
            baselines[peer] = digest
            return None
        if digest == baseline:
            return None
        return Decision.block(
            "{}: agent card drift for {} (re-admission required)".format(
                _CARD_POLICY_ID, peer
            ),
            policy_id=_CARD_POLICY_ID,
            attributed_to=_CARD_KEY,
        )

    return rule
