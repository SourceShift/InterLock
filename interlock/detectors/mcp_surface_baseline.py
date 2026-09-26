"""MCP tool surface baseline: a listing that changed is a new admission.

``mcp_tool_pinning`` owns per-tool, call-time identity: a tool the operator
*pinned*, checked only when a *call* presents its declared schema under
``args["__schema__"]``. It has no opinion about a tool nobody pinned, and it
never looks at the server's listing as a whole. This Rule is the complementary
axis: the **surface** - the whole tool listing - at **admission/listing**
time. It fires on listing events (``tools/list``) where the pin rule fires on
call events, and it reads the listing payload (``args["__tools__"]``) where
the pin rule reads ``args["__schema__"]``, so the two cannot both fire on one
event and the engine's first-non-ALLOW order cannot make them race.

Division of labour with ``mcp_server_attestation`` (R6b): that rule binds an
*identity* to the listing digest the server itself *presents* - self-
consistency, checked at call time, proving the presenter still holds the
provisioned token over the surface it serves. This rule holds the *reviewed*
listing and fires when a later one *differs* - it is the memory of what was
admitted, and it needs no token. Both sides share one canonicalization
(:func:`mcp_server_attestation.listing_digest`): entries sorted by tool name,
each serialized with sorted JSON keys, sha256'd. Sharing it is the point - a
listing that re-serializes or re-orders must read as the same surface to both
rules, and two independently-written canonicalizers that drift apart would
manufacture false positives that get this control removed.

What the fingerprint covers: every field of every listing entry - tool names,
input schemas, and **descriptions**, because a description is free text that
steers the model and a server that rewrites its tool descriptions under
admission has changed the interface the operator reviewed. A tool that
disappears changes the fingerprint like any other edit: removal is drift. A
rename is not special-cased - it is a removal plus an addition, and the
fingerprint changes either way.

Semantics:

- first listing for a server: record the fingerprint, return None
  (admission). "I have no baseline" and "the baseline changed" are different
  branches; a rule that collapses them either blocks every server on first
  sight or never fires.
- later listing with the same fingerprint: None. Same listing, serialized
  differently (key order permuted, tools reordered), is still the same
  fingerprint - canonicalization is the whole game.
- later listing with a different fingerprint: BLOCK, and the *old* baseline
  stands. The block persists until re-admission, which is a deliberate
  re-install of this rule (a fresh factory call, as with
  ``mcp_consent_budget``'s fresh budget), never a silent slide to the new
  surface. A silent change is a new admission decision, not a continuation
  of the old one.
- a listing the rule cannot parse, from a server it already admitted: BLOCK,
  not silence. ``mcp_tool_pinning``'s rule is the model - unusable input on a
  pinned subject is a failure, and an admitted server whose surface cannot be
  verified has not proven itself. Before admission, an unusable listing is
  ignored and records nothing: a malformed listing can therefore never
  establish *or* reset a baseline, and an attacker who sends one first cannot
  reset admission for the real listing behind it.

Coupling with the capability lease (R6a): a lease issued for a reviewed
surface must not survive that surface changing underneath it. Pass the same
:class:`~mcp_capability_lease.LeaseRegistry` the lease rule reads as
``leases=`` and every drift - or unusable listing from an admitted server -
revokes all of that server's leases before the BLOCK is returned, so the old
grant dies with the old surface instead of quietly covering calls to the new
one. Re-admission then re-issues the lease (``registry.issue``) alongside the
fresh baseline. Without a registry the rule still detects drift; only the
revocation is absent.

The listing event shape is fixed: action ``tools/list`` (the MCP protocol
method for a listing) with the listing under ``args["__tools__"]`` and the
server under ``args["__origin__"]``. A listing event has no tool name to mine
a server prefix from - unlike a call's dotted action name - so an unlabelled
listing is out of scope (``mcp_trust_registry`` is the rule that refuses
unlabelled traffic), as is any event with another action: calls are the pin
rule's ground, not this one's.

State lives in the factory closure, as in ``mcp_consent_budget`` and
``host_fanout_guard``: two rules built from separate factory calls never
share a baseline, so one server's admission cannot anchor another's. The
rule never raises: args are attacker-influenced and may be any type, and
every reader narrows to "unusable" rather than touching a key blindly.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from .mcp_capability_lease import LeaseRegistry
from .mcp_server_attestation import _ORIGIN_KEY, _TOOLS_KEY, listing_digest

POLICY_ID = "mcp_surface_baseline"

# The action a listing event carries: the MCP protocol method for listing a
# server's tools, not a tool call. This is what makes the event shapes - and
# therefore this rule and the call-side mcp_tool_pinning - disjoint.
_LISTING_ACTION = "tools/list"


def _listing_server(args: object) -> Optional[str]:
    """Resolve the server a listing event belongs to: the explicit label.

    A listing event's action is the protocol method (``tools/list``), not a
    server-qualified tool name, so there is no dotted prefix to fall back to -
    unlike a call event. Args are attacker-influenced and may be anything; a
    non-mapping args or a blank/non-str label means "no server named", which
    the caller treats as out of scope rather than refusing on the label's
    behalf (mcp_trust_registry owns that refusal).
    """
    if not isinstance(args, dict):
        return None
    origin = args.get(_ORIGIN_KEY)
    if isinstance(origin, str) and origin.strip():
        return origin
    return None


def mcp_surface_baseline(leases: Optional[LeaseRegistry] = None) -> Rule:
    """Rule: admit a server's first listing, block any later surface change.

    Returns None on the first parseable listing for a server (admission: the
    fingerprint is recorded) and on later listings with the same fingerprint,
    however re-serialized. Blocks a later listing whose fingerprint differs -
    added, removed, or renamed tools, changed schemas, changed descriptions -
    and a listing that cannot be parsed from a server already admitted. With
    ``leases`` set, every block also revokes that server's leases so the old
    grant cannot cover the new surface. The baseline is per factory call and
    is never rewritten by a drift: re-admission is a fresh rule.
    """
    baselines: Dict[str, str] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != _LISTING_ACTION:
            return None
        server = _listing_server(event.args)
        if server is None:
            return None
        tools = event.args.get(_TOOLS_KEY) if isinstance(event.args, dict) else None
        fingerprint = listing_digest(tools)
        baseline = baselines.get(server)
        if fingerprint is None:
            if baseline is None:
                # Before admission an unusable listing records nothing: it
                # must not be able to anchor - or reset - a baseline.
                return None
            if leases is not None:
                leases.revoke(server)
            return Decision.block(
                "{}: unusable tool listing for {} (admitted surface not"
                " verifiable)".format(POLICY_ID, server),
                policy_id=POLICY_ID,
                attributed_to=_TOOLS_KEY,
            )
        if baseline is None:
            baselines[server] = fingerprint
            return None
        if fingerprint == baseline:
            return None
        if leases is not None:
            leases.revoke(server)
        return Decision.block(
            "{}: tool surface drift for {} (re-admission required)".format(
                POLICY_ID, server
            ),
            policy_id=POLICY_ID,
            attributed_to=_TOOLS_KEY,
        )

    return rule
