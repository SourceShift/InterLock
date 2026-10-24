"""DNS-rebinding guard: block egress whose destination is a bare IP literal.

An allowlist keyed on *names* (see :func:`interlock.detectors.data_egress.network_egress_guard`)
can be defeated by DNS rebinding: the attacker registers ``evil.example`` so it
resolves to a public address when the allowlist is checked, then flips the record
to an internal address before the connection is opened. The same class of bypass
is available trivially to anyone who simply writes the destination as an address
instead of a name — there is no hostname for the allowlist to match at all.

This rule closes that gap by refusing IP *literals* outright, public or private.
A caller that must reach a host has to name it, which keeps the string the
allowlist matches on and the address actually dialled in the same namespace.
Names themselves are left to the allowlist, whose job it is to say which are
permitted; this rule has an opinion only on destinations it can prove are raw
addresses.

The check sits on the egress action, before the socket is opened. Non-egress
actions, an absent or blank destination, and values that will not parse all
return None (no opinion), so the rule never raises on odd input.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from .._net import ip_literal
from .._url import destination_host
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "raw_ip_egress"

# The egress action names this guard recognises. Kept to unambiguous transport
# verbs so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "fetch", "request", "send", "upload",
})

# Argument keys that may carry the destination, tried in this order.
DESTINATION_KEYS = ("url", "endpoint", "uri", "host", "address")


def _destination(args: Any) -> Optional[Tuple[str, str]]:
    """First usable (argument name, destination) pair in *args*, else None.

    A key whose value is not a non-blank string (None, an int, a nested
    container) is skipped rather than stringified. The argument name rides
    along so a denial can name the input that triggered it.
    """
    if not isinstance(args, dict):
        return None
    for key in DESTINATION_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return key, value.strip()
    return None


def raw_ip_egress_guard() -> Rule:
    """Build a Rule that blocks egress to a bare IP literal.

    For an action in :data:`EGRESS_ACTIONS`, the destination is read from the
    first present key in :data:`DESTINATION_KEYS`. When its host parses as an
    IPv4 or IPv6 literal (public or private alike) the rule returns a BLOCK: a
    domain allowlist cannot govern a raw address, so callers must use named
    hosts. A domain name, a non-egress action, and a missing or unparseable
    destination all yield None.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        dest = _destination(getattr(event, "args", None))
        if dest is None:
            return None
        dest_key, destination = dest

        host = destination_host(destination)
        if not host:
            return None

        address = ip_literal(host)  # every spelling a client dials, not just dotted quads
        if address is None:
            return None  # a domain name: the allowlist's business, not ours

        return Decision.block(
            reason="{}: {} is a raw {} literal, not a named host".format(
                POLICY_ID, host, "IPv6" if address.version == 6 else "IPv4"
            ),
            policy_id=POLICY_ID,
            attributed_to=dest_key,
        )

    return rule
