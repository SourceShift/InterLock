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

import ipaddress
from typing import Any, Optional
from urllib.parse import urlparse

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


def _destination(args: Any) -> Optional[str]:
    """First usable destination string in *args*, else None.

    A key whose value is not a non-blank string (None, an int, a nested
    container) is skipped rather than stringified.
    """
    if not isinstance(args, dict):
        return None
    for key in DESTINATION_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _host_of(destination: str) -> Optional[str]:
    """Hostname carried by *destination*, else None.

    A URL is parsed to its hostname. A bare ``host`` / ``host:port`` / ``host/path``
    string (no scheme, which urlparse cannot resolve a hostname from) is split
    by hand so a scheme-less literal is still judged. Anything that will not
    parse returns None.
    """
    try:
        parsed = urlparse(destination)
        host = parsed.hostname  # may raise on malformed IPv6 brackets
    except ValueError:
        return None

    if host:
        return host

    if "://" in destination:  # had a scheme but no extractable host
        return None

    # No scheme: the whole string is authority + path; strip the path then port.
    bare = destination.split("/", 1)[0]
    if "@" in bare:  # userinfo@host
        bare = bare.rsplit("@", 1)[1]
    if bare.startswith("["):  # [::1]:port
        end = bare.find("]")
        return bare[1:end] if end != -1 else None
    return bare.split(":", 1)[0] or None


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

        destination = _destination(getattr(event, "args", None))
        if destination is None:
            return None

        host = _host_of(destination)
        if not host:
            return None

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None  # a domain name: the allowlist's business, not ours

        return Decision.block(
            reason="{}: {} is a raw {} literal, not a named host".format(
                POLICY_ID, host, "IPv6" if address.version == 6 else "IPv4"
            ),
            policy_id=POLICY_ID,
        )

    return rule
