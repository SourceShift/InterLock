"""SSRF guard: block egress to private / loopback / link-local addresses.

An allowlist on *names* (see :func:`interlock.detectors.data_egress.network_egress_guard`)
still lets an attacker through when the destination is written as an IP literal:
``http://169.254.169.254/latest/meta-data/`` is the cloud metadata endpoint, a
literal the allowlist never sees because there is no hostname to match. This
rule covers that gap by judging the destination as an address rather than a
name. Only IP *literals* are decided here — a domain name is left to the
allowlist, whose job it is to say which names are permitted.

The check sits on the egress action, before the socket is opened, so the
request never reaches the loopback service, the RFC1918 host, the link-local
metadata endpoint, or a reserved range. Non-egress actions, an absent or blank
destination, and any value that will not parse all return None (no opinion),
so the rule only ever fires on a destination it can prove is non-public, and
never raises on odd input.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "private_ip_egress"

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
    """Hostname for an IP-literal destination, else None.

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


def _non_public_reason(ip: str, address: Any) -> Optional[str]:
    """Human-readable reason string when *address* is non-public, else None."""
    flags = []
    if address.is_private:
        flags.append("private")
    if address.is_loopback:
        flags.append("loopback")
    if address.is_link_local:
        flags.append("link-local")
    if address.is_reserved:
        flags.append("reserved")
    if not flags:
        return None
    return "{} is {}".format(ip, ", ".join(flags))


def private_ip_egress_guard() -> Rule:
    """Build a Rule that blocks egress whose destination is a non-public IP.

    For an action in :data:`EGRESS_ACTIONS`, the destination is read from the
    first present key in :data:`DESTINATION_KEYS`. When it parses as an IP
    literal that is private, loopback, link-local, or reserved the rule returns
    a BLOCK. A domain name (not an IP literal), a non-egress action, and a
    missing or unparseable destination all yield None.
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

        why = _non_public_reason(host, address)
        if why is None:
            return None
        return Decision.block(
            reason="{}: {}".format(POLICY_ID, why),
            policy_id=POLICY_ID,
        )

    return rule
