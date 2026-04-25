"""Egress scheme allowlist: only http(s) destinations may be sent to.

The destination allowlists (see
:func:`interlock.detectors.data_egress.network_egress_guard`) and the SSRF guard
(see :func:`interlock.detectors.private_ip_egress_guard`) both judge *where* a
request goes. This rule judges *how* it is carried: the URL scheme. A scheme is
a capability, and most of the dangerous ones reach past the network stack
entirely. ``file:///etc/passwd`` reads the local disk, ``gopher://`` and
``dict://`` speak arbitrary bytes to an arbitrary port (the classic pivot to an
internal service), ``ftp://`` moves files to a third party, and ``data:``
carries an inline payload the transport never had to fetch. Each of these
arrives as a perfectly ordinary-looking ``url`` argument, so a host allowlist
never sees the danger.

The check sits on the egress action, before the scheme is dispatched, so an
unvetted scheme never reaches its handler. Only ``http`` and ``https`` are
permitted; a scheme that is anything else — including blank — is blocked.
Non-egress actions, an absent or blank destination, and any destination that
will not parse all return None (no opinion), so the rule only ever fires on a
destination whose scheme it can prove is not http(s), and never raises on odd
input.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "url_scheme"

# The egress action names this guard recognises. Kept to unambiguous transport
# verbs so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "fetch", "request", "send", "upload",
})

# Argument keys that may carry the destination, tried in this order.
DESTINATION_KEYS = ("url", "endpoint", "uri", "host", "address")

# The only schemes permitted to leave the process.
ALLOWED_SCHEMES = frozenset({"http", "https"})


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


def _scheme_of(destination: str) -> str:
    """Lower-cased scheme of *destination*, or "" when it carries none.

    ``urlparse`` only recognises a scheme matching ``[a-zA-Z][a-zA-Z0-9+.-]*``,
    so ``data:text/html,...`` resolves to ``data`` while a bare
    ``api.example.com/v1`` resolves to the empty string. Both fall outside the
    allowlist and are blocked. A destination whose brackets are malformed
    raises ValueError, which the caller treats as unparseable (None).
    """
    return urlparse(destination).scheme.lower()


def url_scheme_guard() -> Rule:
    """Build a Rule that blocks egress to a non-http(s) URL scheme.

    For an action in :data:`EGRESS_ACTIONS`, the destination is read from the
    first present key in :data:`DESTINATION_KEYS`. When its scheme is absent or
    is anything other than ``http`` / ``https`` the rule returns a BLOCK; a
    non-egress action and a missing, blank, or unparseable destination all
    yield None.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        destination = _destination(getattr(event, "args", None))
        if destination is None:
            return None

        try:
            scheme = _scheme_of(destination)
        except ValueError:
            return None  # unparseable: nothing we can prove about the scheme

        if scheme in ALLOWED_SCHEMES:
            return None

        why = "scheme {!r} is not http(s)".format(scheme) if scheme else "missing scheme"
        return Decision.block(
            reason="{}: {}".format(POLICY_ID, why),
            policy_id=POLICY_ID,
        )

    return rule
