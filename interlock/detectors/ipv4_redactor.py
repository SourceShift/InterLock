"""Private IPv4 redaction guard: mask internal addresses out of egress, don't block.

A private IPv4 address is self-identifying by its RFC-1918 range: ``10/8``,
``192.168/16``, or ``172.16/12``. Those ranges are never routable on the public
internet, so an address inside one describes internal network topology - a host
on the corporate VPC, a database node, a service mesh peer. Leaking one in an
outbound payload hands an adversary a map of the private network to pivot
through, but does not itself grant access the way a credential would.

That makes this the MODIFY point of the allow/modify/block spectrum: the send
is assumed legitimate and the address incidental, so the rule masks each match
in place and lets the (now-clean) request proceed. A payload that happened to
quote a log line or a config snippet from inside the VPC does not take the
agent's work down with it.

Only the content keys of an egress action are scanned. Destination keys
(``url``, ``endpoint``, ``uri``, ``host``) are deliberately left alone:
rewriting where a request goes would break the send the redaction was meant to
preserve, and the destination is the egress allowlist's concern, not this
rule's. The pattern is deliberately permissive and unvalidated - every regex
match is masked, because a defensive false positive here merely over-redacts a
string that already looked like an internal address.

Reads only str values under the content keys of a dict ``args``; an int, None,
or nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion. Non-egress actions return None. The rule never raises.
"""
from __future__ import annotations

import re
from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "ipv4_redact"

# The mask a redacted address is replaced with.
MARKER = "[REDACTED IP]"

# RFC-1918 private ranges: 10.0.0.0/8, 192.168.0.0/16, and 172.16.0.0/12. The
# octet groups are bounded but not range-validated (a group may be 999); every
# match is masked, so an over-broad hit costs only redaction, never a crash.
PATTERN = re.compile(
    r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)

# Egress action names this guard recognises. Kept to verbs that unambiguously
# leave the process, so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "fetch", "request", "send", "upload",
    "log", "write",
})

# Argument keys that may carry outbound content. Destination keys are absent by
# design; only a str under one of these is scanned.
CONTENT_KEYS = (
    "data", "body", "payload", "content", "text", "message", "msg", "value",
)


def ipv4_redactor() -> Rule:
    """Build a Rule that masks private IPv4s out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the internal
    address stripped and the destination untouched. Otherwise - a clean
    payload, a non-egress action, or a non-dict ``args`` - it returns None
    (no opinion).
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        changed: Dict[str, str] = {}
        for key in CONTENT_KEYS:
            value = args.get(key)
            if not isinstance(value, str):
                continue
            cleaned, hits = PATTERN.subn(MARKER, value)
            if hits:
                changed[key] = cleaned

        if not changed:
            return None
        return Decision.modify(changed, reason="ipv4_redact", policy_id=POLICY_ID)

    return rule
