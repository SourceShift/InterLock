"""US/E.164 phone redaction guard: mask phone numbers out of egress payloads.

A phone number is a strong identifier. On its own it is public-ish, but paired
with a name it is the recovery key for almost every account, the input to a SIM
swap, and the pivot that turns a leak in one system into a live attack on
another. A number that rides out in an ``http_post`` body or a log line is
therefore a privacy problem with a security edge - and it is almost always
accidental, a model echoing the record it was asked to summarise rather than an
attacker exfiltrating on purpose.

This rule sits at the MODIFY point of the allow/modify/block spectrum: it
rewrites each number to a marker in place and lets the (now-clean) send proceed.
The leak is neutralised without failing the transport, so a phone number copied
into an outbound payload by mistake does not take the agent's work down with it.

Only the content keys of an egress action are scanned. Destination keys (``url``,
``endpoint``, ``uri``, ``host``) are deliberately left alone: rewriting where a
request goes would break the send the redaction exists to preserve, and the
destination is the egress allowlist's concern, not this rule's.

The pattern is shape-only. A phone number has no checksum to validate against,
and the region-code space is too sparse to gate on without rejecting real,
unfamiliar numbers, so every match is masked - no extra validation. The
lookarounds only stop a match from starting or ending in the middle of a longer
digit run, so an order id or a timestamp is not chopped into a false phone. A
false positive costs a literal ``[REDACTED PHONE]`` in the payload; a false
negative costs the identifier, so the rule leans toward masking.

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

POLICY_ID = "phone_redact"

# The mask a redacted phone number is replaced with. Contains no digits, so a
# second pass over the same payload cannot re-match it.
MARKER = "[REDACTED PHONE]"

# North-American / E.164 phone shape: an optional ``+1`` or ``1`` country code,
# an optional parenthesised area code, and three separator-flexible groups. The
# digit lookarounds keep a match from slicing a longer digit run (an id, a
# timestamp) into a false positive; no checksum or region gate follows.
PATTERN = re.compile(
    r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
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


def us_phone_redactor() -> Rule:
    """Build a Rule that masks phone numbers out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the number
    stripped and the destination untouched. Otherwise - a clean payload, a
    non-egress action, or a non-dict ``args`` - it returns None (no opinion).
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
        return Decision.modify(
            changed, reason="phone_redact", policy_id=POLICY_ID,
            attributed_to=next(iter(changed)),
        )

    return rule
