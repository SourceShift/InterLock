"""Google API key redaction: mask keys out of egress payloads, don't block.

A Google API key is a bearer credential with no expiry and no bind to a caller:
whoever holds the string can spend the quota it is attached to, and for a key
scoped to Maps, Gemini, or a billing-enabled project the ceiling is whatever the
project allows. The key is self-identifying - every one of them begins ``AIza``
and is followed by exactly 35 characters from the base64url alphabet - so no
lookup or validity check is needed to find one; the prefix is a precise, cheap
anchor that nothing else in ordinary text shares.

Like the JWT, AWS-ARN, and DB-URI redactors, this rule assumes the send is
legitimate and the key is accidental: a key pasted into an outbound body, a log
line, or a tool argument by mistake. It masks the key in place and lets the
(now-clean) request proceed. That is the MODIFY point of the allow/modify/block
spectrum - the credential exposure is neutralised without failing the transport,
so an accidentally-included key does not take the agent's work down with it.

Only the content keys of an egress action are scanned. Destination keys (``url``,
``endpoint``, ``uri``, ``host``) are deliberately left alone: rewriting where a
request goes would break the send the redaction was meant to preserve, and the
destination is the egress allowlist's concern, not this rule's.

Google documents a 35-character body after the ``AIza`` prefix, so the length is
pinned rather than left open; a shorter lookalike in prose is not a key and is
not touched. No validation follows - every regex match is masked.

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

POLICY_ID = "google_key_redact"

# The mask a redacted API key is replaced with.
MARKER = "[REDACTED GOOGLE_KEY]"

# ``AIza`` followed by exactly 35 base64url characters, bounded by non-word
# neighbours. The fixed prefix plus the pinned body length keep prose and
# vendor-shaped identifiers from matching; no validity check follows - every
# regex match is masked.
PATTERN = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")

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


def google_api_key_redactor() -> Rule:
    """Build a Rule that masks Google API keys out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the key stripped
    and the destination untouched. Otherwise - a clean payload, a non-egress
    action, or a non-dict ``args`` - it returns None (no opinion).
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
            changed, reason="google_key_redact", policy_id=POLICY_ID
        )

    return rule
