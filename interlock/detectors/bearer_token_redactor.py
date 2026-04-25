"""Authorization Bearer token redaction: strip the credential, keep the send.

An ``Authorization: Bearer <token>`` header is a live credential with no
structure worth validating - the token is opaque, and whoever reads it can use
it. The permission to act is the value itself, so the damage is done the moment
one leaves the process in an ``http_post`` body or a log line. Unlike a
block-first guard, this rule assumes the send is legitimate and the token is
accidental: it masks the token in place and lets the (now-clean) request
proceed. That is the MODIFY point of the allow/modify/block spectrum - the
exfiltration is neutralised without failing the transport, so a token that was
copied into an outbound payload by mistake does not take the agent's work down
with it.

The pattern anchors on the literal ``Bearer`` scheme followed by whitespace and
a token body of at least sixteen characters drawn from the RFC 6750 b64token
alphabet, so a bare ``Bearer`` in prose or a short placeholder word is not
touched. No validation follows - every regex match is masked.

Only the content keys of an egress action are scanned. Destination keys (``url``,
``endpoint``, ``uri``, ``host``) are deliberately left alone: rewriting where a
request goes would break the send the redaction was meant to preserve, and the
destination is the egress allowlist's concern, not this rule's.

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

POLICY_ID = "bearer_token_redact"

# The mask a redacted credential is replaced with.
MARKER = "[REDACTED BEARER]"

# ``Bearer`` (RFC 6750 scheme) + whitespace + a token body of at least sixteen
# b64token characters, optionally padded with ``=``. The sixteen-character floor
# keeps a bare scheme name or a short placeholder from matching; no validation
# follows - every regex match is masked.
PATTERN = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*")

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


def bearer_token_redactor() -> Rule:
    """Build a Rule that masks Bearer credentials out of an outbound payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the token
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
            changed, reason="bearer_token_redact", policy_id=POLICY_ID
        )

    return rule
