"""S3 presigned-URL signature redaction: strip the capability, keep the send.

A presigned S3 URL embeds its authorization in the query string, under the
``X-Amz-Signature`` parameter. Unlike a long-lived key, the signature is a
time-limited capability: it grants whoever holds it read (or write) access to a
single object until it expires, with no further credential required. The leak is
complete the moment the URL leaves the process in an ``http_post`` body or a log
line - anyone who reads the payload can replay the URL until the clock runs out.

Like the Bearer, basic-auth, and JWT redactors, this rule assumes the send is
legitimate and the URL is accidental: it masks the signature in place and lets
the (now-clean) request proceed. That is the MODIFY point of the
allow/modify/block spectrum - the capability is neutralised without failing the
transport, so a presigned URL that was copied into an outbound payload by
mistake does not take the agent's work down with it. The rest of the URL - the
bucket, key, and ``X-Amz-*`` siblings such as ``X-Amz-Expires`` - survives; only
the signature itself is lost.

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

POLICY_ID = "s3_presigned_redact"

# The mask a redacted signature is replaced with.
MARKER = "[REDACTED PRESIGN]"

# An ``X-Amz-Signature`` query parameter on a presigned URL. The leading ``[?&]``
# anchors the match to a real query delimiter, so a bare ``X-Amz-Signature=``
# appearing mid-path is not touched. The value is the URL-encoded hex signature
# (``%`` permitted), floored at sixteen characters so a truncated or placeholder
# value does not match. No validation follows - every regex match is masked.
PATTERN = re.compile(r"[?&]X-Amz-Signature=[A-Za-z0-9%]{16,}")

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


def s3_presigned_redactor() -> Rule:
    """Build a Rule that masks S3 presigned signatures out of an outbound payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the signature
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
            changed, reason="s3_presigned_redact", policy_id=POLICY_ID
        )

    return rule
