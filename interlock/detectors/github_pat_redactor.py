"""GitHub token redaction: strip personal/OAuth access tokens out of egress, don't block.

A GitHub token is a bearer credential with the full reach of the account that
minted it: ``ghp_`` for a classic personal access token, ``gho_`` for an OAuth
token, ``ghu_`` for a user-to-server token, ``ghs_`` for a server-to-server
token, and ``ghr_`` for a refresh token. The prefix states the token's class,
and the thirty-six-character body is the secret. A token that lands in an
outbound body or a log line is live material - anyone who reads the payload can
authenticate as the token's owner until it is revoked - so unlike a password it
does not sit quietly in a hash; it is usable the moment it is sent.

This rule assumes the send is legitimate and the token is accidental, the same
posture as the JWT, DB-URI, and ARN redactors: it masks the token in place and
lets the (now-clean) request proceed. That is the MODIFY point of the
allow/modify/block spectrum - the credential is neutralised without failing the
transport, so a token that was copied into an outbound payload by mistake does
not take the agent's work down with it.

The pattern is anchored on the five fixed ``gh*_`` prefixes and requires the
exact thirty-six-character body GitHub emits, so prose, hostnames, and
vendor-shaped strings that merely contain "ghp_" are not touched. No validation
follows - every regex match is masked.

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

POLICY_ID = "github_pat_redact"

# The mask a redacted GitHub token is replaced with.
MARKER = "[REDACTED GH_TOKEN]"

# ``gh<p|o|u|s|r>_`` followed by the exact thirty-six-character body GitHub
# emits. The fixed prefix plus the exact body length is what keeps a short
# ``ghp_...`` fragment from matching; no validation for a live token follows -
# every regex match is masked.
PATTERN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")

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


def github_pat_redactor() -> Rule:
    """Build a Rule that masks GitHub tokens out of an outbound action's payload.

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
            changed, reason="github_pat_redact", policy_id=POLICY_ID,
            attributed_to=next(iter(changed)),
        )

    return rule
