"""Database-URI credential redaction: strip user:pass out of egress payloads.

A database connection string carries its credentials inline, in the URI itself:
``postgres://admin:s3cr3t@10.0.0.5:5432/prod``. There is no separate secret to
look up and no signature to verify - the password is right there in the text of
whatever argument the agent is about to hand to ``http_post`` or write to a log.
Config dumps, error strings, and copied connection snippets all leak it the same
way, and the leak is complete the moment the string leaves the process.

Like the JWT redactor, this rule assumes the send is legitimate and the
credential is accidental: it masks the ``user:password@`` portion in place and
lets the (now-clean) request proceed. That is the MODIFY point of the
allow/modify/block spectrum - the exfiltration is neutralised without failing
the transport, so a connection string that was pasted into an outbound body by
mistake does not take the agent's work down with it.

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

POLICY_ID = "db_uri_redact"

# The mask a redacted connection string is replaced with.
MARKER = "[REDACTED DB_URI]"

# A database URI whose authority embeds a username and password. The two
# ``[^\s:@/]+`` segments either side of an explicit ``:`` are what make this
# credential-shaped rather than merely vendor-shaped: ``postgres://host/db``
# (no credentials) cannot match, because nothing supplies the password half.
# ``[^\s/]+`` for the host stops at the first path/whitespace boundary. No
# validation follows - every regex match is masked.
PATTERN = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
    r"://[^\s:@/]+:[^\s:@/]+@[^\s/]+"
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


def db_uri_redactor() -> Rule:
    """Build a Rule that masks DB-URI credentials out of an outbound payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the credential
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
            changed, reason="db_uri_redact", policy_id=POLICY_ID,
            attributed_to=next(iter(changed)),
        )

    return rule
