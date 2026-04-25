"""Email address redaction guard: mask addresses out of egress, don't block.

An email address is the most portable identifier a person has. It is a login on
its own, the recovery channel for everything else, and the key that joins one
leaked record to the next - a support ticket here, a CRM row there - into a
profile. It is also the single most common thing an LLM copies verbatim out of
the context it was handed: a record it was asked to summarise, a log line it
was asked to explain, a contact it echoed back. The leak is almost always
incidental rather than deliberate.

That makes this the MODIFY point of the allow/modify/block spectrum. The send
is assumed legitimate and the address incidental, so the rule masks each match
in place with :data:`MARKER` and lets the (now-clean) request proceed. A user
who pasted a contact into a prompt does not take the agent's work down with it.

Only the content keys of an egress action are scanned. Destination keys
(``url``, ``endpoint``, ``uri``, ``host``) are deliberately left alone:
rewriting where a request goes would break the send the redaction was meant to
preserve, and the destination is the egress allowlist's concern, not this
rule's.

The pattern is shape-only and deliberately unvalidated - every regex match is
masked, with no disposable-domain list and no MX check, because a false
positive here costs only a literal ``[REDACTED EMAIL]`` while a false negative
costs the identifier. The ``\\b`` anchors keep the pattern from slicing an
address out of a larger token such as a URL query fragment.

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

POLICY_ID = "email_redact"

# The mask a redacted address is replaced with. Contains no ``@`` or dot, so a
# second pass over the same payload cannot re-match it.
MARKER = "[REDACTED EMAIL]"

# Broad email shape: a local part of RFC-5322 atoms, an ``@``, a dotted domain,
# and a TLD-leaning tail of two or more letters. Every match is masked; no
# validation follows.
PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

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


def email_pii_redactor() -> Rule:
    """Build a Rule that masks email addresses out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the address
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
        return Decision.modify(changed, reason="email_redact", policy_id=POLICY_ID)

    return rule
