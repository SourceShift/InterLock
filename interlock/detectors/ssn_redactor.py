"""US Social Security Number redaction guard: mask SSNs out of egress, don't block.

A US Social Security Number is a bare nine-digit identifier with no structure of
its own to protect it - no ``@``, no dotted domain, no checksum a reader would
notice is wrong. In a payload it looks like any other number, which is exactly
why an LLM copies one verbatim out of the record it was asked to summarise: a
tax form, an onboarding row, a support log. The leak is incidental, not
deliberate, and the same nine digits are enough to open accounts in the
subject's name.

That makes this the MODIFY point of the allow/modify/block spectrum. The send is
assumed legitimate and the number incidental, so the rule masks each match in
place with :data:`MARKER` and lets the (now-clean) request proceed. A user who
pasted an applicant record into a prompt does not take the agent's work down
with it.

Only the content keys of an egress action are scanned. Destination keys
(``url``, ``endpoint``, ``uri``, ``host``) are deliberately left alone:
rewriting where a request goes would break the send the redaction was meant to
preserve, and the destination is the egress allowlist's concern, not this
rule's.

The pattern is shape-only and deliberately unvalidated - every ``###-##-####``
match is masked, with no area-number rules, no SSA exclusion list (000, 666,
900-999 are all masked), and no validity check, because a false positive here
costs only a literal ``[REDACTED SSN]`` while a false negative costs the
identifier. The ``\\b`` anchors and the fixed digit counts keep the pattern from
slicing nine digits out of a longer token such as an order number or a date.

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

POLICY_ID = "ssn_redact"

# The mask a redacted number is replaced with. Contains no digits, so a second
# pass over the same payload cannot re-match it.
MARKER = '[REDACTED SSN]'

# Shape-only SSN: three digits, a hyphen, two digits, a hyphen, four digits.
# Every match is masked; no area-number or serial validation follows.
PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

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


def ssn_redactor() -> Rule:
    """Build a Rule that masks US SSNs out of an outbound action's payload.

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
        return Decision.modify(changed, reason="ssn_redact", policy_id=POLICY_ID)

    return rule
