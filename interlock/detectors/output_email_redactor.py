"""Generated-output email redaction: mask addresses out of egress, don't block.

An email address is the most portable identifier a person owns - a login, a
recovery channel, and the join key that stitches one leaked record to the next.
It is also the single most common thing a model copies verbatim out of the
context it was handed: a record it was asked to summarise, a log line it was
asked to explain, a contact it echoed back into its answer. The address was not
exfiltrated on purpose; it simply rode out inside legitimate output.

That makes this the MODIFY point of the allow/modify/block spectrum. The relay
is assumed legitimate and the address incidental, so the rule masks each match
in place with :data:`MARKER` and lets the (now-clean) send proceed. Blocking
would be wrong: the output itself is the agent's payload, not an attack, and the
useful context around the address must survive.

Only the content keys of an egress action are scanned. Destination keys
(``url``, ``endpoint``, ``uri``, ``host``) are deliberately left alone:
rewriting where output goes would break the send the redaction was meant to
preserve, and the destination is the egress allowlist's concern, not this
rule's.

The pattern is shape-only and deliberately unvalidated - every regex match is
masked, with no disposable-domain list and no MX check, because a false positive
here costs only a literal ``[REDACTED EMAIL]`` while a false negative costs the
identifier. The ``\\b`` anchors keep the pattern from slicing an address out of
a larger token such as a URL query fragment.

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

POLICY_ID = "output_email_redact"

# The mask a redacted address is replaced with. Contains no ``@`` or dot, so a
# second pass over the same payload cannot re-match it.
MARKER = "[REDACTED EMAIL]"

# Broad email shape: a local part of RFC-5322 atoms, an ``@``, a dotted domain,
# and a TLD-leaning tail of two or more letters. Every match is masked; no
# validation follows.
PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Egress action names this guard recognises. The result-side verbs are the
# reason this rule exists - the generated output is leaving - and ``http_post``
# covers the same relaying path when the output is forwarded straight from a
# tool call. A same-named in-house tool is not shadowed because only an action
# carrying a content key is ever modified.
EGRESS_ACTIONS = frozenset({
    "respond", "output", "return", "tool_result", "http_post",
})

# Argument keys that may carry outbound content. Destination keys are absent by
# design; only a str under one of these is scanned.
CONTENT_KEYS = (
    "data", "body", "payload", "content", "text", "message", "msg", "value",
)


def output_email_redactor() -> Rule:
    """Build a Rule that masks email addresses out of an egress action's payload.

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
        return Decision.modify(
            changed, reason="output_email_redact", policy_id=POLICY_ID
        )

    return rule
