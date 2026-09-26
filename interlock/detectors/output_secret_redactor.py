"""Output secret redaction: mask vendor keys out of tool RESULTS, don't block.

A tool result is where secrets surface by accident. The model calls a tool, the
tool returns a config dump, an error string, or an environment listing, and a
live credential - an AWS access key id, an OpenAI-style ``sk-`` token, a GitHub
personal access token - is sitting in the text the agent is about to relay
onward through ``respond``, ``output``, or a log line. Nothing was exfiltrated
on purpose; the secret simply rode out inside legitimate output. Egress at this
point is already in flight, so the leak is complete the moment the clean result
is forwarded to the next hop.

Like the JWT, DB-URI, and ARN redactors, this rule assumes the relay is
legitimate and the credential is accidental: it masks the key in place and lets
the (now-clean) send proceed. That is the MODIFY point of the allow/modify/block
spectrum - the credential is neutralised without failing the transport, so a
result that happened to contain a key does not take the agent's work down with
it. Blocking here would be wrong: the tool result itself is the agent's payload,
not an attack, and the useful context around the key must survive.

Only the content keys of an egress action are scanned. Destination keys (``url``,
``endpoint``, ``uri``, ``host``) are deliberately left alone: rewriting where a
result is sent would break the send the redaction was meant to preserve, and the
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

POLICY_ID = "output_secret_redact"

# The mask a redacted secret is replaced with.
MARKER = "[REDACTED SECRET]"

# Vendor-shaped API keys that appear verbatim in tool output: an AWS access key
# id (``AKIA`` plus sixteen upper-case alphanumerics), an OpenAI-style key
# (``sk-`` plus twenty or more alphanumerics), and a GitHub personal access
# token (``ghp_`` plus exactly thirty-six alphanumerics). The ``\b`` anchors
# keep the match from bleeding into a longer word. No validation follows -
# every regex match is masked.
PATTERN = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36})\b")

# Egress action names this guard recognises. The result-side verbs are the
# reason this rule exists - a call already completed and its output is leaving -
# and ``http_post`` is included so the same relaying path is covered when the
# result is forwarded straight from a tool call. A same-named in-house tool is
# not shadowed because only an action carrying a content key is ever modified.
EGRESS_ACTIONS = frozenset({
    "tool_result", "return", "respond", "output", "log", "http_post",
})

# Argument keys that may carry outbound content. Destination keys are absent by
# design; only a str under one of these is scanned.
CONTENT_KEYS = (
    "data", "body", "payload", "content", "text", "message", "msg", "value",
)


def output_secret_redactor() -> Rule:
    """Build a Rule that masks vendor keys out of an egress action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the secret
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
            changed, reason="output_secret_redact", policy_id=POLICY_ID,
            attributed_to=next(iter(changed)),
        )

    return rule
