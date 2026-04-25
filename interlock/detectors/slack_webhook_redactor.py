"""Slack webhook redaction guard: mask webhook URLs out of egress, don't block.

A Slack incoming-webhook URL is a bearer capability: anyone holding
``https://hooks.slack.com/services/<T>/<B>/<secret>`` can post arbitrary
messages into that workspace channel. The secret is the URL itself - there is no
separate token - so a webhook that leaks inside an outbound payload is a
credential leak, not merely an information disclosure. Yet the send carrying it
is usually legitimate: an agent quoting a config snippet, a log line, or a
support ticket that happens to embed the URL. Blocking the send punishes the
agent's actual task for an incidental bystander string.

That makes this the MODIFY point of the allow/modify/block spectrum: mask each
webhook match in place and let the (now-clean) request proceed. The message
still goes out; only the capability is stripped.

Only the content keys of an egress action are scanned. Destination keys
(``url``, ``endpoint``, ``uri``, ``host``) are deliberately left alone: rewriting
where a request goes would break the send the redaction was meant to preserve,
and the destination is the egress allowlist's concern, not this rule's. The
pattern is deliberately permissive and unvalidated - every regex match is
masked - because the only cost of a false positive is over-redacting a string
that already looked like a webhook.

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

POLICY_ID = "slack_webhook_redact"

# The mask a redacted webhook URL is replaced with.
MARKER = '[REDACTED SLACK_WEBHOOK]'

# A Slack incoming-webhook URL: the fixed host plus the /services/<team>/<bot/
# <secret> path. The trailing 20-char-or-more run of path characters is what
# carries the capability; the pattern is unvalidated, so every match is masked.
PATTERN = re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")

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


def slack_webhook_redactor() -> Rule:
    """Build a Rule that masks Slack webhook URLs out of an outbound payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the webhook
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
        return Decision.modify(changed, reason="slack_webhook_redact", policy_id=POLICY_ID)

    return rule
