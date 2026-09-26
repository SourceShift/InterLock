"""AWS ARN redaction: strip resource ARNs out of egress payloads, don't block.

An Amazon Resource Name is a self-describing pointer to one specific resource in
one specific account: ``arn:aws:iam::123456789012:role/prod-admin`` names the
partition, the service, the region, the owning account id, and the exact
resource path in a single token. The account id and the resource layout are the
sensitive parts - they are the addressing scheme an attacker needs to reach the
resource directly - and they are fully readable without any credential.

The account id is the leak that cannot be rotated: unlike a token or a password,
an AWS account number is long-lived infrastructure identity, so its appearance in
an outbound body or a log line is a durable piece of reconnaissance. Like the JWT
and DB-URI redactors, this rule assumes the send is legitimate and the ARN is
accidental: it masks the ARN in place and lets the (now-clean) request proceed.
That is the MODIFY point of the allow/modify/block spectrum - the reconnaissance
value is neutralised without failing the transport, so an ARN that was copied
into an outbound payload by mistake does not take the agent's work down with it.

The pattern is anchored on the fixed ``arn:aws:`` prefix and requires a
twelve-digit account field, so prose, hostnames, and vendor-shaped strings that
merely mention "arn" are not touched. No validation follows - every regex match
is masked.

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

POLICY_ID = "aws_arn_redact"

# The mask a redacted ARN is replaced with.
MARKER = "[REDACTED ARN]"

# ``arn:aws:<service>:<region>:<account>:<resource>``. The service and region
# fields are ``[a-z0-9-]`` (region is allowed to be empty, as in the global
# services), the account field is required to be exactly twelve digits, and the
# resource tail runs to the next whitespace or quote. The twelve-digit floor is
# what keeps a short ``arn:aws:...`` fragment from matching; no validation for a
# real ARN follows - every regex match is masked.
PATTERN = re.compile(
    r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"']+"
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


def aws_arn_redactor() -> Rule:
    """Build a Rule that masks AWS ARNs out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the ARN stripped
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
            changed, reason="aws_arn_redact", policy_id=POLICY_ID,
            attributed_to=next(iter(changed)),
        )

    return rule
