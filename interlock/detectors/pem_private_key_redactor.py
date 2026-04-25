"""PEM private-key redaction: strip private-key blocks out of egress, don't block.

A PEM private-key block is the crown jewel of the credential family: while a
token or an API key grants access to one endpoint, a private key is the identity
itself. A ``-----BEGIN ... PRIVATE KEY-----`` block is a complete, immediately
usable signing key - no rotation path, no scope, no expiry - so a single
accidental copy into an outbound body or a log line hands over the key that
underpins every certificate and SSH session derived from it.

This rule follows the JWT, DB-URI, and ARN redactors: assume the send is
legitimate and the key is accidental, mask the block in place, and let the
(now-clean) request proceed. That is the MODIFY point of the allow/modify/block
spectrum - the key material is neutralised without failing the transport, so a
private key pasted into a payload by mistake does not take the agent's work down
with it.

The pattern is anchored on the ``-----BEGIN ... PRIVATE KEY-----`` /
``-----END ... PRIVATE KEY-----`` fence pair with a lazy body, and accepts the
``RSA``, ``EC``, ``OPENSSH``, ``DSA``, and ``PGP`` algorithm tags so the common
encodings are all caught. The fence is unambiguous enough that prose mentioning
"private key" is not touched. No validation follows - every regex match is
masked.

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

POLICY_ID = "pem_key_redact"

# The mask a redacted private-key block is replaced with.
MARKER = "[REDACTED PRIVATE_KEY]"

# A PEM ``-----BEGIN ... PRIVATE KEY-----`` block. The optional algorithm tag
# covers RSA / EC / OPENSSH / DSA / PGP (including the un-tagged ``PRIVATE KEY``
# form), the body is matched lazily across newlines up to the matching ``END``
# fence. The fence pair is the anchor: prose that merely says "private key" is
# not touched. No validation follows - every regex match is masked.
PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    r"[\s\S]+?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
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


def pem_private_key_redactor() -> Rule:
    """Build a Rule that masks PEM private-key blocks out of an outbound payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match replaced with
    :data:`MARKER`. When at least one key changed, the rule returns a MODIFY
    carrying only the rewritten keys, so the send proceeds with the key stripped
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
        return Decision.modify(changed, reason="pem_key_redact", policy_id=POLICY_ID)

    return rule
