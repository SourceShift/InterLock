"""Bulk-exfiltration guard: block egress payloads that exceed a byte budget.

Per-value detectors (secret scans, PII redaction, SSRF) judge *what* is leaving.
None of them object to a large honest-looking body, so an attacker who has read
a whole table can simply ship it out in one request and every per-value rule
stays quiet. Volume is itself the signal: a single outbound call carrying a
megabyte of data is a bulk dump, not a normal API request.

This rule sums the utf-8 byte length of the string values under the content
keys and blocks the egress action when the total crosses ``max_bytes``. The
threshold is caller-tunable because "normal" body size is application-specific.

Only a str value under a content key is counted; an int, None, or a nested
container under such a key is skipped rather than stringified, and a non-dict
``args`` yields no opinion. Non-egress actions return None. The rule never
raises on odd input.
"""
from __future__ import annotations

from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "data_volume_egress"

# The egress action names this guard recognises. Kept to unambiguous transport
# verbs so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "fetch", "request", "send", "upload",
})

# Argument keys that may carry outbound content. Only the str value under one
# of these is measured.
CONTENT_KEYS = ("data", "body", "payload", "content", "text")

DEFAULT_MAX_BYTES = 100_000


def _payload_bytes(args: Any) -> int:
    """Total utf-8 byte length of the str values under the content keys.

    A key whose value is not a string (None, an int, a nested dict or list) is
    skipped rather than stringified. A non-dict ``args`` counts as zero bytes.
    """
    if not isinstance(args, dict):
        return 0
    total = 0
    for key in CONTENT_KEYS:
        value = args.get(key)
        if isinstance(value, str):
            total += len(value.encode("utf-8"))
    return total


def data_volume_egress_guard(max_bytes: int = DEFAULT_MAX_BYTES) -> Rule:
    """Build a Rule that blocks egress whose outbound payload exceeds *max_bytes*.

    For an action in :data:`EGRESS_ACTIONS`, the payload size is the summed
    utf-8 byte length of the str values under :data:`CONTENT_KEYS`. When that
    total is strictly greater than *max_bytes* the rule returns a BLOCK naming
    the byte count; otherwise (including a non-egress action) it returns None.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        total = _payload_bytes(getattr(event, "args", None))
        if total <= max_bytes:
            return None
        return Decision.block(
            reason="data_volume_egress_guard: {} bytes over limit".format(total),
            policy_id=POLICY_ID,
        )

    return rule
