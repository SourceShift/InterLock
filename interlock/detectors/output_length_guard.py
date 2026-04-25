"""Excessive-output guard: block model/tool output that exceeds a byte budget.

Per-value output rules (secret redaction, PII masking, injection markers) judge
*what* a response contains. None of them object to a large honest-looking
response, so an unbounded answer is allowed to leave the boundary unfiltered.
Volume is itself the signal: a single response carrying hundreds of kilobytes
is a data-dump or a token-drain, not an ordinary answer.

This rule targets the *output* side of the boundary. For output actions it sums
the utf-8 byte length of the string values under the content keys and blocks the
response when the total crosses ``max_bytes``. The threshold is caller-tunable
because "normal" response size is application-specific.

Only a str value under a content key is counted; an int, None, or a nested
container under such a key is skipped rather than stringified, and a non-dict
``args`` yields no opinion. Non-output actions return None. The rule never
raises on odd input.
"""
from __future__ import annotations

from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "output_length"

# The output action names this guard recognises. Kept to unambiguous response
# verbs so a same-named in-house tool is not shadowed.
OUTPUT_ACTIONS = frozenset({
    "respond", "output", "return", "tool_result",
})

# Argument keys that may carry response content. Only the str value under one
# of these is measured.
CONTENT_KEYS = ("text", "content", "body", "data")

DEFAULT_MAX_BYTES = 50_000


def _output_bytes(args: Any) -> int:
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


def output_length_guard(max_bytes: int = DEFAULT_MAX_BYTES) -> Rule:
    """Build a Rule that blocks output whose response payload exceeds *max_bytes*.

    For an action in :data:`OUTPUT_ACTIONS`, the payload size is the summed
    utf-8 byte length of the str values under :data:`CONTENT_KEYS`. When that
    total is strictly greater than *max_bytes* the rule returns a BLOCK naming
    the byte count; otherwise (including a non-output action) it returns None.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in OUTPUT_ACTIONS:
            return None

        total = _output_bytes(getattr(event, "args", None))
        if total <= max_bytes:
            return None
        return Decision.block(
            reason="output_length_guard: {} bytes over limit".format(total),
            policy_id=POLICY_ID,
        )

    return rule
