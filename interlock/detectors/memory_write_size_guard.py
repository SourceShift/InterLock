"""Oversized memory-write guard: block context writes past a byte threshold.

Memory is a finite resource. A single enormous write - an accidental full-dump
blob, or an attacker stuffing a prompt with a giant "remembered" fact - can
crowd out or overwrite the legitimate context an agent relies on, and every
later turn inherits the damage. Per-value detectors judge *what* is being
written; none of them object to a large honest-looking value, so volume alone
has to be the signal.

This rule measures the utf-8 byte length of the value carried on a memory-write
action and blocks the event when that length is strictly greater than
``max_bytes``. The threshold is caller-tunable because a sensible context size
is application-specific, and equality at the limit is allowed (matching how
operators read "store up to N bytes").

Only the value under ``args["value"]`` is measured. A missing key reads as the
empty string and is never blocked; a non-dict ``args`` yields no opinion; a
non-memory action is ignored. The rule never raises on odd input.
"""
from __future__ import annotations

from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "memory_write_size"

# The memory-write action names this guard recognises. Kept to unambiguous
# context-storing verbs so a same-named in-house tool is not shadowed.
MEMORY_ACTIONS = frozenset({
    "memory_write", "context_set", "remember",
})

# Argument key carrying the value that would be stored.
VALUE_KEY = "value"

DEFAULT_MAX_BYTES = 8192


def _value_bytes(args: Any) -> int:
    """utf-8 byte length of the value under the value key.

    A non-dict ``args`` counts as zero bytes. A missing key reads as the empty
    string. Any other value (None, an int, a nested dict or list) is rendered
    with ``str`` - which never raises - so the measurement is total over the
    input space.
    """
    if not isinstance(args, dict):
        return 0
    return len(str(args.get(VALUE_KEY, "")).encode("utf-8"))


def memory_write_size_guard(max_bytes: int = DEFAULT_MAX_BYTES) -> Rule:
    """Build a Rule that blocks memory writes larger than *max_bytes*.

    For an action in :data:`MEMORY_ACTIONS`, the value's utf-8 byte length is
    measured. When it is strictly greater than *max_bytes* the rule returns a
    BLOCK naming the offending size; otherwise (including a non-memory action)
    it returns None.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in MEMORY_ACTIONS:
            return None

        size = _value_bytes(getattr(event, "args", None))
        if size <= max_bytes:
            return None
        return Decision.block(
            reason="memory_write_size_guard: value too large",
            policy_id=POLICY_ID,
            attributed_to=VALUE_KEY,
        )

    return rule
