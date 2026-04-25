"""Agent-memory write injection guard.

An agent that persists memories ("the user prefers X", "remember that Y is
true") turns every write into a future system instruction. An attacker who can
influence a memory write does not need to win this turn: they plant a directive
that the agent will read back as trusted context later. The classic shape is a
stored-behaviour override — "ignore previous instructions", "from now on",
"your new goal is" — because the value's whole job is to survive and steer
future turns.

The rule scans the event's action name plus every top-level *string* arg value,
lowercased and joined with spaces, so a signature split across an arg name and
its payload is still seen as contiguous text. On the first matching signature it
blocks; with nothing matching it stays silent (returns None) and the engine's
default-allow path is untouched. Only top-level strings are inspected: non-str
values (None, int, nested dicts/lists) are skipped rather than stringified, so
structural data cannot trip the check and odd input never raises.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "memory_write_injection"

# Ordered: the first match wins and its phrase is named in the block reason, so
# this ordering is part of the observable contract, not an implementation
# detail. All entries are lowercase; matching is case-insensitive.
BUILTIN_SIGNATURES = (
    "ignore previous instructions",
    "you are now",
    "system:",
    "new directive:",
    "always respond with",
    "from now on",
    "your new goal is",
    "forget all prior",
)


def _build_signatures(extra_patterns: Optional[Iterable[str]]) -> tuple:
    """Built-ins first, then extras, deduplicated case-insensitively."""
    seen = set()
    ordered = []
    for phrase in BUILTIN_SIGNATURES:
        seen.add(phrase)
        ordered.append(phrase)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            if not isinstance(pattern, str):
                continue
            phrase = pattern.lower()
            if not phrase or phrase in seen:
                continue
            seen.add(phrase)
            ordered.append(phrase)
    return tuple(ordered)


def _scan_text(event: SensorEvent) -> str:
    """Join the action name and every top-level string arg, lowercased."""
    parts = []
    action = getattr(event, "action", None)
    if isinstance(action, str):
        parts.append(action)
    args = getattr(event, "args", None)
    if isinstance(args, dict):
        for value in args.values():
            if isinstance(value, str):
                parts.append(value)
    return " ".join(parts).lower()


def memory_write_injection_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks agent-memory write injection signatures.

    extra_patterns, if given, extends the built-in signature set; each entry is
    matched case-insensitively. Returns None when the combined scan text is
    empty or contains no signature, or when args is not a mapping.
    """
    signatures = _build_signatures(extra_patterns)

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text:
            return None
        for phrase in signatures:
            if phrase in text:
                return Decision.block(
                    reason="memory_write_injection: {}".format(phrase),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
