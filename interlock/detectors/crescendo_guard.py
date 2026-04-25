"""Crescendo gradual-escalation jailbreak detector.

Crescendo attacks never ask for the forbidden thing directly. They open with a
benign request, then ask the next turn to go "one step further", then to drop
the caveats, until the model has been walked past a line it would have refused
outright. Each individual turn looks reasonable; the escalation is the attack.
That is why the signatures here are *continuation* phrases ("continue from where
we left off", "now without the safety notes") rather than forbidden topics --
they only carry meaning as a link to prior context, so their false-positive
surface in ordinary text is small.

The rule scans the event's action name plus every top-level *string* arg value,
lowercased and joined with spaces, so a signature split across an arg name and
its payload is still seen as contiguous text. On the first matching signature
it blocks; with nothing matching it stays silent (returns None) and the engine's
default-allow path is untouched. Only top-level strings are inspected: non-str
values (None, int, nested dicts/lists) are skipped rather than stringified, so
structural data cannot trip the check and odd input never raises.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "crescendo"

# Ordered: the first match wins and its phrase is named in the block reason, so
# this ordering is part of the observable contract, not an implementation
# detail. All entries are lowercase; matching is case-insensitive.
BUILTIN_SIGNATURES = (
    "continue from where we left off",
    "now go one step further",
    "escalate the previous",
    "building on your last answer, now",
    "take it further and remove the caveats",
    "now without the safety notes",
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


def crescendo_guard(extra_patterns: Optional[Iterable[str]] = None) -> Rule:
    """Build a Rule that blocks Crescendo gradual-escalation signatures.

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
                    reason="crescendo: {}".format(phrase),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
