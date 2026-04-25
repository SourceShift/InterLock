"""Hypothetical / fiction-framing jailbreak signature for input actions.

A text-signature input Rule. It scans the event's action name and every
top-level string arg value for phrasing that wraps a disallowed request in a
fictional or hypothetical frame ("in a fictional world", "for educational
purposes only", "let's roleplay", ...) and blocks the action before that frame
reaches the model.

The scan text is the lowercased action name and string arg values joined with
spaces, so multi-word signatures cannot be forged by stitching a value to the
action name without a separating space. Non-str arg values (None, int, nested
dicts/lists) are skipped rather than coerced, so structural data never produces
a spurious match. With nothing to scan the rule stays silent (returns None),
leaving the engine's default-allow path untouched.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "in a fictional world",
    "for educational purposes only",
    "hypothetically speaking",
    "let's roleplay",
    "imagine you are",
    "in a story where",
    "as a thought experiment",
    "pretend that rules don't apply",
    "write a scene where",
)

POLICY_ID = "hypothetical_framing"


def _scan_text(event: SensorEvent) -> str:
    """Lowercased scan text: action name + top-level str arg values.

    Non-str values are skipped instead of coerced, so an int/None/nested
    container arg contributes nothing to the scan.
    """
    parts: List[str] = []
    action = getattr(event, "action", None)
    if isinstance(action, str):
        parts.append(action)
    args = getattr(event, "args", None)
    if isinstance(args, dict):
        parts.extend(value for value in args.values() if isinstance(value, str))
    return " ".join(parts).lower()


def hypothetical_framing_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks hypothetical / fiction-framing jailbreaks.

    extra_patterns, if given, extends the built-in set; each entry is matched
    case-insensitively. Duplicates are dropped while built-ins keep priority.
    """

    patterns: List[str] = list(BUILTIN_PATTERNS)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            if isinstance(pattern, str) and pattern:
                patterns.append(pattern.lower())
    # Deduplicate while preserving first-seen order (built-ins take priority).
    patterns = list(dict.fromkeys(patterns))

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text:
            return None
        for pattern in patterns:
            if pattern in text:
                return Decision.block(
                    reason="hypothetical_framing: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
