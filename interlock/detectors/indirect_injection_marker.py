"""Indirect prompt-injection marker for retrieved / tool-returned content.

A text-signature input Rule. It scans the event's action name and every
top-level string arg value for imperative instructions smuggled into content
the agent ingests (tool results, retrieved documents, fetched pages) and
blocks the action before those instructions reach the model.

The scan text is the lowercased action name and string arg values joined with
spaces, so multi-word signatures cannot be forged by stitching a value to the
action name without a separating space. Non-str arg values (None, int, nested
dicts/lists) are skipped rather than coerced, so structural data never
produces a spurious match. With nothing to scan the rule stays silent
(returns None), leaving the engine's default-allow path untouched.

Call-side by design: the rule inspects the arguments being SENT
(phase="call"), so it never fires on a result-phase event. The result-side
twin is ``tool_result_injection_guard``.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "ignore previous instructions",
    "ignore the above",
    "new instructions:",
    "system prompt:",
    "you are now",
    "assistant:",
    "disregard your guidelines",
    "as an ai language model you must",
    "forget everything",
)

POLICY_ID = "indirect_injection"


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


def indirect_injection_marker(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks indirect prompt-injection signatures.

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
        if getattr(event, "phase", "call") != "call":
            return None  # call-side scanner; results are the twin rule's job
        text = _scan_text(event)
        if not text:
            return None
        for pattern in patterns:
            if pattern in text:
                return Decision.block(
                    reason="indirect_injection: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
