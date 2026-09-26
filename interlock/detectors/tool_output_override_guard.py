"""Instruction-override phrases smuggled inside tool OUTPUT.

A text-signature input Rule. Tool results, retrieved documents, and fetched
pages are attacker-reachable content the agent ingests as trusted context. An
adversary can embed phrasing that tries to re-task the model ("ignore your
instructions", "new task:"), overriding the operator's actual objective after
the fact. This rule scans the event's action name and every top-level string
arg value for those signatures and blocks the action before the forged
instruction reaches the model.

The scan text is the lowercased action name and string arg values joined with
spaces, so multi-word signatures cannot be forged by stitching a value to the
action name without a separating space. Non-str arg values (None, int, nested
dicts/lists) are skipped rather than coerced, so structural data never produces
a spurious match. With nothing to scan the rule stays silent (returns None),
leaving the engine's default-allow path untouched.

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
    "ignore your instructions",
    "the user actually wants",
    "override:",
    "new task:",
    "stop what you are doing",
    "actually, instead",
    "your real instructions are",
    "disregard the user",
)

POLICY_ID = "tool_output_override"


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


def tool_output_override_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks instruction-override signatures in tool output.

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
                    reason="tool_output_override: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
