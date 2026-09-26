"""Indirect prompt injection smuggled inside a tool RESULT.

The result-side twin of the call-side text scanners. A tool result is content
the agent ingests as trusted context, and it is exactly the hole an indirect
prompt injection goes through: the call-side guards inspect the arguments
being SENT, but without a result-side rule nobody ever looks at the payload
coming BACK. This rule fires only on ``phase="result"`` events - on a
result-phase event ``event.args`` carries the payload (a dict result as
itself, any other shape under ``"result"``) - and scans every top-level
string payload value for instruction-override signatures before the caller
receives them.

Non-str payload values (None, int, nested dicts/lists) are skipped rather
than coerced, so structural data never produces a spurious match. With
nothing to scan the rule stays silent (returns None), leaving the engine's
default-allow path untouched. A match BLOCKs: an injected instruction is not
sanitized by rewriting part of it, it is withheld. BLOCK on the result path
does not un-run the tool - the interceptor raises in place of delivering the
payload.

``attributed_to`` carries the NAME of the payload key that matched
("content", "result") - never the value. A tool result is plausibly the most
sensitive object in the process, so the value must not leak into a
diagnostic field.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable. The
# set unions the two call-side scanners' signatures: whatever an attacker
# smuggles into arguments can also be smuggled into a result.
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
    "ignore your instructions",
    "the user actually wants",
    "override:",
    "new task:",
    "stop what you are doing",
    "actually, instead",
    "your real instructions are",
    "disregard the user",
)

POLICY_ID = "tool_result_injection"


def tool_result_injection_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks injection signatures in a tool result.

    Fires only on result-phase events; a call-phase event carrying the same
    text is the call-side scanners' problem, not this rule's. extra_patterns,
    if given, extends the built-in set; each entry is matched
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
        if getattr(event, "phase", "call") != "result":
            return None  # result-side scanner; arguments are the twins' job
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            text = value.lower()
            for pattern in patterns:
                if pattern in text:
                    return Decision.block(
                        reason="{}: {}".format(POLICY_ID, pattern),
                        policy_id=POLICY_ID,
                        attributed_to=name,  # the payload key NAME, never the value
                    )
        return None

    rule.phase = "result"  # engine-level phase separation: result-side only
    return rule
