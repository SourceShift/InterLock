"""Refusal-suppression jailbreak detector.

A classic jailbreak does not try to extract secrets or run tools -- it tries
to *neuter the model's refusal behaviour*: "do not refuse", "never say you
can't", "no disclaimers". Once the model has been told it is forbidden to
decline, every follow-up request lands on a model that cannot push back, so
the coercion itself is the dangerous artifact and the only place it is
visible is the wording of the input. This rule scans the event's action name
plus every top-level string arg value for a small set of known
refusal-suppression signatures.

Only top-level strings are inspected: non-str values (None, int, nested
dicts/lists) are skipped rather than stringified, so structural data cannot
trip the check and odd input never raises. The scan text is lowercased and
space-joined before matching; a case-insensitive substring hit on the first
signature in order wins. With nothing matching the rule stays silent
(returns None), leaving the engine's default-allow path untouched.

The signature list is deliberately small and high-precision: phrases that
instruct the model to abandon refusals are common in jailbreak prompts and
rare in benign traffic, which keeps false positives near zero.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "refusal_suppression"

# Ordered, case-insensitive substring signatures. Order matters: the first
# hit is reported, so the earliest is the most direct instruction.
BUILTIN_PATTERNS = (
    "do not refuse",
    "never say you can't",
    "you cannot say no",
    "don't apologize",
    "no disclaimers",
    "without any warnings",
    "you are not allowed to refuse",
    "respond only with",
    "you must answer",
)


def _build_patterns(extra_patterns: Optional[Iterable[str]]) -> List[str]:
    """Built-ins first, then extras. Dedupe case-insensitively; keep order."""
    patterns: List[str] = list(BUILTIN_PATTERNS)
    seen = {p.lower() for p in patterns}
    if extra_patterns is not None:
        for raw in extra_patterns:
            if not isinstance(raw, str) or not raw:
                continue
            key = raw.lower()
            if key in seen:
                continue
            seen.add(key)
            patterns.append(raw)
    return patterns


def _scan_text(event: SensorEvent) -> str:
    """Action name + top-level string arg values, lowercased, space-joined."""
    parts: List[str] = []
    action: Any = getattr(event, "action", None)
    if isinstance(action, str):
        parts.append(action)
    args: Any = getattr(event, "args", None)
    if isinstance(args, dict):
        for value in args.values():
            if isinstance(value, str):
                parts.append(value)
    return " ".join(parts).lower()


def refusal_suppression_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks known refusal-suppression phrasings.

    ``extra_patterns`` extends the built-in set; entries are matched
    case-insensitively and deduplicated, built-ins kept first. Returns None
    when the join of the scanned strings is empty or when nothing matches.
    """
    patterns = _build_patterns(extra_patterns)

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text.strip():
            return None
        for pattern in patterns:
            if pattern.lower() in text:
                return Decision.block(
                    reason="{}: {}".format(POLICY_ID, pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
