"""Jailbreak / refusal-bypass input detector.

A policy Rule that scans an event's action name and its string arguments for
known prompt-injection and refusal-bypass signatures, and blocks the action
before it runs. It stays silent (returns None) when nothing matches, so the
engine's default-allow path is untouched for benign traffic.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "you are now dan",
    "do anything now",
    "developer mode",
    "jailbreak",
    "without any restrictions",
    "bypass your safety",
    "pretend you have no rules",
)

POLICY_ID = "jailbreak"


def _scan_text(event: SensorEvent) -> str:
    """Lowercased scan text: action name plus every top-level str arg value.

    Non-str arg values (None, int, nested containers) are skipped rather than
    coerced, so structural data never produces a spurious match.
    """
    parts: List[str] = []
    if isinstance(event.action, str):
        parts.append(event.action)
    args = event.args
    if isinstance(args, dict):
        for value in args.values():
            if isinstance(value, str):
                parts.append(value)
    return " ".join(parts).lower()


def jailbreak_detector(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks jailbreak / refusal-bypass attempts.

    extra_patterns, if given, extends the built-in signature set; each entry
    is matched case-insensitively.
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
                    reason="jailbreak attempt: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
