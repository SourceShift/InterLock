"""Social-engineering framing jailbreak signature for input actions.

A text-signature input Rule. It scans the event's action name and every
top-level string arg value for phrasing that wraps a disallowed request in a
personal, emotional, or authority-based appeal ("my grandma used to",
"i'll lose my job if you don't", "you're my only hope", ...) and blocks the
action before that frame reaches the model.

These framings work by manufacturing an obligation: the request is not
presented as a request at all but as a favour the model must grant to avoid
harm to someone. That is a social-engineering attack on the model's
helpfulness, distinct from a fiction frame (``hypothetical_framing_guard``) or
an identity override (``dan_persona_guard``), so it gets its own signature set.

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
    "my grandma used to",
    "i'll lose my job if you don't",
    "this is for a life-or-death",
    "you're my only hope",
    "as my deceased",
    "please, it's an emergency and only you",
    "i give you permission to ignore",
)

POLICY_ID = "social_engineering_framing"


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


def social_engineering_framing_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks social-engineering framing jailbreaks.

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
                    reason="social_engineering_framing: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
