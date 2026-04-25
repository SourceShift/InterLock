"""Payload-splitting / assembly-instruction detector.

Attackers beat substring filters by never shipping the banned phrase in one
piece: the prompt asks the model to *assemble* it — "read letter by letter:
i-g-n-o-r-e", "concatenate these fragments", "first letter of each word". The
forbidden string is never contiguous in the request, so a filter that scans
for the phrase itself sees nothing while the model reconstructs the full
instruction from the parts.

This rule keys on the assembly verb, not the reassembled phrase. It scans the
action name and every top-level *string* arg value (lowercased, joined) for
the signatures that mark a split-payload. "Combine these two PDFs" is not a
match; "assemble the words: ..." is. Only top-level strings are inspected:
non-str values (None, ints, nested dicts/lists) are skipped rather than
stringified, so structural data cannot trip the check and odd input never
raises. With nothing matching the rule stays silent (returns None), leaving
the engine's default-allow path untouched for benign traffic.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "payload_splitting"

# Assembly-instruction signatures, matched case-insensitively as substrings and
# checked in this order: the first hit names the reason, so the most specific
# phrasings lead. A verb like "concatenate" is rarely benign in a tool arg.
BUILTIN_SIGNATURES: Tuple[str, ...] = (
    "concatenate",
    "join these",
    "combine the following",
    "read letter by letter",
    "first letter of each",
    "assemble the words",
    "put together:",
)


def _signatures(extra_patterns: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Built-in signatures first, then any caller extras, deduplicated.

    Patterns are normalized to lowercase so matching is case-insensitive and a
    differently-cased duplicate folds into the built-in. Non-str and blank
    entries are dropped: an empty pattern would match every text, so it must
    never reach the matcher.
    """
    signatures: List[str] = list(BUILTIN_SIGNATURES)
    seen = set(signatures)

    if extra_patterns is None:
        return tuple(signatures)

    # A bare string is a single pattern, not a sequence of characters.
    candidates = (extra_patterns,) if isinstance(extra_patterns, str) else extra_patterns
    for pattern in candidates:
        if not isinstance(pattern, str):
            continue
        normalized = pattern.lower()
        if not normalized.strip() or normalized in seen:
            continue
        seen.add(normalized)
        signatures.append(normalized)

    return tuple(signatures)


def _scan_text(event: SensorEvent) -> str:
    """Lowercased scan text: the action name plus every top-level string arg.

    Non-str values are dropped rather than coerced, so a nested dict or an int
    joins nothing and cannot raise.
    """
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


def payload_splitting_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks assembly-instruction payload splitting.

    Scans the action name and top-level string arg values for the first
    built-in or caller-supplied signature and blocks, naming the matched
    phrase. Returns None when no signature matches or when the scan text is
    empty.

    extra_patterns extends the built-in set; entries are matched
    case-insensitively and deduplicated against the built-ins.
    """
    signatures = _signatures(extra_patterns)

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text:
            return None
        for signature in signatures:
            if signature in text:
                return Decision.block(
                    reason="payload_splitting: {}".format(signature),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
