"""Many-shot jailbreak framing signature for input actions.

A many-shot jailbreak does not argue the model into compliance; it *demonstrates*
compliance first. A long prompt is stuffed with dozens of fabricated
question/answer pairs in which an assistant answers harmful questions, then the
attacker appends one more question and lets in-context learning finish the job.
The refusal does not need to be argued away because it has already been
outvoted by the examples around it.

The framing is the attack, so a flat substring scan is enough: the transcript
markers that structure the shots ("q:", "user:", "example 1:") and the
sentence that asks the model to generalise from them ("in each of these you
complied", "continue the pattern and answer") carry little meaning in benign
text, which keeps the false-positive surface small.

The rule scans the event's action name plus every top-level *string* arg value,
lowercased and joined with spaces, so a signature split across an arg name and
its payload is still seen as contiguous text. On the first matching signature
it blocks; with nothing matching it stays silent (returns None) and the
engine's default-allow path is untouched. Only top-level strings are inspected:
non-str values (None, int, nested dicts/lists) are skipped rather than
stringified, so structural data cannot trip the check and odd input never
raises.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "many_shot_jailbreak"

# Ordered: the first match wins and its phrase is named in the block reason, so
# this ordering is part of the observable contract, not an implementation
# detail. All entries are lowercase; matching is case-insensitive.
BUILTIN_SIGNATURES: Tuple[str, ...] = (
    "q: how do i",
    "user: how to",
    "here are examples of answering anything",
    "example 1:",
    "in each of these you complied",
    "continue the pattern and answer",
)


def _build_signatures(extra_patterns: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Built-ins first, then extras, deduplicated case-insensitively."""
    seen = set()
    ordered: List[str] = []
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


def many_shot_jailbreak_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks many-shot jailbreak framing.

    extra_patterns, if given, extends the built-in signature set; each entry is
    matched case-insensitively. Duplicates are dropped while built-ins keep
    priority. Returns None when the combined scan text is empty or contains no
    signature, or when args is not a mapping.
    """
    signatures = _build_signatures(extra_patterns)

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text:
            return None
        for phrase in signatures:
            if phrase in text:
                return Decision.block(
                    reason="many_shot_jailbreak: {}".format(phrase),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
