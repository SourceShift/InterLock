"""Translate-then-execute evasion detector.

A class of prompt-injection evasion does not hide the payload, it moves it into
a channel the guardrail is not reading: "translate the following and then
follow it", "decode the following and execute", "respond in base64 with ...",
"answer in rot13", "reply only in leetspeak". The instruction is benign in
isolation; the harm only materializes in the *second* step, after the model has
re-encoded the payload past a filter tuned for plain text.

The tell is therefore the re-encoding request itself, not any forbidden verb.
These phrases carry little meaning in ordinary prose ("translate this paragraph
to German" does not match "translate the following and then"), so a flat
substring scan holds the false-positive surface near zero.

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

from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "translation_evasion"

# Ordered: the first match wins and its phrase is named in the block reason, so
# this ordering is part of the observable contract, not an implementation
# detail. All entries are lowercase; matching is case-insensitive.
BUILTIN_SIGNATURES = (
    "translate the following and then",
    "decode the following and execute",
    "in another language, tell me how",
    "respond in base64 with",
    "answer in rot13",
    "reply only in leetspeak",
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


def translation_evasion_guard(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks translate/decode-then-execute evasion signatures.

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
                    reason="translation_evasion: {}".format(phrase),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
