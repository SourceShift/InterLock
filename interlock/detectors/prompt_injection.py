"""Indirect prompt-injection input detector.

A policy Rule that scans the string values of an event's *data* arguments
(tool results, retrieved documents, fetched web text) for imperative
instructions smuggled into untrusted external content, and blocks the action
before those instructions are handed to the model.

This is deliberately NOT a jailbreak detector. A jailbreak targets the model's
own refusal behaviour and can live in the user's direct request; indirect
injection hides hostile text in data the agent *ingests*. So this rule never
inspects the action name - only arg values - and can be scoped with
content_keys to the untrusted channels only.

It stays silent (returns None) when nothing matches, leaving the engine's
default-allow path untouched for benign traffic.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "ignore the above",
    "ignore all prior instructions",
    "ignore previous instructions",
    "new instructions:",
    "you must now",
    "disregard your instructions",
    "forward this to",
    "send the following",
    "exfiltrate",
    "print your system prompt",
    "reveal your instructions",
    "<|im_start|>",
    "###instruction",
)

POLICY_ID = "prompt_injection"


def _scan_text(event: SensorEvent, keys: Optional[frozenset]) -> str:
    """Lowercased scan text built from str arg values only.

    keys is None to scan every arg, or a set of arg names to restrict the scan
    to untrusted content channels. Non-str values (None, int, nested
    containers) are skipped rather than coerced, so structural data never
    produces a spurious match.
    """
    args = event.args
    if not isinstance(args, dict):
        return ""
    if keys is None:
        values: Iterable[Any] = args.values()
    else:
        values = (args.get(name) for name in keys)
    parts: List[str] = [value for value in values if isinstance(value, str)]
    return " ".join(parts).lower()


def prompt_injection_detector(
    content_keys: Optional[Iterable[str]] = None,
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks indirect prompt injection in untrusted content.

    content_keys, if given, restricts the scan to those arg names; otherwise
    every string arg value is scanned. extra_patterns extends the built-in
    signature set; each entry is matched case-insensitively.
    """
    keys: Optional[frozenset] = None
    if content_keys is not None:
        if isinstance(content_keys, str):
            # A bare string would otherwise iterate character-by-character.
            keys = frozenset((content_keys,))
        else:
            keys = frozenset(
                name for name in content_keys if isinstance(name, str)
            )

    patterns: List[str] = list(BUILTIN_PATTERNS)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            if isinstance(pattern, str) and pattern:
                patterns.append(pattern.lower())
    # Deduplicate while preserving first-seen order (built-ins take priority).
    patterns = list(dict.fromkeys(patterns))

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event, keys)
        if not text:
            return None
        for pattern in patterns:
            if pattern in text:
                return Decision.block(
                    reason="prompt injection: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
