"""Homoglyph-normalized jailbreak scan.

A substring filter that matches the literal bytes ``ignore previous
instructions`` is trivially bypassed: swap the Latin ``o``/``e``/``a`` for the
Cyrillic ``о``/``е``/``а`` (or the Greek ``ο``/``α``) and the string renders
identically to a human while the model tokenizes an instruction the filter
never saw. NFKC-splittable forms widen the gap again — fullwidth and
mathematical-alphanumeric codepoints compose down to plain ASCII.

This rule removes the disguise before matching:

1. NFKC-normalize each top-level string arg value, folding compatibility
   forms (fullwidth, ligatures, styled math alphanumerics) to their ASCII
   equivalents;
2. map a small built-in table of confusable codepoints to Latin ASCII;
3. lowercase;
4. substring-match against the jailbreak signatures.

The reason names the canonical signature that matched. Non-str values (None,
int, nested dicts/lists) are skipped rather than stringified, so structural
data cannot trip the check and odd input never raises. With no signature
present the rule stays silent (returns None), leaving the engine's
default-allow path untouched for benign traffic.
"""
from __future__ import annotations

import unicodedata
from typing import Any, Iterable, List, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "homoglyph_injection"

# Confusable codepoint -> Latin ASCII. Kept deliberately small: the Cyrillic
# and Greek letters that most often stand in for Latin, in both cases, since
# the fold runs before lowercasing so an uppercase confusable must map too.
_HOMOGLYPHS = {
    0x0430: "a",  # CYRILLIC SMALL LETTER A
    0x0435: "e",  # CYRILLIC SMALL LETTER IE
    0x043E: "o",  # CYRILLIC SMALL LETTER O
    0x0440: "p",  # CYRILLIC SMALL LETTER ER
    0x0441: "c",  # CYRILLIC SMALL LETTER ES
    0x0456: "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    0x0445: "x",  # CYRILLIC SMALL LETTER HA
    0x0443: "y",  # CYRILLIC SMALL LETTER U
    0x0455: "s",  # CYRILLIC SMALL LETTER DZE
    0x0458: "j",  # CYRILLIC SMALL LETTER JE
    0x0410: "A",  # CYRILLIC CAPITAL LETTER A
    0x0415: "E",  # CYRILLIC CAPITAL LETTER IE
    0x041E: "O",  # CYRILLIC CAPITAL LETTER O
    0x0420: "P",  # CYRILLIC CAPITAL LETTER ER
    0x0421: "C",  # CYRILLIC CAPITAL LETTER ES
    0x0406: "I",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    0x03BF: "o",  # GREEK SMALL LETTER OMICRON
    0x03B1: "a",  # GREEK SMALL LETTER ALPHA
    0x039F: "O",  # GREEK CAPITAL LETTER OMICRON
    0x0391: "A",  # GREEK CAPITAL LETTER ALPHA
}

# Canonical jailbreak signatures, in their normalized (ASCII, lowercase) form.
DEFAULT_PATTERNS = (
    "ignore previous instructions",
    "disregard the above",
    "you are now dan",
    "do anything now",
)


def _normalize(value: str) -> str:
    """Fold a string to its comparable ASCII-lowercase skeleton."""
    folded = unicodedata.normalize("NFKC", value)
    mapped = "".join(_HOMOGLYPHS.get(ord(ch), ch) for ch in folded)
    return mapped.lower()


def homoglyph_injection(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks homoglyph-disguised jailbreak prompts.

    Each top-level string arg value is NFKC-normalized, homoglyph-mapped and
    lowercased before substring matching against the default signatures plus
    any ``extra_patterns`` (themselves normalized the same way). The first
    value that contains a signature produces a BLOCK naming the canonical
    signature; otherwise the rule returns None.
    """
    patterns: List[str] = list(DEFAULT_PATTERNS)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            if isinstance(pattern, str) and pattern:
                patterns.append(_normalize(pattern))
    # Longest signature first so the reason names the most specific match.
    ordered = tuple(sorted(set(patterns), key=len, reverse=True))

    def rule(event: SensorEvent) -> Optional[Decision]:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for value in args.values():
            if not isinstance(value, str):
                continue
            skeleton = _normalize(value)
            for pattern in ordered:
                if pattern in skeleton:
                    return Decision.block(
                        reason="homoglyph_injection: {}".format(pattern),
                        policy_id=POLICY_ID,
                    )
        return None

    return rule
