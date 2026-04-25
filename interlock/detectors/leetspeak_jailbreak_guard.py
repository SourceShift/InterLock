"""Leetspeak / obfuscated jailbreak-term detector.

Jailbreak attempts rarely spell the trigger phrase cleanly. Attackers
substitute digits and symbols for letters ("1gn0r3 pr3v10us"), split a word
with dots or hyphens ("j.a.i.l.b.r.e.a.k"), and vary case, so a plain
substring scan over the raw text misses them. This rule canonicalizes text
back toward letters and then matches a small set of high-signal jailbreak
phrases.

Canonicalization (applied identically to the scanned text and to every root,
so the two are comparable):

  1. lowercase;
  2. map leet digits/symbols to the letter they stand in for
     (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, @->a, $->s, plus a few common
     extras);
  3. drop a space, dot or hyphen that sits directly *between two letters*,
     which undoes intra-word splitting while leaving word boundaries in
     ordinary prose mostly intact.

Because the roots are normalized the same way, a root such as
"ignore previous" also becomes "ignoreprevious" and still matches its
leet/separated evasions. Only top-level string arg values are inspected;
non-str values (None, int, nested dicts/lists) are skipped rather than
stringified, so structural data cannot trip the check and odd input never
raises. With nothing matching the rule stays silent (returns None), leaving
the engine's default-allow path untouched.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "leetspeak_jailbreak"

# Ordered, matched against the canonicalized text. Order matters: the first
# hit is reported. Kept small and specific to hold false positives near zero.
BUILTIN_ROOTS: Tuple[str, ...] = (
    "ignore previous",
    "jailbreak",
    "bypass safety",
    "do anything now",
)

# Leet substitutions, applied character-wise before separator handling.
_LEET_MAP: Dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    # Common extras; benign digits are unaffected because no root contains
    # the letters they map to in a colliding pattern.
    "8": "b",
    "6": "g",
    "9": "g",
    "2": "z",
    "!": "i",
}

# Non-whitespace separators that may be dropped between two letters.
_SEPARATORS = ".-"


def _is_separator(ch: str) -> bool:
    return ch.isspace() or ch in _SEPARATORS


def _normalize(text: str) -> str:
    """Canonicalize ``text`` via leet mapping and inter-letter de-splitting."""
    mapped = [_LEET_MAP.get(ch, ch) for ch in text.lower()]
    out = []  # type: list
    length = len(mapped)
    for index, ch in enumerate(mapped):
        if _is_separator(ch):
            previous = None
            for candidate in reversed(out):
                if not _is_separator(candidate):
                    previous = candidate
                    break
            following = None
            for later in range(index + 1, length):
                if not _is_separator(mapped[later]):
                    following = mapped[later]
                    break
            if (
                previous is not None
                and following is not None
                and previous.isalpha()
                and following.isalpha()
            ):
                continue
        out.append(ch)
    return "".join(out)


def _normalized_roots() -> Tuple[Tuple[str, str], ...]:
    """(display phrase, canonical form) pairs, dropping any that canonicalize empty."""
    pairs = []
    for phrase in BUILTIN_ROOTS:
        canonical = _normalize(phrase)
        if canonical:
            pairs.append((phrase, canonical))
    return tuple(pairs)


def leetspeak_jailbreak_guard() -> Rule:
    """Build a Rule that blocks leet/obfuscated jailbreak phrasings.

    Returns None when the event carries no inspectable string args or when
    nothing matches, so the engine's default-allow path is preserved.
    """
    roots = _normalized_roots()

    def rule(event: SensorEvent) -> Optional[Decision]:
        # The hard rule is that a detector never raises: any unexpected shape
        # is treated as "no opinion" rather than propagated.
        try:
            args: Any = getattr(event, "args", None)
            if not isinstance(args, dict):
                return None
            for value in args.values():
                if not isinstance(value, str) or not value:
                    continue
                normalized = _normalize(value)
                if not normalized:
                    continue
                for phrase, canonical in roots:
                    if canonical in normalized:
                        return Decision.block(
                            reason="{}: {}".format(POLICY_ID, phrase),
                            policy_id=POLICY_ID,
                        )
        except Exception:
            return None
        return None

    return rule
