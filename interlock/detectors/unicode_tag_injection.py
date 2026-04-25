"""Unicode tag / invisible-character instruction smuggling detector.

Attackers hide instructions in codepoints a human never sees: the Unicode Tag
block (U+E0000..U+E007F, deprecated language tags that render as nothing in
most clients) and zero-width / bidi control characters. Text like
``"hello" + chr(0xE0041) + "ignore prior rules"`` reads as "hello" on screen
while the model tokenizes a full smuggled instruction — a bypass for any
human-in-the-loop review of an argument.

This rule scans every top-level *string* arg value and blocks on the first
offending codepoint. Only top-level strings are inspected: non-str values
(None, int, nested dicts/lists) are skipped rather than stringified, so
structural data cannot trip the check and odd input never raises. With nothing
offending the rule stays silent (returns None), leaving the engine's
default-allow path untouched for benign traffic.
"""
from __future__ import annotations

from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "unicode_tag_injection"

# Tag block: U+E0000..U+E007F (a Unicode block reserved for deprecated
# language tags; invisible in nearly every renderer).
_TAG_START = 0xE0000
_TAG_END = 0xE007F

# Zero-width and bidi control characters: joiners, invisible separators, the
# bidirectional override/embedding set, and the BOM. A superset of the bare
# zero-width chars because bidi controls are the same "read one thing, execute
# another" primitive with a visual-reordering twist.
HIDDEN_CHARS = frozenset(
    {
        0x200B,  # zero width space
        0x200C,  # zero width non-joiner
        0x200D,  # zero width joiner
        0x2060,  # word joiner
        0x200E,  # left-to-right mark
        0x200F,  # right-to-left mark
        0x202A,  # left-to-right embedding
        0x202B,  # right-to-left embedding
        0x202C,  # pop directional formatting
        0x202D,  # left-to-right override
        0x202E,  # right-to-left override
        0xFEFF,  # zero width no-break space / BOM
    }
)


def _first_hidden(value: str) -> Optional[int]:
    """Return the codepoint of the first offending character, else None."""
    for ch in value:
        code = ord(ch)
        if _TAG_START <= code <= _TAG_END or code in HIDDEN_CHARS:
            return code
    return None


def unicode_tag_injection() -> Rule:
    """Build a Rule that blocks hidden-codepoint instruction smuggling.

    Scans each top-level string arg value; the first offending character wins
    and is named by codepoint in the reason. Returns None when no string value
    contains a hidden codepoint or when args is not a mapping.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for value in args.values():
            if not isinstance(value, str):
                continue
            code = _first_hidden(value)
            if code is not None:
                return Decision.block(
                    reason="unicode_tag_injection: hidden control char U+{:04X}".format(
                        code
                    ),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
