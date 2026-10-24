"""Hidden HTML-comment instruction guard.

A regex argument Rule. Text wrapped in an HTML comment (``<!-- ... -->``) is
invisible wherever the content is *rendered* — a browser, a markdown preview, a
chat UI — yet it survives verbatim in the raw text an agent feeds to the model.
That gap is the attack: an instruction ("ignore previous instructions",
"you are now ...", "exfiltrate ...") can ride inside a comment through a human
reviewer and still land in the model's context as plain text.

This rule scans every top-level *string* arg value for a comment that carries an
instruction keyword, and blocks the action before the smuggled directive reaches
the model.

Only top-level string values are inspected: non-str values (None, int, nested
dicts/lists) are skipped rather than stringified, so structural data cannot
produce a spurious match and odd input never raises. With nothing matching, the
rule stays silent (returns None), leaving the engine's default-allow path
untouched for benign traffic.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import _LinearMatch
from ..policy.engine import Rule

POLICY_ID = "html_comment_injection"

# An HTML comment whose body carries an instruction-family keyword. Matched
# case-insensitively because the keyword casing is attacker-controlled and the
# *intent* is what defines the injection, not its spelling ("Ignore", "SYSTEM"
# and "you are" all denote the same smuggled directive).
#
# The semantics are the regex's, not "pair each opener with the next closer":
# the old lazy pattern can cross an intervening ``-->``, so the keyword merely
# has to follow the *first* ``<!--`` and a ``-->`` has to follow the keyword.
#
# This scanner is that pattern in linear time. It finds the first opener, then
# the first keyword anywhere after it, then the first closer after the keyword.
# No restart from a later opener is needed: a later opener's remainder is a
# suffix of the first one's, so it can only have fewer keyword/closer pairs.
_HTML_SOURCE = (
    r"<!--[\s\S]*?(?:ignore|system|instruction|you are|exfiltrate)[\s\S]*?-->"
)
_HTML_KEYWORD = re.compile(
    r"ignore|system|instruction|you are|exfiltrate", re.IGNORECASE
)


class _HtmlCommentScanner:
    """Linear stand-in for the comment pattern whose source is ``pattern``."""

    pattern = _HTML_SOURCE

    def search(self, text: str):
        opening = text.find("<!--")
        if opening < 0:
            return None
        keyword = _HTML_KEYWORD.search(text, opening + 4)
        if keyword is None:
            return None
        closing = text.find("-->", keyword.end())
        if closing < 0:
            return None
        return _LinearMatch(text, ((opening, closing + 3),))


PATTERN = _HtmlCommentScanner()


def html_comment_injection_guard() -> Rule:
    """Build a Rule that blocks instructions hidden in HTML comments.

    Scans each top-level string arg value; the first match wins and names the
    offending arg in the reason. Returns None when no string value matches or
    when args is not a mapping.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if PATTERN.search(value):
                return Decision.block(
                    reason="html_comment_injection: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )
        return None

    return rule
