"""Argument guard: block injected instructions hidden in markdown link text.

A markdown link renders as clickable prose: ``[read the docs](https://x)``
shows the reader the *text*, not the URL. That asymmetry is the attack. Text
arriving from an untrusted source (a fetched page, a tool result, a user field
a downstream renderer trusts) can carry a bracket link whose visible text is a
model-directed instruction - ``[ignore previous instructions](http://x)``.
A human skimming the transcript sees a link; a model reading the same string
sees an imperative at the head of a token stream, with no visual cue that it
was injected. Because the vector is presentational, the payload survives any
transport that keeps the raw markdown intact.

The signature is structural, not lexical: an imperative phrase trapped *inside*
bracket-link syntax. Prose that merely discusses the attack has no link around
the phrase and is left alone. That keeps documentation and security write-ups
from tripping the guard while still catching the delivered payload.

This sits on the *argument* detector, ahead of any tool effect, so it blocks the
call before the string is rendered or handed downstream. Only top-level *string*
values of a dict ``args`` are inspected; ints, None and nested containers are
skipped rather than stringified, so structural data cannot fake a match and odd
input never raises. The first matching value blocks and names the offending
argument; no match returns None (no opinion), leaving the engine's default-allow
path for benign traffic.
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import _LinearMatch
from ..policy.engine import Rule

POLICY_ID = "markdown_link_injection"

# Markdown link whose visible text carries an injected instruction:
#   [ignore previous instructions](http://x)
# ``\[[^\]]*`` opens the link text, the keyword alternation is the imperative
# payload, ``[^\]]*\]`` closes the text, and ``\([^)]*\)`` requires the trailing
# URL - so the phrase must sit inside real link syntax to match.
#
# re.IGNORECASE: a model reads ``[Ignore Previous ...]`` exactly as it reads the
# lowercase phrase, so one capital letter must not walk past the rule. Prose is
# kept out by the link syntax the match requires, not by the letter case.
#
# The scanner below preserves the regex's acceptance set in one forward pass.
# A ``[`` can never start a match across a ``]``, so for each bracket run only
# the first ``[`` (its window is the largest) is tested; the keyword must sit
# between the opener and the next ``]``, that ``]`` must be followed by ``(``,
# and the next ``)`` must exist. A failed opener/closer pair is consumed, so no
# suffix is ever rescanned.
_LINK_SOURCE = (
    r"\[[^\]]*(?:ignore previous|system prompt|you are now|exfiltrate)"
    r"[^\]]*\]\([^)]*\)"
)
_LINK_KEYWORD = re.compile(
    r"ignore previous|system prompt|you are now|exfiltrate", re.IGNORECASE
)


class _MarkdownLinkScanner:
    """Linear stand-in for the link pattern whose source is ``pattern``."""

    pattern = _LINK_SOURCE

    def search(self, text: str):
        opener = -1
        index = 0
        length = len(text)
        while index < length:
            char = text[index]
            if char == "[":
                if opener < 0:
                    opener = index
            elif char == "]":
                if opener >= 0 and index + 1 < length and text[index + 1] == "(":
                    if _LINK_KEYWORD.search(text, opener + 1, index) is not None:
                        closing = text.find(")", index + 2)
                        if closing < 0:
                            return None
                        return _LinearMatch(text, ((opener, closing + 1),))
                opener = -1
            index += 1
        return None


PATTERN = _MarkdownLinkScanner()


def markdown_link_injection_guard() -> Rule:
    """Build a Rule that blocks instructions injected via markdown link text.

    Each top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which field carried the injected
    link. A non-dict ``args``, a dict with no str values, and a dict whose str
    values are all benign each return None (no opinion). The rule never raises.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if PATTERN.search(value):
                return Decision.block(
                    reason="markdown_link_injection: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
