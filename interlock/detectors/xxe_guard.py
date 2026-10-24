"""Argument guard: block XML external-entity (XXE) declarations in tool arguments.

An XML parser that resolves external entities turns a document the caller
supposed to be *data* into a file read or an outbound request. The document
declares the entity in its prolog and dereferences it in place:

    <?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root>&xxe;</root>

The parser substitutes the contents of ``/etc/passwd`` for ``&xxe;``, so the
response - an error message, a rendered page, a logged body - carries a secret
the caller never asked for. The same primitive reads arbitrary local files and,
with the ``http://`` scheme, performs a server-side request forgery against
internal endpoints.

The pattern targets the *declarations* that enable the primitive, not the
benign XML an application legitimately parses:

    <!DOCTYPE ... [   - an internal DTD subset, the only place an entity can
                        be declared without an external DTD reference
    <!ENTITY          - an entity declaration of any kind
    SYSTEM "file:     - a file-scheme external identifier
    SYSTEM "http      - an http-scheme external identifier

An ordinary document - ``<note><to>Amir</to></note>`` - contains none of
these. ``re.IGNORECASE`` is deliberately *not* applied: XML keywords are
case-sensitive, so ``<!doctype`` is not a valid declaration and folding the
case would match prose (``system "file:`` in a config snippet) that the parser
would never treat as an entity, widening the guard past its intent.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first
matching value blocks the call; no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import _LinearMatch, _is_word
from ..policy.engine import Rule

POLICY_ID = "xxe"

# Declarations that enable external-entity resolution:
#   <!DOCTYPE[^>]*\[  - a DOCTYPE carrying an internal subset (where entities live)
#   <!ENTITY\b        - an entity declaration
#   SYSTEM\s+"file:   - a file-scheme external identifier
#   SYSTEM\s+"http    - an http-scheme external identifier
# Case is not folded: the XML keywords are case-sensitive, so IGNORECASE would
# match ordinary prose the parser would never read as a declaration.
#
# The scanner below keeps the same acceptance set without rescanning a suffix
# per marker. Each ``<!DOCTYPE`` checks the next ``>`` and ``[`` once (a ``[``
# before the ``>`` -- or before end-of-text -- is the match); a failed DOCTYPE
# consumes through its ``>``, so ``"<!DOCTYPE" * n`` is one pass. The ENTITY
# branch tests the ``\b`` boundary; the two SYSTEM branches keep ``\s+``
# anchored at each occurrence. Only ``<!DOCTYPE`` needs the precomputed next
# ``>``/``[`` positions, built once per search.
_XXE_SOURCE = r'(?:<!DOCTYPE[^>]*\[|<!ENTITY\b|SYSTEM\s+"file:|SYSTEM\s+"http)'
_SYSTEM_FILE = re.compile(r'SYSTEM\s+"file:')
_SYSTEM_HTTP = re.compile(r'SYSTEM\s+"http')


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


class _XxeScanner:
    """Linear stand-in for the XXE pattern whose source is ``pattern``."""

    pattern = _XXE_SOURCE

    def search(self, text: str):
        best = self._doctype(text)
        entity = self._entity(text)
        if entity is not None and (best is None or entity[0] < best[0]):
            best = entity
        system = self._system(text)
        if system is not None and (best is None or system[0] < best[0]):
            best = system
        return None if best is None else _LinearMatch(text, (best,))

    @staticmethod
    def _doctype(text: str):
        position = text.find("<!DOCTYPE")
        if position < 0:
            return None
        length = len(text)
        next_gt = _next_character(text, ">")
        while position >= 0:
            after = position + 9  # len("<!DOCTYPE")
            gt = next_gt[after]
            # ``[^>]*`` is greedy, so the match ends at the *last* ``[`` before
            # the first ``>`` (or before end-of-text when there is none).
            bracket = text.rfind("[", after, gt)
            if bracket >= 0:
                return (position, bracket + 1)
            if gt >= length:
                return None
            position = text.find("<!DOCTYPE", gt + 1)
        return None

    @staticmethod
    def _entity(text: str):
        position = text.find("<!ENTITY")
        while position >= 0:
            if not _is_word(text, position + 8):  # the trailing \b
                return (position, position + 8)
            position = text.find("<!ENTITY", position + 1)
        return None

    @staticmethod
    def _system(text: str):
        position = text.find("SYSTEM")
        while position >= 0:
            match = (
                _SYSTEM_FILE.match(text, position)
                or _SYSTEM_HTTP.match(text, position)
            )
            if match is not None:
                return (position, match.end())
            position = text.find("SYSTEM", position + 1)
        return None


PATTERN = _XxeScanner()


def xxe_guard() -> Rule:
    """Build a Rule that blocks an argument carrying an XXE declaration.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    document. A non-dict ``args``, a dict with no str values, and a dict whose
    str values are all benign each return None (no opinion). The rule never
    raises.
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
                    reason="xxe: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
