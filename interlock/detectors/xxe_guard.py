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
from ..policy.engine import Rule

POLICY_ID = "xxe"

# Declarations that enable external-entity resolution:
#   <!DOCTYPE[^>]*\[  - a DOCTYPE carrying an internal subset (where entities live)
#   <!ENTITY\b        - an entity declaration
#   SYSTEM\s+"file:   - a file-scheme external identifier
#   SYSTEM\s+"http    - an http-scheme external identifier
# Case is not folded: the XML keywords are case-sensitive, so IGNORECASE would
# match ordinary prose the parser would never read as a declaration.
PATTERN = re.compile(r'(?:<!DOCTYPE[^>]*\[|<!ENTITY\b|SYSTEM\s+"file:|SYSTEM\s+"http)')


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
