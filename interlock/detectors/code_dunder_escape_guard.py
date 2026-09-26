"""Argument guard: block code arguments that walk the Python object graph.

A tool that executes a string as Python (``exec``, ``eval``, a code sandbox)
takes model-controlled text and turns it into a program. The escape from such a
sandbox does not need an import statement or a file write: it starts from any
object the sandbox already handed the code and climbs the object graph to
something dangerous. ``().__class__.__bases__[0].__subclasses__()`` enumerates
every class the interpreter has loaded, which is enough to reach a class whose
module holds ``os`` or ``subprocess``; ``__globals__`` / ``__builtins__`` reach
the real builtins and the defining module's globals from any function object.
These are the *mechanism* of sandbox escape - a payload must name one of them,
whichever route it takes to the effect.

Matching the raw source text rather than a parsed AST is deliberate: parsing
model-supplied code is itself an attack surface (recursion limits, encodings),
and the dunder names a working escape must contain are a closed, literal set
that ordinary code does not spell. A payload can obfuscate the name
(``getattr(x, "__glo"+"bals__")``) and evade a text match, but that is a
different, noisier technique; the direct walk this rule targets is the common
shape and the cheap one to catch.

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

POLICY_ID = "code_dunder_escape"

# Attribute names that let code walk from an object it already holds to the
# interpreter's loaded classes, modules, globals, or builtins. ``__class__`` is
# listed only as part of ``__class__.__bases__`` - the bare name is ordinary
# and appears in legitimate introspection; the pairing is what signals a climb
# up the MRO. re.IGNORECASE is deliberately not applied: Python attributes are
# case-sensitive, so matching ``__GLOBALS__`` would widen the guard to
# spellings that cannot resolve at runtime and so change which inputs are
# caught rather than merely how they are written.
PATTERN = re.compile(
    r"(?:__globals__|__builtins__|__subclasses__|__mro__|__class__\.__bases__|__import__)"
)


def code_dunder_escape_guard() -> Rule:
    """Build a Rule that blocks a code argument walking the Python object graph.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    escape. A non-dict ``args``, a dict with no str values, and a dict whose
    str values are all clean each return None (no opinion). The rule never
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
                    reason="code_dunder_escape: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
