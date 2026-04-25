"""Argument guard: block submitted code that calls a dynamic-execution builtin.

A code tool takes a string and evaluates it - whether that string is handed to
``exec``, ``eval``, ``compile`` or reached through ``__import__``. The payload
is the argument, and it is visible before the call runs, which is where this
rule sits: on the argument detector, ahead of any effect. A model that is asked
to "run some Python" and returns ``exec(base64.b64decode(payload))`` has put
the execution primitive directly in the argument text.

Matching the raw argument text rather than a parsed AST is deliberate. Parsing
submitted source means running a parser on the attack surface, and a payload
can hide behind ``getattr(builtins, "ev" + "al")`` in ways no single pattern
catches. What the pattern does catch is the common case: the literal builtin
name followed by a call. ``re.search`` is used rather than ``fullmatch`` because
the call is embedded in surrounding source - a multi-line script that mentions
``compile(`` anywhere is enough.

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

POLICY_ID = "code_eval_exec"

# A dynamic-execution builtin followed by a call. The ``\b`` anchor keeps the
# match on a bare identifier (``__import__(`` matches at the start of a name;
# ``myeval(`` does not). re.IGNORECASE is deliberately not applied: the Python
# builtins are spelled in lower case, so folding case would only widen the match
# to names such as ``EVAL(`` that are not the builtin, changing which inputs are
# caught rather than merely how they are written.
PATTERN = re.compile(r"\b(?:eval|exec|compile|__import__)\s*\(")


def code_eval_exec_guard() -> Rule:
    """Build a Rule that blocks a code argument calling eval/exec/compile/__import__.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    payload. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="code_eval_exec: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
