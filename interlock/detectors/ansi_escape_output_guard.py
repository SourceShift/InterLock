"""Argument guard: block ANSI-escape sequences in output-bound text.

An ANSI escape sequence is a rendering instruction, not content. If an agent
emits text containing one and a downstream consumer writes it to a terminal,
`echo -e`s it, or pipes it through a logger that interprets escapes, the
sequence stops being text and becomes a command to the display: ``\\x1b[2J``
clears the screen, ``\\x1b[31m`` recolours everything after it, and
``\\x1b[<n>A`` / ``\\x1b[<n>D`` can overwrite lines the user already read. A
model that can smuggle one into its output can therefore forge, hide, or
reorder what a human sees while the surrounding text looks benign.

The sequence travels as an ordinary string argument, so a regex over the
argument text sees it before the output leaves the process. The pattern covers
both shapes the sequence can take:

* the live byte - a real ``ESC`` (``\\x1b``) or the C1 single-byte introducer
  ``\\x9b``, followed by ``[``; and
* the *escaped* textual forms - the literal characters ``\\x1b[``, ``\\033[``,
  and ``\\u001b[``, which are inert in the producing process but become a live
  escape the moment a consumer unescapes or re-emits them.

Only top-level string values of a dict ``args`` are scanned: an int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first
matching value blocks the call; no match returns None (no opinion).

``re.IGNORECASE`` is deliberately not applied: it would fold the literal
alternative so ``\\X1B[`` matched too, which widens *which* inputs are caught
rather than merely how they are written.
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "ansi_escape_output"

# Live introducers (real ESC ``\x1b`` and the C1 ``\x9b``, each followed by
# ``[``) and their escaped textual spellings (``\x1b[``, ``\033[``, ``[``).
# re.IGNORECASE is deliberately not applied (see module docstring).
PATTERN = re.compile(r"(?:\x1b\[|\\x1b\[|\\033\[|\\u001b\[|\x9b)")


def ansi_escape_output_guard() -> Rule:
    """Build a Rule that blocks an argument carrying an ANSI escape sequence.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    escape. A non-dict ``args``, a dict with no str values, and a dict whose str
    values are all clean each return None (no opinion). The rule never raises.
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
                    reason="ansi_escape_output: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
