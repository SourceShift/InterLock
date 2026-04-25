"""Argument guard: block allocation bombs before they exhaust memory.

An agent emits code and data as *text*. Most of that text is harmless, but a
handful of ordinary-looking expressions allocate gigabytes in a single step:
``[0] * 10 ** 9`` is one multiplication away from an out-of-memory kill, and the
failure takes down the whole process rather than returning a clean error. The
danger is not in the shape of the code - it is a plain list, a plain
``bytearray``, a plain ``range`` - but in the *size* folded into a constant the
model wrote. There is no partial state to recover: once the allocation runs,
the host is already over the cliff, so the only safe moment to stop it is
before the tool executes.

Matching the raw argument text rather than a parsed expression is deliberate.
The string is what the model assembled; its syntax tree does not exist until
something parses it, and a parser accepts a far larger language than the
allocations worth catching. The pattern instead targets the literal spelling of
a bomb: a repeat count of ``10 ** 7`` or higher, a multi-digit power of ten, or
``10 ** 8``/``10 ** 9`` handed to ``bytearray`` or ``range``. Those fragments
must appear verbatim in the bomb, and an ordinary value will not contain them -
``[0] * 100`` is a hundred elements and stays clear.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first
matching value blocks the call naming the offending argument; no match returns
None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "memory_bomb"

# Spelled-out allocation bombs, in the form the model writes them. Each branch
# is anchored on a literal fragment with bounded quantifiers, so the scan stays
# linear even on adversarial input. re.IGNORECASE is deliberately not applied:
# it would widen the match to spellings such as ``BYTEARRAY(`` and ``RANGE(``
# and so change which inputs are caught rather than merely how they are
# written.
PATTERN = re.compile(
    r"(?:\*\s*10\s*\*\*\s*[7-9]|\*\s*1[0-9]{7,}|bytearray\(\s*10\s*\*\*|range\(\s*10\s*\*\*\s*[89])"
)


def memory_bomb_guard() -> Rule:
    """Build a Rule that blocks an argument naming a memory-bomb allocation.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    bomb. A non-dict ``args``, a dict with no str values, and a dict whose str
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
                    reason="memory_bomb: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
