"""Argument guard: block code that signals or forks out of the sandbox.

Sandboxed code arrives as a string in a ``code`` argument and runs as a program.
The sandbox's containment assumes the code stays inside its process, so the
escape primitive is the call that stops, kills or duplicates that process:
``os.kill`` reaps an arbitrary pid, ``os.abort`` and ``os._exit`` tear the
interpreter down without unwinding, ``os.fork`` clones the current process
outside any supervisor that only watches the original, and ``signal.`` reaches
the host's signal handling. Each is the destructive or boundary-crossing
sibling of the process-spawn primitives, and each is visible in the argument
text before the code executes - which is exactly where this rule sits: on the
argument detector, ahead of the effect.

Matching the raw argument text rather than parsing the code is deliberate.
Import aliasing (``import os as o``) or a computed callee would evade a
syntactic check, but the fragments this pattern looks for are the spellings an
ordinary snippet that stays inside the sandbox will not contain, and a false
positive on a benign string costs only a block the caller can inspect. Only
top-level string values of a dict ``args`` are scanned; an int, None, or nested
container is skipped rather than stringified, and a non-dict ``args`` yields no
opinion - a detector must never raise on odd input. The first matching value
blocks; no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "signal_kill"

# Process-signalling / fork entry points reachable from sandboxed Python.
# re.IGNORECASE is deliberately not applied: it would widen the match to
# spellings such as ``OS.KILL`` and ``SIGNAL.SIGTERM`` and so change which
# inputs are caught rather than merely how they are written. The trailing \b
# is what keeps the bare module names out of scope: ``import signal`` does not
# match, while ``signal.SIGTERM`` does, because the boundary needs a word
# character after the dot.
PATTERN = re.compile(
    r"\b(?:os\.kill|os\.abort|signal\.|os\._exit|os\.fork)\b"
)


def signal_kill_guard() -> Rule:
    """Build a Rule that blocks a code argument that signals or forks.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    call. A non-dict ``args``, a dict with no str values, and a dict whose str
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
                    reason="signal_kill: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
