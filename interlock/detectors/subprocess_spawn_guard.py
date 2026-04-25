"""Argument guard: block code that spawns a subprocess.

Sandboxed code is handed to a ``code`` argument as a string and executed as a
program. The sandbox's containment rests on the code only reaching its approved
APIs, so the escape primitive is the call that starts a *new process outside*
the sandbox: ``subprocess.run``/``Popen``/``call``/``check_output``,
``os.system``, ``os.popen`` and ``pty.spawn`` each hand a command line to the
host shell or a fresh interpreter. That is the first link of an exfiltration
chain - spawn ``sh -c '...'`` and the sandbox boundary is gone. The payload
rides in the argument, so it is visible before the code executes, which is
exactly where this rule sits: on the argument detector, ahead of any effect.

Matching the raw argument text rather than parsing the code is deliberate.
Import aliasing (``import subprocess as sp``) or a computed callee would evade a
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

POLICY_ID = "subprocess_spawn"

# Process-spawning entry points reachable from sandboxed Python. re.IGNORECASE
# is deliberately not applied: it would widen the match to spellings such as
# ``SUBPROCESS.RUN`` and so change which inputs are caught rather than merely
# how they are written.
PATTERN = re.compile(
    r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen|pty\.spawn)\b"
)


def subprocess_spawn_guard() -> Rule:
    """Build a Rule that blocks a code argument that spawns a subprocess.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    spawn call. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="subprocess_spawn: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
