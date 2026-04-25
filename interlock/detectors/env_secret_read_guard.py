"""Argument guard: block reads of secret-bearing environment variables.

The agent's own process environment is the leak surface this rule defends. A
model that has been steered, or a tool result that has been poisoned, can try
to pull credentials out of the environment and ship them somewhere: ``printenv``
dumps the whole block, ``env | ...`` pipes it, ``echo $AWS_SECRET_ACCESS_KEY``
expands one, and ``os.environ[...]`` reaches it from inside Python. Each of
these produces a secret in the clear, which a later step can forward - so the
only place to stop the read is before the tool runs, on the argument detector.

The pattern is deliberately narrow: it keys on the secret-*shaped* variable
name suffixes (SECRET, KEY, TOKEN, PASSWORD), so ``echo $HOME`` and
``echo $PATH`` are left alone. ``re.IGNORECASE`` is not applied: it would widen
``[A-Z_]`` to lowercase and so start catching ``echo $mykey`` and ``ENV |`` -
changing *which* inputs match rather than merely how they are spelled.

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

POLICY_ID = "env_secret_read"

# Reads of secret-bearing environment variables, in the spelling a shell or
# CPython accepts: a full dump (printenv), a pipe of the whole block
# (env | ...), a shell expansion of one var whose name ends in a secret-shaped
# suffix, or a direct os.environ[...] lookup.
PATTERN = re.compile(
    r"(?:printenv|env\s*\||echo\s+\$[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)|os\.environ\[)"
)


def env_secret_read_guard() -> Rule:
    """Build a Rule that blocks an argument reading a secret env var.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    read. A non-dict ``args``, a dict with no str values, and a dict whose str
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
                    reason="env_secret_read: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
