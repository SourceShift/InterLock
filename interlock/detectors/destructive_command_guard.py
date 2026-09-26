"""Argument guard: block irreversible destructive shell commands.

Shell injection is about *who* runs a command; this rule is about *what* the
command does. A handful of command lines destroy state that no later step in
the agent's plan can restore: wiping the root filesystem, overwriting a raw
disk device, reformatting one, recursively loosening permissions on the whole
tree, or a fork bomb that takes the host down. There is no "undo" for any of
them, so the only safe place to stop them is before the tool runs - which is
exactly where this rule sits: on the argument detector, ahead of the effect.

Matching the raw argument text rather than a parsed command is deliberate. The
invocation is a string the model assembled; its tokenised form does not exist
until the shell parses it, and the shell's grammar is larger than any parser we
could ship here. The fragments the pattern looks for are those that must appear
verbatim in the destructive spelling, and that an ordinary value will not
contain. The root-wipe branch is anchored on an absolute ``/`` followed by
whitespace or end-of-string, so ``rm -rf /`` and ``rm -rf / --no-preserve-root``
match while a relative-path clean such as ``rm -rf ./build`` does not - the
guard targets the unrecoverable case, not routine cleanup.

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

POLICY_ID = "destructive_command"

# Irreversible destructive command fragments, in the spelling a shell accepts.
# re.IGNORECASE is deliberately not applied: it would widen the match to
# spellings such as ``MKFS`` and ``CHMOD -R 777 /`` and so change which inputs
# are caught rather than merely how they are written.
PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/(?:\s|$)|\bmkfs\b|\bdd\s+if=|:\(\)\s*\{\s*:\|:|>\s*/dev/sd|chmod\s+-R\s+777\s+/)"
)


def destructive_command_guard() -> Rule:
    """Build a Rule that blocks an argument naming a destructive command.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    command. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="destructive_command: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
