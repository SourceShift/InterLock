"""Argument guard: block command arguments that carry shell metacharacters.

A command tool takes a string and hands it to a shell. That hand-off is the
vulnerability: any argument the model controls is interpolated into a command
line, so a value that looks like ordinary text to the model is executable
syntax to ``sh``. Shell injection is the class of attack that exploits it - a
semicolon ends the intended command, ``|``/``||``/``&&`` chain another, and
``$(...)`` or a backtick substitutes the output of an embedded command. The
payload rides in the argument, so it is visible before the tool runs, which is
exactly where this rule sits: on the argument detector, ahead of any effect.

Matching the raw argument text rather than a parsed command is deliberate. The
tokenised command does not exist until the shell parses it, and the shell's
grammar is larger than any parser we could ship here (quoting, expansion,
``eval``); the fragments the pattern looks for are substrings a shell payload
must contain and an ordinary value (``ls reports``) will not. The pattern also
flags a few unambiguous dangerous command fragments - ``rm -rf``, and the
network fetchers ``curl`` and ``wget`` - which are the usual exfiltration
second half of an injected chain.

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

POLICY_ID = "shell_injection"

# Shell metacharacters and dangerous command fragments. The metacharacters are
# the injection *mechanism* (``;`` sequencing, ``|`` / ``||`` / ``&&`` chaining,
# ``$(`` / backtick substitution, ``> /`` redirection to an absolute path); the
# command fragments (``rm -rf``, ``curl``, ``wget``) are the usual payload.
# re.IGNORECASE is deliberately not applied: it would widen the match to
# spellings such as ``CURL`` and ``RM -RF`` and so change which inputs are
# caught rather than merely how they are written.
PATTERN = re.compile(
    r"(?:;|\||\|\||&&|\$\(|`|>\s*/|\brm\s+-rf\b|\bcurl\b|\bwget\b)"
)


def shell_injection_guard() -> Rule:
    """Build a Rule that blocks a command argument carrying shell syntax.

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
                    reason="shell_injection: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
