"""Argument guard: block reads of git credential stores.

Git keeps long-lived secrets on disk. ``~/.git-credentials`` holds plaintext
HTTPS tokens, ``.git/config`` can carry an embedded ``user:password`` URL, and
``~/.netrc`` holds machine logins. A file-reading tool handed any of these
paths is one call away from the caller's git identity, so the read is stopped
at the argument - before the tool opens anything.

The signature also covers the *command* form: ``git config --get url.*`` and
``git config --get remote.origin.password`` print credentials to stdout, which
is just a read wearing a subprocess costume. Both shapes travel in a string
argument, so a regex over the argument text sees them in time.

Matching literal/short-regex fragments rather than a resolved path is
deliberate: the resolved path only exists after the tool runs, and a resolver
can be fooled by symlinks. The fragments are distinctive enough that ordinary
source reads (``src/main.py``) never trip them. ``re.IGNORECASE`` is
deliberately not applied: git's own paths and subcommands are lowercase, and
folding case would widen the match to spellings such as ``GIT CONFIG`` - it
would change *which* inputs are caught, not merely how they are written.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first matching
value blocks the call; no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "git_credential_read"

# Credential-store paths and the ``git config --get`` read form. ``\.git/config``
# is anchored on the ``.git/`` directory so a source file named ``config.py``
# does not match; ``git\s+config\s+--get`` requires the subcommand plus the
# ``--get`` flag, and ``.*(?:url|password)`` requires a credential-shaped key.
# re.IGNORECASE is deliberately not applied (see module docstring).
PATTERN = re.compile(
    r"(?:\.git-credentials|\.git/config|\.netrc|git\s+config\s+--get\s+.*(?:url|password))"
)


def git_credential_guard() -> Rule:
    """Build a Rule that blocks an argument naming a git credential store.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    read. A non-dict ``args``, a dict with no str values, and a dict whose str
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
                    reason="git_credential_read: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
