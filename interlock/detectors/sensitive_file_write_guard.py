"""Argument guard: block writes aimed at credential or system config paths.

A write tool is handed a destination and trusts it. That trust becomes a
capability when the destination is a credential store or a system
configuration root: ``/root/.ssh/authorized_keys`` installs a key that grants
persistent access, ``.env`` leaks or rewrites the secrets a process starts
with, and ``/etc/`` or ``/boot/`` turn a file write into host takeover. The
destination travels in the argument, so it is visible before the tool runs -
which is where this rule sits, on the argument detector, ahead of any
filesystem effect.

Matching the raw text rather than a resolved path is deliberate. Resolution is
not available until the tool does the work, and a resolver that follows
symlinks can be steered away from the very input the attacker sent. The rule
instead recognises the common spellings as literal fragments: ``/etc/``,
``/root/``, ``/boot/``, ``.ssh/``, ``.aws/``, a trailing ``.env``, the
``id_rsa`` and ``authorized_keys`` key filenames. Each is a substring a write
to a credential or config path must contain and an ordinary output path
(``output/summary.txt``) will not.

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

POLICY_ID = "sensitive_write"

# Credential-store and system-config path fragments. re.IGNORECASE is
# deliberately not applied: it would widen the match to spellings such as
# ``/ETC/`` or ``AUTHORIZED_KEYS`` and so change which inputs are caught
# rather than merely how they are written.
PATTERN = re.compile(
    r"(?:/etc/|/root/|\.ssh/|\.aws/|\.env$|\.env\b|id_rsa|authorized_keys|/boot/)"
)


def sensitive_file_write_guard() -> Rule:
    """Build a Rule that blocks a write argument aimed at a sensitive path.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    destination. A non-dict ``args``, a dict with no str values, and a dict
    whose str values are all clean each return None (no opinion). The rule
    never raises.
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
                    reason="sensitive_write: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
