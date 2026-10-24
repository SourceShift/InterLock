"""Argument guard: block irreversible destructive shell commands.

Shell injection is about *who* runs a command; this rule is about *what* the
command does. A handful of command lines destroy state that no later step in
the agent's plan can restore: wiping the root filesystem, overwriting a raw
disk device, reformatting one, recursively loosening permissions on the whole
tree, or a fork bomb that takes the host down. There is no "undo" for any of
them, so the only safe place to stop them is before the tool runs - which is
exactly where this rule sits: on the argument detector, ahead of the effect.

Two checks run, and either one blocks. The raw-text :data:`PATTERN` matches
fragments that must appear verbatim in the destructive spelling. It is anchored
on an absolute ``/`` followed by whitespace or end-of-string, so ``rm -rf /``
and ``rm -rf / --no-preserve-root`` match while a relative-path clean such as
``rm -rf ./build`` does not. But raw text loses to respelling: ``rm -fr /``,
``rm -r -f /``, ``/bin/rm -Rf /``, ``bash -c 'rm -rf /'`` and ``rm -rf ~`` all
slip past it. So the value is also parsed (:mod:`interlock.shell`) and blocked
when it carries a *critical* intent - a recursive delete or permission change
of a root-equivalent or system path, a raw disk write, or a disk format - no
matter how it is spelled or wrapped. The parsed check only adds findings; it
can never clear a value the pattern matched. A value the parser could only
partly read (an unclosed quote, nesting deeper than it follows) may hide the
act, so with no match it escalates to a human instead of passing. Pass
``parse=False`` to keep the raw-text check alone. Neither check is a boundary:
obfuscated commands pass both, and untrusted code belongs in the BRACE sandbox.

Only top-level string values of a dict ``args`` are scanned (or the ``keys``
you name). An int, None, or nested container is skipped rather than
stringified, and a non-dict ``args`` yields no opinion - a detector must never
raise on odd input. The first matching value blocks the call; otherwise a
partly read value escalates it, and no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Iterable, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..shell import read_command

POLICY_ID = "destructive_command"

#: Intent kinds that block when critical (see :mod:`interlock.shell.intents`).
CRITICAL_KINDS = frozenset(
    {"fs.delete.recursive", "fs.permissions.recursive", "disk.overwrite", "disk.format"}
)

# Irreversible destructive command fragments, in the spelling a shell accepts.
# re.IGNORECASE is deliberately not applied: it would widen the match to
# spellings such as ``MKFS`` and ``CHMOD -R 777 /`` and so change which inputs
# are caught rather than merely how they are written. A ``dd`` matches only when
# its ``of=`` is a block device: ``dd if=/dev/zero of=scratch.img`` makes a file.
PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/(?:\s|$)|\bmkfs\b"
    r"|\bdd\b[^;&|\n]*\bof=/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|loop\d)"
    r"|:\(\)\s*\{\s*:\|:|>\s*/dev/sd|chmod\s+-R\s+777\s+/)"
)


def destructive_command_guard(
    *, parse: bool = True, keys: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks an argument naming a destructive command.

    Every top-level str value of a dict ``args`` (or of the ``keys`` you name)
    is tested against :data:`PATTERN` and, unless ``parse=False``, parsed for a
    critical intent in :data:`CRITICAL_KINDS`. On the first match the rule
    returns a BLOCK naming the offending argument, so the caller can tell which
    parameter carried the command. With no match, a value the parser could only
    partly read returns an ESCALATE naming it. A non-dict ``args``, a dict with
    no str values, and a dict whose str values are all benign and fully read
    each return None (no opinion). The rule never raises.
    """
    key_set = None if keys is None else frozenset(keys)

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        unread = None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if key_set is not None and name not in key_set:
                continue
            critical, partial = bool(PATTERN.search(value)), False
            if not critical and parse:
                critical, partial = _scan(value)
            if critical:
                return Decision.block(
                    reason="destructive_command: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )
            if partial and unread is None:
                unread = name

        if unread is not None:
            return Decision.escalate(
                reason="destructive_command: {} could not be fully read".format(unread),
                policy_id=POLICY_ID,
                attributed_to=unread,
            )
        return None

    return rule


def _scan(value: str) -> Tuple[bool, bool]:
    """Whether ``value`` carries a critical intent, and whether it was partly read."""
    try:
        intents, partial = read_command(value)
    except Exception:  # a parser bug is a value it could not read
        return False, True
    return any(i.critical and i.kind in CRITICAL_KINDS for i in intents), partial
