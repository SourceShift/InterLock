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

from ..actions import command_values, joined_command
from ..enforce import Decision
from ..event import SensorEvent
from ..masking import _LinearMatch, _is_word
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
#
# Six unrelated alternatives share this pattern; only the ``dd`` branch is
# super-linear (it rescans a whole segment for every ``dd``). The scanner below
# runs the other five over the whole text exactly as the original alternation
# did -- ``\s`` crosses newlines, so they must not be split on segment
# boundaries -- and handles ``dd`` with one pass per segment (segments split on
# ``[;&|\n]``, as ``[^;&|\n]*`` requires). Device prefixes, case sensitivity and
# the other five alternatives are unchanged.
_DESTRUCTIVE_SOURCE = (
    r"(?:rm\s+-rf\s+/(?:\s|$)|\bmkfs\b"
    r"|\bdd\b[^;&|\n]*\bof=/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|loop\d)"
    r"|:\(\)\s*\{\s*:\|:|>\s*/dev/sd|chmod\s+-R\s+777\s+/)"
)
_NON_DD_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/(?:\s|$)|\bmkfs\b"
    r"|:\(\)\s*\{\s*:\|:|>\s*/dev/sd|chmod\s+-R\s+777\s+/)"
)
_DEVICE_PATTERN = re.compile(
    r"(?:r?disk\d|sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|loop\d)"
)


class _DestructiveScanner:
    """Linear stand-in for the destructive-command pattern; exposes ``search``."""

    pattern = _DESTRUCTIVE_SOURCE

    def search(self, text: str):
        match = _NON_DD_PATTERN.search(text)
        non_dd = None if match is None else match.span()
        dd = self._dd_span(text)
        if non_dd is None:
            best = dd
        elif dd is None:
            best = non_dd
        else:
            best = non_dd if non_dd[0] <= dd[0] else dd
        return None if best is None else _LinearMatch(text, (best,))

    @staticmethod
    def _dd_span(text: str):
        length = len(text)
        segment_start = 0
        while segment_start <= length:
            segment_end = segment_start
            while segment_end < length and text[segment_end] not in ";&|\n":
                segment_end += 1
            span = _DestructiveScanner._dd_in_segment(text, segment_start, segment_end)
            if span is not None:
                return span
            if segment_end >= length:
                return None
            segment_start = segment_end + 1
        return None

    @staticmethod
    def _dd_in_segment(text: str, start: int, end: int):
        position = start
        while True:
            position = text.find("dd", position, end)
            if position < 0:
                return None
            if not _is_word(text, position - 1) and not _is_word(text, position + 2):
                break
            position += 1
        search_from = position + 2
        found = None
        while True:
            of_at = text.find("of=/dev/", search_from, end)
            if of_at < 0:
                # The original ``[^;&|\n]*`` is greedy, so its match ends at
                # the rightmost ``of=/dev/<device>`` in the segment.
                return found
            if not _is_word(text, of_at - 1):  # the \b in \bof=
                device = _DEVICE_PATTERN.match(text, of_at + 8)
                if device is not None:
                    found = (position, device.end())
            search_from = of_at + 1


PATTERN = _DestructiveScanner()


def destructive_command_guard(
    *, parse: bool = True, keys: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks an argument naming a destructive command.

    Every top-level str value of a dict ``args`` (or of the ``keys`` you name)
    is tested against :data:`PATTERN` and, unless ``parse=False``, parsed for a
    critical intent in :data:`CRITICAL_KINDS`. A split ``command`` + ``args``
    pair is also joined by :func:`interlock.actions.command_values` and judged
    as the invocation it would run; that derived joined form is handed to the
    parser only, because its words are argument data where a destructive phrase
    can be inert (``grep rm -rf / notes``). The bare ``command`` value is still
    tested by :data:`PATTERN`, so a whole command line carried there and
    accompanied by an ``args`` list stays blocked. On the first match the rule returns a
    BLOCK naming the offending argument, so the caller can tell which parameter
    carried the command. With no match, a value the parser could only partly
    read returns an ESCALATE naming it. A non-dict ``args``, a dict with no str
    values, and a dict whose str values are all benign and fully read each
    return None (no opinion). The rule never raises.
    """
    key_set = None if keys is None else frozenset(keys)

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        joined = joined_command(args)
        joined_is_judged = joined is not None and (
            key_set is None or "command" in key_set
        )
        unread = None
        for name, value in command_values(args, key_set):
            # The raw pattern is a lexical test for a command line. A joined
            # ``command`` + ``args`` pair is an argv, where the same words can
            # be harmless argument data (``grep rm -rf / file``), so it is
            # judged by the parser below instead, which knows which word is the
            # program.
            if joined_is_judged and name == "command" and value == joined:
                critical, partial = False, False
                if parse:
                    critical, partial = _scan(value)
            else:
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
