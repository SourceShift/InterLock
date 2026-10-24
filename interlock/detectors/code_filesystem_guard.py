"""Argument guard: block submitted code that reaches the filesystem.

A sandboxed code tool is handed a string and executes it somewhere that is
supposed to have no I/O reach. The filesystem is the shortest way out of that
box: ``open('/etc/passwd')`` reads host state, ``os.remove``/``os.unlink``/
``os.rmdir`` destroy it, ``os.system`` shells out, and ``shutil``/``pathlib``
carry whole families of the same operations behind a tidy import. The payload
sits in the argument and is visible before the call runs, which is where this
rule sits: on the argument detector, ahead of any effect.

Matching the raw argument text rather than a parsed AST is deliberate. Parsing
submitted source means running a parser on the attack surface, and a payload can
hide behind ``getattr(os, "rem" + "ove")`` in ways no single pattern catches.
What the pattern does catch is the common case: the literal call form embedded
in surrounding source. ``re.search`` is used rather than ``fullmatch`` because
the call appears inside a multi-line script - a script that mentions ``open(``
anywhere is enough.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first matching
value blocks the call; no match returns None (no opinion).

Identifiers are matched after NFKC normalization because that is how Python
reads them: a fullwidth spelling of ``open`` or ``pathlib.Path`` is the same
name to the interpreter, so it must be to this guard too. The raw text is
scanned first, so the reason and attribution of an ordinary ASCII match do not
change.
"""
from __future__ import annotations

import re
from typing import Optional

from .._unicode import nfkc
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "code_filesystem"

# Filesystem entry points: the ``open`` builtin, the destructive members of
# ``os``, and the ``shutil``/``pathlib`` modules. The ``\b`` anchor keeps the
# match on a bare identifier (``open(`` matches; ``reopen(`` does not). The
# trailing ``\b`` on the ``os`` alternatives stops ``os.systemx`` from matching
# while allowing ``os.system(``. re.IGNORECASE is deliberately not applied:
# folding case would widen ``pathlib.Path`` to the non-existent ``pathlib.path``
# and ``open(`` to ``OPEN(``, changing which inputs are caught rather than merely
# how they are written.
PATTERN = re.compile(
    r"(?:\bopen\s*\(|\bos\.(?:remove|unlink|rmdir|system)\b|\bshutil\.|\bpathlib\.Path)"
)


def code_filesystem_guard() -> Rule:
    """Build a Rule that blocks a code argument reaching the filesystem.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`, first as written and then in NFKC form. On the first
    match the rule returns a BLOCK naming the offending argument, so the caller
    can tell which parameter carried the payload. A non-dict ``args``, a dict
    with no str values, and a dict whose str values are all clean each return
    None (no opinion). The rule never raises.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if not PATTERN.search(value):
                normalized = nfkc(value)
                if normalized == value or not PATTERN.search(normalized):
                    continue
            return Decision.block(
                reason="code_filesystem: {}".format(name),
                policy_id=POLICY_ID,
                attributed_to=name,
            )

        return None

    return rule
