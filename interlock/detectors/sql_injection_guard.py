"""Argument guard: block query arguments carrying classic SQL-injection shapes.

A query tool takes a string and hands it to a database. That hand-off is the
vulnerability: an argument the model controls is concatenated into a statement,
so a value that reads as ordinary text to the model is executable SQL to the
engine. SQL injection is the class of attack that exploits it - a quote closes
the intended literal, ``OR 1=1`` turns the predicate true for every row, and a
``;`` ends the intended statement so ``DROP TABLE`` runs as a second one. The
payload rides in the argument, so it is visible before the tool runs, which is
exactly where this rule sits: on the argument detector, ahead of any effect.

Matching the raw argument text rather than a parsed statement is deliberate. The
statement does not exist until the database parses it, and SQL's grammar is
larger than any parser we could ship here (dialect differences, nested
subqueries, comments); the fragments the pattern looks for are substrings an
injection payload must contain and an ordinary value (``select name from users
where id = 5``) will not. The pattern covers the canonical shapes: quote-break
with ``OR``, statement stacking via ``; drop table``, ``union select`` data
exfiltration, ``--`` and ``/* */`` comment truncation, and ``xp_cmdshell``
command execution on MSSQL.

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

POLICY_ID = "sql_injection"

# Classic SQL-injection payload fragments. ``(?i)`` is placed at the start of
# the pattern and is the only flag applied: SQL keywords are case-insensitive in
# every dialect, so ``OR``/``DROP TABLE``/``UNION SELECT`` must match regardless
# of spelling, and folding case here does not widen the match to any benign
# value the lowercase spellings would miss.
PATTERN = re.compile(
    r"(?i)(?:'\s*or\s*'?\d|;\s*drop\s+table|union\s+select|--\s|/\*.*\*/|xp_cmdshell)"
)


def sql_injection_guard() -> Rule:
    """Build a Rule that blocks a query argument carrying SQL-injection syntax.

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
                    reason="sql_injection: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
