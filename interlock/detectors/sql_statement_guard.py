"""Block (or ask about) SQL by what it does, not by how it is written.

A regex SQL guard reads text: ``WITH gone AS (DELETE FROM t) SELECT * FROM gone``
looks like a read, ``SELECT 'DROP TABLE x'`` looks like a drop. This rule hands
each query argument to :mod:`interlock.sql`, which lexes it (comments and
literals out, dialect quoting rules, ``$$`` bodies) and classifies every
statement by its effects, the tables it reads and writes, and its flags.

Selectors name what to stop::

    sql_statement_guard(block=["drop", "truncate", "unbounded", "external",
                               "write:customers"],
                        escalate=["delete", "grant"])
    sql_statement_guard(read_only=True)     # anything but reads is blocked

=========================  ======================================================
``"delete"``, ``"drop"``   an operation anywhere in the text (``select``,
                           ``insert``, ``update``, ``delete``, ``create``,
                           ``drop``, ``alter``, ``truncate``, ``grant``,
                           ``revoke``, ``unknown`` ...)
``"ddl"``, ``"dml"``,      groups of operations; ``write`` also matches any
``"write"``, ``"control"``  table written
``"write:customers"``      a table written (globs: ``"read:pay*"``,
``"table:audit.*"``)       ``table:`` matches either access
``"unbounded"``            an ``UPDATE``/``DELETE`` with no ``WHERE``
``"opaque"``               ``DO``/``CALL``/``EXEC``/``EXECUTE``/a PL block, or an
                           unrecognised statement
``"external"``             ``COPY ... PROGRAM``, server file I/O, ``INTO
                           OUTFILE``, ``xp_cmdshell``, ``dblink`` ...
``"multi"``                more than one statement
=========================  ======================================================

``read_only=True`` blocks everything except ``select``/``show``/``set``/
transaction control, and anything opaque or external. By default only
arguments named like SQL (``sql``, ``query``, ``statement``, ...) are read;
pass ``keys=`` for others. The reason names the selector and the argument,
never the query text. Parsing is not a boundary: database permissions are.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..sql import GROUPS, analyze_sql

POLICY_ID = "sql_statement"

#: Argument names read as SQL when ``keys`` is not given.
DEFAULT_KEYS = ("sql", "query", "statement", "statements", "stmt", "sql_query", "q")

_READ_ONLY = frozenset({"select", "other"}) | GROUPS["control"]


def sql_statement_guard(
    block: Iterable[str] = (),
    *,
    escalate: Iterable[str] = (),
    read_only: bool = False,
    keys: Optional[Iterable[str]] = DEFAULT_KEYS,
    actions: Optional[Iterable[str]] = None,
    dialect: str = "generic",
) -> Rule:
    """Build a Rule that blocks or escalates SQL arguments by what they do.

    block / escalate: selectors (see the module docstring). A block wins.
    read_only:        block anything that is not a read.
    keys:             argument names holding SQL; None reads every str argument.
    actions:          action names the rule applies to; default every call.
    dialect:          ``generic`` (every dialect's reading, unioned), or
                      ``postgres``, ``mysql``, ``mssql``, ``sqlite``.
    """
    block_selectors = tuple(block)
    escalate_selectors = tuple(escalate)
    if not block_selectors and not escalate_selectors and not read_only:
        raise ValueError("sql_statement_guard needs a selector or read_only=True")
    analyze_sql("", dialect)  # reject an unknown dialect now, not per call
    key_set = None if keys is None else frozenset(keys)
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_set is not None and event.action not in action_set:
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if not isinstance(value, str) or not value.strip():
                continue
            if key_set is not None and name not in key_set:
                continue
            try:
                analysis = analyze_sql(value, dialect)
            except Exception:  # the analyzer never raises; belt and braces
                return Decision.block("sql_statement: unreadable query in {}".format(name),
                                      POLICY_ID, attributed_to=name)
            if read_only:
                writes = (set(analysis.effects) - _READ_ONLY
                          or any(r.access == "write" for r in analysis.relations)
                          or analysis.opaque or analysis.external)
                if writes:
                    return Decision.block(
                        "sql_statement: not read-only ({}) in {}".format(analysis.operation, name),
                        POLICY_ID, attributed_to=name)
            for selector in block_selectors:
                if analysis.matches(selector):
                    return Decision.block("sql_statement: {} in {}".format(selector, name),
                                          POLICY_ID, attributed_to=name)
            for selector in escalate_selectors:
                if analysis.matches(selector):
                    return Decision.escalate(
                        "sql_statement: {} ({}) in {}".format(selector, analysis.operation, name),
                        POLICY_ID, attributed_to=name)
        return None

    return rule
