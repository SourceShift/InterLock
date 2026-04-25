"""Argument guard: block NoSQL operator injection smuggled into tool arguments.

A tool that forwards its argument straight to a document store inherits the
store's query grammar. MongoDB-style operators - ``$gt``, ``$ne``, ``$regex``,
``$where``, ``$or``, ``$in`` - are just data to the language model but code to
the database: an argument that was meant to be a scalar filter becomes a query
predicate. The classic shape is

    {"filter": "{\\"password\\": {\\"$gt\\": \\"\\"}}"}

which, once parsed, asks the store for the first document whose password is
greater than the empty string - i.e. any document at all. The same trick turns
an equality check into a wildcard (``$ne``), a regex match into a scan
(``$regex``), or hands the database an expression to evaluate (``$where``).
The guard's job is to stop the operator before it reaches the query.

The pattern matches an operator token followed by the ``:`` or ``=`` that binds
it to a value. A closing quote is permitted between the two because the payload
arrives as JSON, where the operator is a *quoted key* - ``"$gt":`` - so the
quote, not the operator, is what sits against the colon. The token is anchored
by ``\\b`` so ``$gte`` and ``$nin`` (distinct, benign-to-this-rule operators)
are not caught by the ``$gt``/``$in`` branches. ``re.IGNORECASE`` is
deliberately absent: MongoDB operators are case-sensitive lowercase, so folding
case would widen the match to spellings the store does not recognise as
operators - changed behaviour, not merely changed spelling.

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

POLICY_ID = "nosql_injection"

# A query operator followed by its value-binding ':' or '='. The optional quote
# absorbs the closing quote of a JSON operator key ("$gt": ...) in either quote
# style. re.IGNORECASE is deliberately not applied: it would fold case onto
# spellings MongoDB does not treat as operators, changing which inputs are
# caught.
PATTERN = re.compile(r"""(?:\$where|\$gt\b|\$ne\b|\$regex\b|\$or\b|\$in\b)["']?\s*[:=]""")


def nosql_injection_guard() -> Rule:
    """Build a Rule that blocks an argument carrying a NoSQL query operator.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    operator. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="nosql_injection: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
