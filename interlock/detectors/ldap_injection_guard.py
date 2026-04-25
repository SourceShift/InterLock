"""Argument guard: block LDAP filter injection smuggled into tool arguments.

A tool that forwards its argument into an LDAP search filter inherits the
filter grammar. The filter is a parenthesised, prefix-notation expression -
``(&(uid=alice)(pw=secret))`` - and its metacharacters are ``* ( ) \\``. Those
characters are data to the language model but structure to the directory
server, so an argument that was meant to be a scalar value can be re-read as
new filter syntax. The classic shape is

    uid=*)(objectClass=*

which closes the ``(uid=...)`` assertion the caller opened, balances the
expression with the trailing ``)``, and injects ``objectClass=*`` - a clause
that is true of every entry. The surrounding filter is now a tautology and the
search returns the whole directory instead of one user's record. The same
grammar yields ``(|(...)`` (union), ``(&(...)`` (intersection), and a rewritten
``objectClass=*`` for anonymous enumeration.

The pattern targets *combinations* of metacharacters, not the metacharacters
themselves. A bare ``*`` or a lone pair of parentheses is ordinary filter
syntax - ``uid=amir*``, ``(uid=amir)`` - and blocking it would fail legitimate
searches. What cannot occur in an honestly-assembled value is an operator
smuggled across a boundary: an assertion closed and immediately re-opened
(``)(``), a wildcard terminating an assertion (``*)``), an explicit union or
intersection opening (``(|(``, ``(&(``), or a rewritten ``objectClass=*``
clause. ``re.IGNORECASE`` is applied here: ``objectClass`` is an
attribute-name case variant (``objectclass``, ``OBJECTCLASS``), and the
directory server folds case when resolving it, so the folded spelling is the
same injection rather than a different one.

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

POLICY_ID = "ldap_injection"

# Metacharacter combinations that only a smuggled filter clause produces:
#   \)\(          - an assertion closed and another opened across the boundary
#   \*\)          - a wildcard terminating an assertion
#   \(\|\(        - an explicit union filter
#   \(&\(         - an explicit intersection filter
#   \bobjectClass=\*  - a rewritten match-all objectClass clause
# The bare metacharacters (a lone ``*``, ``(``, ``)``) are deliberately absent:
# they are ordinary filter syntax and are not, on their own, injection.
# re.IGNORECASE is applied because LDAP attribute names are case-insensitive,
# so the folded spelling injects identically.
PATTERN = re.compile(r"(?:\)\(|\*\)|\(\|\(|\(&\(|\bobjectClass=\*)", re.IGNORECASE)


def ldap_injection_guard() -> Rule:
    """Build a Rule that blocks an argument carrying an LDAP injection clause.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    filter fragment. A non-dict ``args``, a dict with no str values, and a dict
    whose str values are all benign each return None (no opinion). The rule
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
                    reason="ldap_injection: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
