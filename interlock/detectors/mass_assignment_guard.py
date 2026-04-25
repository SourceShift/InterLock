"""Argument guard: block mass-assignment of privilege-bearing fields.

Mass assignment is a field-name attack. A tool that binds its arguments
straight onto a model / ORM object - ``User(**args)``, ``update(payload)`` -
lets a caller set fields the endpoint never intended to expose. The caller
does not need to guess a dangerous *value*; the danger is the field name.
Smuggling ``{"is_admin": "true"}`` or ``{"role": "superuser"}`` into an update
payload escalates privileges even though the strings look ordinary, so this
rule matches on the field name, which is where the capability lives.

The pattern recognises the common spellings of a privilege grant across
frameworks: ``is_admin`` / ``is_superuser`` / ``is_staff`` (Django's flags),
``role``, ``permissions``, and ``account_type``. The ``\\b`` boundaries stop
``role`` from matching inside ``controller`` and keep ``is_admin`` from firing
on ``is_administrator``.

The field name is a *key* of ``args``; a caller-written payload may also carry
the same name inside a string value (a JSON body or query fragment), so string
values are scanned as well. Non-str values, nested containers, and non-dict
``args`` are skipped rather than stringified - a detector must never raise on
odd input. The first match blocks the call naming the offending argument; no
match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mass_assignment"

# Privilege-bearing field names in a write / update payload. The inline (?i)
# is deliberate: REST and query params spell these in mixed case (`isAdmin`,
# `IS_STAFF`), so case-insensitive matching widens genuine coverage here and
# no extra re.IGNORECASE flag is needed. \b keeps `role` out of `controller`.
PATTERN = re.compile(
    r"(?i)\b(?:is_admin|role|is_superuser|permissions|account_type|is_staff)\b"
)


def mass_assignment_guard() -> Rule:
    """Build a Rule that blocks a payload carrying a privilege field.

    Each top-level entry of a dict ``args`` is tested: first its key name,
    then a str value, against :data:`PATTERN`. On the first match the rule
    returns a BLOCK naming the offending argument so the caller can tell which
    field was smuggled in. A non-dict ``args``, an entry whose key is not a
    str, and a payload with no matching name or str value each return None
    (no opinion). The rule never raises.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for name, value in args.items():
            if isinstance(name, str) and PATTERN.search(name):
                return Decision.block(
                    reason="mass_assignment: {}".format(name),
                    policy_id=POLICY_ID,
                )
            if isinstance(value, str) and PATTERN.search(value):
                return Decision.block(
                    reason="mass_assignment: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
