"""Argument guard: block code that reaches an unsafe deserialization entry point.

``pickle``, ``marshal`` and a bare ``yaml.load`` are deserializers that may
reconstruct arbitrary objects from attacker-controlled bytes - unpickling is a
well-known remote-code-execution primitive, and ``yaml.load`` without a safe
``Loader`` can build Python objects the same way. All three put the dangerous
call directly in the source text, so the payload is visible in the argument
before the code runs. This rule sits on the argument detector, ahead of any
effect.

``re.search`` is used rather than ``fullmatch`` because the call is embedded in
surrounding source: a script that deserializes anywhere is enough. The
``yaml.load`` alternative carries a negative lookahead that suppresses the match
when the same line passes an explicit ``Loader`` - the caller has opted into a
safe loader, so the call is not the unsafe form this rule targets. The other
three branches have no such escape hatch: ``pickle.loads``, ``cPickle.loads``
and ``marshal.loads`` are unsafe unconditionally.

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

POLICY_ID = "pickle_deser"

# An unsafe deserializer followed by a call. The ``yaml.load`` branch refuses to
# match when a ``Loader`` argument appears later on the line, which is the
# explicit-safe spelling. re.IGNORECASE is deliberately not applied: the module
# and function names are spelled in lower case, and case folding would widen the
# match to names such as ``Pickle.Loads`` that are not the real entry points -
# changing which inputs are caught rather than merely how they are written.
PATTERN = re.compile(
    r"(?:pickle\.loads|cPickle\.loads|marshal\.loads|yaml\.load\s*\((?!.*Loader))"
)


def pickle_deser_guard() -> Rule:
    """Build a Rule that blocks an argument calling an unsafe deserializer.

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
                    reason="pickle_deser: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
