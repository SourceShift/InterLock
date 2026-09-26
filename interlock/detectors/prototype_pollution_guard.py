"""Argument guard: block prototype-pollution keys smuggled in tool arguments.

Prototype pollution is a key-name attack. A tool that merges, defaults, or
deep-copies its arguments hands the attacker a way to write onto an object's
prototype chain: an argument like ``{"__proto__": {"isAdmin": true}}`` names a
property the merge will walk into, and every object that inherits from the
polluted prototype silently gains the injected field. The attack carries no
obviously malicious *value* - the danger is the key - so this rule matches on
the key text wherever it appears in a string value, which is where a
JSON-encoded body or a query fragment carries it into the tool.

Three spellings of the same capability are recognised: ``__proto__`` (the
literal magic key), ``constructor.prototype`` (the equivalent reached through
the constructor), and ``prototype[`` (indexed assignment onto a prototype).
A filter that only strips ``__proto__`` leaves the other two open, so all
three are matched.

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

POLICY_ID = "prototype_pollution"

# The three prototype-pollution keys: the literal ``__proto__`` magic key, the
# ``constructor.prototype`` route to the same chain, and ``prototype[`` for
# indexed assignment. re.IGNORECASE is deliberately not applied: JS property
# keys are case-sensitive, so ``__PROTO__`` is a different key, and the flag
# would widen which inputs are caught rather than merely how they are written.
PATTERN = re.compile(r"(?:__proto__|constructor\.prototype|prototype\[)")


def prototype_pollution_guard() -> Rule:
    """Build a Rule that blocks an argument carrying a prototype-pollution key.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    key. A non-dict ``args``, a dict with no str values, and a dict whose str
    values are all clean each return None (no opinion). The rule never raises.
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
                    reason="prototype_pollution: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
