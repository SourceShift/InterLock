"""Argument guard: block server-side template-injection (SSTI) syntax.

When a tool forwards a caller-supplied string into a template engine, the
string is not data - it is program. Jinja2, Twig, Django, and Handlebars all
evaluate interpolation inside ``{{ ... }}`` or ``{% ... %}``; JavaScript
template literals and JSP evaluate ``${ ... }``; Ruby and CoffeeScript
interpolation uses ``#{ ... }``. A value containing any of those forms is an
attempt to make the renderer execute rather than display it, and the safest
place to stop it is on the argument detector, before the string reaches the
engine.

The pattern matches the *syntax*, not a particular payload: ``{{7*7}}``,
``{{config.items()}}`` and ``{% import os %}`` are all caught by the same
four alternations, so the guard does not need to know which engine sits
downstream. A non-greedy body keeps each match scoped to one expression so
that an ordinary value which merely happens to contain a brace is not swept
up with a later one. ``re.IGNORECASE`` is deliberately not applied: it would
widen which inputs match - changing the detector's behaviour rather than just
how the spelling is written.

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

POLICY_ID = "ssti"

# Template-expression syntax across the common engines: Jinja2/Twig
# ({{ }} and {% %}), JS template literals / JSP (${ }), and Ruby /
# CoffeeScript interpolation (#{ }). re.IGNORECASE is deliberately not
# applied - it would change which inputs are caught, not merely how they are
# written.
PATTERN = re.compile(r"(?:\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\})")


def ssti_guard() -> Rule:
    """Build a Rule that blocks an argument carrying template-expression syntax.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    payload. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="ssti: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
