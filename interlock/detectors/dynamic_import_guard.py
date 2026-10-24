"""Argument guard: block a string argument reaching a blocked module via dynamic import.

Ordinary ``import`` statements name their target in source, which is why the
eval/exec guard can afford to look only for call primitives. Dynamic import is
the way around that: ``importlib.import_module``, ``__import__`` and the legacy
``imp.load_`` take the module name as a *runtime value*, so a payload such as
``importlib.import_module('o' + 's')`` never spells ``os`` anywhere static
analysis could find it. The string is the argument, visible before the call
runs, which is where this rule sits: on the argument detector, ahead of any
effect.

``re.search`` is used rather than ``fullmatch`` because the machinery is
embedded in surrounding source - a multi-line script that mentions
``importlib.import_module`` anywhere is enough. ``re.IGNORECASE`` is deliberately
not applied: the three primitives are spelled in lower case, so folding case
would only widen the match to names such as ``IMPORTLIB.IMPORT_MODULE`` that are
not these attributes, changing which inputs are caught rather than merely how
they are written.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first matching
value blocks the call; no match returns None (no opinion).

Identifiers are matched after NFKC normalization because that is how Python
reads them: a fullwidth spelling of ``importlib.import_module`` is the same
attribute path to the interpreter, so it must be to this guard too. The raw
text is scanned first, so the reason and attribution of an ordinary ASCII
match do not change.
"""
from __future__ import annotations

import re
from typing import Optional

from .._unicode import nfkc
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "dynamic_import"

# Dynamic-import machinery: the ``importlib`` attribute, the ``__import__``
# builtin, and the removed ``imp.load_*`` helpers. The ``\b`` anchor keeps a
# match on a bare name start - ``importlib.import_module`` matches, a longer
# identifier such as ``myimp.load_source`` does not. The underscore run is
# ``_+`` rather than one literal ``_`` so a spelling of the attribute with an
# extra underscore (still the same call shape, and what a fullwidth spelling
# can look like once normalized) is caught too.
PATTERN = re.compile(r"\b(?:importlib\.import_+module|__import__\s*\(|imp\.load_)")


def dynamic_import_guard() -> Rule:
    """Build a Rule that blocks an argument reaching a module by dynamic import.

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
                reason="dynamic_import: {}".format(name),
                policy_id=POLICY_ID,
                attributed_to=name,
            )

        return None

    return rule
