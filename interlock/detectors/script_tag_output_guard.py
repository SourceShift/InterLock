"""HTML script-tag / inline-handler output guard (stored XSS).

A regex argument Rule. Generated output that is later rendered as HTML can carry
a stored-XSS payload: a ``<script>`` tag, an inline JS event handler
(``onerror=`` / ``onload=`` / ``onclick=``), or a ``javascript:`` URL scheme.
This rule scans every top-level *string* arg value for those markers and blocks
the action before the tainted output reaches a renderer.

Only top-level string values are inspected: non-str values (None, int, nested
dicts/lists) are skipped rather than stringified, so structural data cannot
produce a spurious match and odd input never raises. With nothing matching, the
rule stays silent (returns None), leaving the engine's default-allow path
untouched for benign traffic.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "script_tag_output"

# Script tags, inline JS event handlers, and javascript: URLs. The inline ``(?is)``
# group carries the case-insensitivity (``i``) and dot-all (``s``) flags, so no
# extra flags are passed to ``re.compile`` -- case is attacker-controlled and the
# marker family is what defines the payload, not its spelling.
PATTERN = re.compile(
    r"(?is)<script\b[^>]*>|</script>|\bon(?:error|load|click)\s*=|javascript:"
)


def script_tag_output_guard() -> Rule:
    """Build a Rule that blocks HTML script tags / inline JS in output args.

    Scans each top-level string arg value; the first match wins and names the
    offending arg in the reason. Returns None when no string value matches or
    when args is not a mapping.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if PATTERN.search(value):
                return Decision.block(
                    reason="script_tag_output: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )
        return None

    return rule
