"""CRLF header/log-injection guard.

A regex argument Rule. If an attacker-controlled value reaches a raw HTTP
header, a log line, or a redirect target carrying an unescaped carriage
return / line feed, everything after it is interpreted as a new header or a
new log record. Classic payloads smuggle a header (``%0d%0aSet-Cookie:``) or
forge log entries this way.

The encoded forms (``%0d%0a``, ``%0a``, ``%0d``) matter because a value is
often URL-decoded *after* the guard sees it; the literal escaped forms
(``\\r\\n``, ``\\n\\r``) matter because a value can arrive pre-escaped as text
and be unescaped downstream. Catching them at the argument boundary blocks
before either decode step.

Only top-level string values are inspected: non-str values (None, int, nested
dicts/lists) are skipped rather than stringified, so structural data cannot
produce a spurious match and odd input never raises. With nothing matching,
the rule stays silent (returns None), leaving the engine's default-allow path
untouched for benign traffic.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "crlf_injection"

# Encoded CRLF (URL-decode path) and literal escaped CRLF (pre-escaped text
# path). Kept case-sensitive: the spec's pattern is exact, and folding case
# would broaden the match set to attacker-supplied uppercase encodes.
PATTERN = re.compile(r"(?:%0d%0a|%0a|%0d|\\r\\n|\\n\\r)")


def crlf_header_injection_guard() -> Rule:
    """Build a Rule that blocks CRLF header/log injection in string args.

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
                    reason="crlf_injection: {}".format(name),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
