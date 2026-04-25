"""Argument guard: block file-tool arguments that escape their directory.

A file tool is handed a path and trusts it. Path traversal is the class of
attack that turns that trust into a capability: ``../`` walks up out of the
intended working directory, and a sensitive root (``/etc/``) is an absolute
destination the tool will happily read. The traversal is carried in the
argument, so it is visible before the tool runs - which is exactly where this
rule sits, on the argument detector, ahead of any filesystem effect.

Matching on the raw text rather than on a resolved path is deliberate. The
resolved path is not available until the tool does the work, and a resolver
that follows symlinks or normalises ``%2e%2e`` can be tricked into missing the
very input the attacker sent. The rule instead recognises the common
encodings of the escape as literal fragments: ``../``, Windows ``..\\``, the
percent-encoded ``%2e%2e``, the ``/etc/`` root, ``~/.`` (home-directory
config), and ``\\windows\\``. Each is a substring a traversal must contain and
an ordinary relative filename (``reports/2026/q1.csv``) will not.

Only top-level string values of a dict ``args`` are scanned. An int, None,
or nested container is skipped rather than stringified, and a non-dict
``args`` yields no opinion - a detector must never raise on odd input. The
first matching value blocks the call; no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "path_traversal"

# Directory-traversal and sensitive-root path fragments. Three encodings of the
# same escape are covered (POSIX ``../``, Windows ``..\\``, percent-encoded
# ``%2e%2e``) plus the sensitive roots ``/etc/``, ``~/.`` and ``\\windows\\``.
# re.IGNORECASE is deliberately not applied: it would widen the match to
# spellings such as ``/ETC/`` and so change which inputs are caught rather than
# merely how they are written.
PATTERN = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e[/\\]|/etc/|~/\.|\\windows\\)"
)


def path_traversal_guard() -> Rule:
    """Build a Rule that blocks a file-tool argument carrying a traversal path.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    escape. A non-dict ``args``, a dict with no str values, and a dict whose
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
                    reason="path_traversal: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
