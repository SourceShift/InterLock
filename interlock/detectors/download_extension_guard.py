"""Argument guard: block download/write targets that carry an executable extension.

A download or write tool is handed a destination and trusts it. The file
*extension* is the part of that destination that decides what happens when the
bytes land: ``report.pdf`` is data, ``payload.sh`` is a script the shell will run,
``installer.msi`` is a package the OS will execute. The extension is carried in
the argument, so it is visible before the tool runs - which is exactly where
this rule sits, on the argument detector, ahead of any network or filesystem
effect.

Matching on the raw argument text rather than on a parsed URL is deliberate. A
URL parser can be tricked (a fragment, a query string, an unusual scheme), and
the resolved filename is not known until the tool does the work. The rule instead
looks for a literal ``.<ext>`` at a boundary the download tool would treat as the
end of the filename - either the end of the string or an ``?``/``#`` that starts a
query or fragment. An embedded extension such as ``.shell`` is therefore *not*
matched, because the ``sh`` is followed by more name characters rather than a
boundary.

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

POLICY_ID = "download_extension"

# Executable/script file extensions a download or write target must not carry.
# ``(?i)`` makes the match case-insensitive (``PAYLOAD.SH`` is still a shell
# script) and is equivalent to passing re.IGNORECASE, so no flag is also needed.
# The trailing ``(?:$|[?#])`` anchors the extension to the end of the filename,
# so it fires on ``.../payload.sh`` and ``.../payload.sh?token=1`` but not on an
# ordinary name that merely contains the letters (``.../payload.shell``).
PATTERN = re.compile(
    r"(?i)\.(?:sh|exe|bat|cmd|ps1|scr|jar|msi|dll|dylib|so)(?:$|[?#])"
)


def download_extension_guard() -> Rule:
    """Build a Rule that blocks a download/write argument naming an executable.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    dangerous target. A non-dict ``args``, a dict with no str values, and a dict
    whose str values are all clean each return None (no opinion). The rule never
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
                    reason="download_extension: {}".format(name),
                    policy_id=POLICY_ID,
                )

        return None

    return rule
