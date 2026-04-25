"""Open-redirect parameter guard.

A regex argument Rule. If an attacker can steer a ``redirect``/``next``/``url``
style parameter to an absolute off-site URL, the app becomes a launchpad for
phishing: the link looks like the trusted host, but lands on the attacker's
page (and can leak tokens in the query string). The tell is a redirect-shaped
parameter whose value is an absolute URL -- either plain (``next=https://...``,
``next=//evil``) or URL-encoded (``next=https%3a//evil``), since the value is
often decoded *after* the guard sees it.

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

POLICY_ID = "open_redirect"

# The spec's pattern is already case-insensitive via the inline ``(?i)`` group,
# so no re.IGNORECASE flag is added -- doing so would be redundant and would not
# change the intended match set. Covers plain, protocol-relative (``//``), and
# percent-encoded (``https%3a``) absolute redirect targets.
PATTERN = re.compile(
    r"(?i)(?:[?&](?:redirect|return|next|url|dest|continue)=(?:https?%3a|//|https?://))"
)


def open_redirect_guard() -> Rule:
    """Build a Rule that blocks off-site open-redirect parameters in string args.

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
                    reason="open_redirect: {}".format(name),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
