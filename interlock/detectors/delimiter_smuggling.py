"""Fake chat-delimiter smuggling detector (ChatML / instruction tags).

A regex argument Rule. Forged conversation delimiters such as ``<|im_start|>``,
``[INST]``, ``<<SYS>>`` and ``### instruction`` let user content impersonate a
new turn and smuggle a system/instruction block past the model's real role
boundary. This rule scans every top-level *string* arg value for those
delimiters and blocks the action before the forged turn reaches the model.

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

POLICY_ID = "delimiter_smuggling"

# Forged role/turn delimiters: ChatML tokens, Llama-2 [INST] / <<SYS>>, and
# Alpaca-style "### instruction". Matched case-insensitively because casing is
# attacker-controlled and the delimiter *family* is what defines a forge, not
# its case ("### Instruction" is in fact the canonical Alpaca spelling).
PATTERN = re.compile(
    r"(?:<\|(?:im_start|im_end|system|user|assistant)\|>"
    r"|\[/?INST\]"
    r"|<<SYS>>"
    r"|###\s*(?:system|instruction))",
    re.IGNORECASE,
)


def delimiter_smuggling() -> Rule:
    """Build a Rule that blocks forged chat-delimiter smuggling.

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
                    reason="delimiter_smuggling: {}".format(name),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
