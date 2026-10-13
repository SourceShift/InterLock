"""Result guard: withhold tool results larger than a limit.

A tool that returns a whole table, a huge log or a crafted blob can flood an
agent's context window - pushing its instructions out, or smuggling an
injection past attention - and costs money per token. This rule measures the
result (as JSON, the way it would be serialized to a model) and withholds it
when it exceeds ``max_bytes``.
"""
from __future__ import annotations

import json
from typing import Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "result_size"


def result_size_guard(max_bytes: int = 256 * 1024, *,
                      actions: Optional[Iterable[str]] = None) -> Rule:
    """Build a result-phase Rule blocking results over ``max_bytes``."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "result":
            return None
        if action_set is not None and event.action not in action_set:
            return None
        payload = getattr(event, "args", None)
        try:
            size = len(json.dumps(payload, default=str).encode("utf-8"))
        except Exception:
            size = len(repr(payload).encode("utf-8"))
        if size > max_bytes:
            return Decision.block("result_size: {} bytes is over the {}-byte limit".format(
                size, max_bytes), POLICY_ID, attributed_to="result")
        return None

    rule.phase = "result"  # type: ignore[attr-defined]
    return rule
