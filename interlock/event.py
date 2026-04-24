"""The event a sensor produces for every intercepted action."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SensorEvent:
    """One observed action, as the guard sees it before the effect happens.

    action:    the tool / function / MCP-call name.
    args:      the call arguments the policy is allowed to inspect.
    principal: who is acting (agent id, user id), if known.
    span_id:   run identity, so every event is attributable to one agent run.
    ts:        wall-clock time the event was captured.
    """

    action: str
    args: Dict[str, Any] = field(default_factory=dict)
    principal: Optional[str] = None
    span_id: Optional[str] = None
    ts: float = field(default_factory=time.time)
