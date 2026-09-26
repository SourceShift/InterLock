"""The event a sensor produces for every intercepted action."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SensorEvent:
    """One observed action, as the guard sees it before the effect happens.

    action:    the tool / function / MCP-call name.
    args:      the call arguments the policy is allowed to inspect. On a
               result-phase event this carries the result payload instead
               (a dict result as itself, any other shape under "result").
    principal: who is acting (agent id, user id), if known.
    span_id:   run identity, so every event is attributable to one agent run.
    ts:        wall-clock time the event was captured.
    """

    action: str
    args: Dict[str, Any] = field(default_factory=dict)
    principal: Optional[str] = None
    span_id: Optional[str] = None
    ts: float = field(default_factory=time.time)
    parent_principal: Optional[str] = None  # audit trail: who spawned this principal
    # Which side of the call this event describes: "call" (the default, the
    # arguments being sent) or "result" (the payload coming back). Defaulting
    # to the call side keeps every event constructed today meaning what it
    # meant - including call-shaped events whose action name says
    # "tool_result".
    phase: str = "call"
