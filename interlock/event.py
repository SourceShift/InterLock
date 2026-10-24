"""The event a sensor produces for every intercepted action."""
from __future__ import annotations

import secrets
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
    # One guarded call's identity, shared by its call-side and result-side
    # events (and by an agent hook's PreToolUse/PostToolUse pair, R18), so the
    # receipts of one action can be joined. None when the caller did not mint
    # one; see new_call_id().
    call_id: Optional[str] = None
    # The directory the action runs in, when the sensor knows it (an agent
    # hook's session cwd), so a relative path in a shell command resolves
    # where the command will run. None: the guard's own directory.
    cwd: Optional[str] = None


def new_call_id() -> str:
    """A fresh, unguessable id for one guarded call."""
    return secrets.token_hex(8)


def result_payload(result: Any) -> Dict[str, Any]:
    """Shape a tool's return value as the ``args`` of a result-phase event.

    A dict result is carried as itself, any other value under ``"result"``. An
    MCP tool result (the official SDK's ``CallToolResult``, or the same shape as
    plain JSON) is a wrapper whose text sits in a ``content`` list, out of reach
    of rules that read top-level strings - which is every built-in result rule.
    For that shape the text items are joined into ``"result"``, so a rule sees
    what the agent will read. The top-level fields of the structured content
    (``structured_content`` or ``structuredContent``) ride alongside, never
    replacing ``"result"``, and ``is_error`` is carried when the result reports
    it.
    """
    if isinstance(result, dict):
        payload = dict(result)
        text = _mcp_text(result.get("content"))
        if text is not None and "result" not in payload:
            payload["result"] = text
        return payload
    text = _mcp_text(getattr(result, "content", None))
    if text is None:
        return {"result": result}
    payload: Dict[str, Any] = {"result": text}
    # The SDK has spelled these both ways (camelCase on the wire, snake_case
    # attributes in newer releases); read whichever the object has.
    structured = _first_attr(result, "structured_content", "structuredContent")
    if isinstance(structured, dict):
        for key, value in structured.items():
            payload.setdefault(str(key), value)
    is_error = _first_attr(result, "is_error", "isError")
    if isinstance(is_error, bool):
        payload["is_error"] = is_error
    return payload


def _first_attr(obj: Any, *names: str) -> Any:
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _mcp_text(content: Any) -> Optional[str]:
    """Join the text items of an MCP ``content`` list, or None if it isn't one."""
    if not isinstance(content, (list, tuple)) or not content:
        return None
    texts = []
    for item in content:
        text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
        if isinstance(text, str):
            texts.append(text)
    return "\n".join(texts) if texts else None
