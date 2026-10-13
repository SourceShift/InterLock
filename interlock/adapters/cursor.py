"""Cursor: beforeShellExecution, beforeReadFile, beforeMCPExecution.

Cursor always exits 0 and answers in JSON: ``{"permission": "allow" | "deny" |
"ask", "user_message": ..., "agent_message": ...}`` (verified by agentjail).
Each event is mapped onto the same tools the policy sees for Claude Code:
shell -> ``Bash`` ``{command}``, file read -> ``Read`` ``{file_path}``, MCP ->
``mcp__<server>__<tool>`` with the arguments Cursor sends as an escaped JSON
string parsed back into an object.

Cursor cannot rewrite a call, so a MODIFY is refused; ``beforeReadFile`` cannot
ask, so an ESCALATE on a read is refused; and Cursor has no post-tool hook, so
tool output is not checked.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from ..enforce import Verdict
from .base import (
    Adapter,
    HookCall,
    HookOutcome,
    Rendered,
    call_events,
    derive_call_id,
    find_command,
    merge_command_hooks,
    normalize_args,
    read_json,
    remove_command_hooks,
    write_json,
)

EVENTS: Dict[str, Optional[str]] = {
    "beforeShellExecution": None,
    "beforeMCPExecution": None,
    "beforeReadFile": None,
}


class CursorAdapter(Adapter):
    name = "cursor"
    title = "Cursor"

    def parse(self, payload: Dict[str, Any]) -> HookCall:
        event = str(payload.get("hook_event_name", ""))
        session = payload.get("conversation_id")
        roots = payload.get("workspace_roots") if isinstance(payload.get("workspace_roots"), list) else []
        cwd = payload.get("cwd") or (roots[0] if roots else None)
        tool, tool_input = "", {}  # type: str, Dict[str, Any]
        can_ask = True
        if event == "beforeShellExecution":
            tool, tool_input = "Bash", {"command": str(payload.get("command", ""))}
        elif event == "beforeReadFile":
            tool, tool_input = "Read", {"file_path": str(payload.get("file_path", ""))}
            can_ask = False
        elif event == "beforeMCPExecution":
            tool = mcp_tool_name(payload)
            raw = payload.get("tool_input")
            if isinstance(raw, str):
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = {"raw": raw}
                tool_input = parsed if isinstance(parsed, dict) else {"raw": parsed}
            elif isinstance(raw, dict):
                tool_input = raw
        call = HookCall(agent=self.name, kind="pre" if tool else "ignore", event_name=event,
                        tool_name=tool, tool_input=normalize_args(tool_input, cwd),
                        session_id=session, cwd=cwd, can_ask=can_ask, can_rewrite=False,
                        native=payload)
        call.call_id = derive_call_id(payload.get("generation_id"), session, tool, tool_input)
        if tool:
            call.events = call_events(self.name, tool, tool_input, session_id=session,
                                      call_id=call.call_id, cwd=cwd)
        return call

    def render(self, call: HookCall, outcome: HookOutcome) -> Rendered:
        if outcome.verdict == Verdict.ALLOW:
            body: Dict[str, Any] = {"permission": "allow"}
            if outcome.observed:
                body["user_message"] = "interlock monitor: would have refused - {}".format(outcome.reason)
            return json.dumps(body), "", 0
        if outcome.verdict == Verdict.ESCALATE:
            return json.dumps({"permission": "ask", "user_message": outcome.message}), "", 0
        return json.dumps({"permission": "deny", "user_message": outcome.message,
                           "agent_message": outcome.message}), "", 0

    def render_error(self, call: Optional[HookCall], message: str, *, fail_open: bool) -> Rendered:
        if fail_open:
            return json.dumps({"permission": "allow",
                               "user_message": "⚠ interlock is NOT enforcing: {}".format(message)}), "", 0
        text = "interlock could not decide ({}); denied fail-closed".format(message)
        return json.dumps({"permission": "deny", "user_message": text, "agent_message": text}), "", 0

    # --- installation -------------------------------------------------------
    def settings_path(self) -> str:
        return os.path.join(os.path.expanduser("~"), ".cursor", "hooks.json")

    def install(self, command: str, settings: Optional[str] = None) -> Tuple[str, str]:
        path = settings or self.settings_path()
        data = read_json(path)
        data["version"] = data.get("version", 1)
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
        data["hooks"] = merge_command_hooks(hooks, EVENTS, command, with_type=False)
        # Cursor entries are flat {"command": ...}, not nested {"hooks": [...]}.
        for event in EVENTS:
            data["hooks"][event] = [
                (e["hooks"][0] if isinstance(e, dict) and "hooks" in e and len(e["hooks"]) == 1
                 and set(e) == {"hooks"} else e)
                for e in data["hooks"][event]
            ]
        return path, write_json(path, data)

    def uninstall(self, settings: Optional[str] = None) -> Tuple[str, Optional[str]]:
        path = settings or self.settings_path()
        if not os.path.exists(path):
            return path, None
        data = read_json(path)
        if isinstance(data.get("hooks"), dict):
            data["hooks"] = remove_command_hooks(data["hooks"])
        return path, write_json(path, data)

    def installed_command(self, settings: Optional[str] = None) -> Optional[str]:
        try:
            return find_command(read_json(settings or self.settings_path()).get("hooks"))
        except (OSError, ValueError):
            return None


def mcp_tool_name(payload: Dict[str, Any]) -> str:
    """``mcp__<server>__<tool>`` from Cursor's three MCP payload shapes."""
    name = str(payload.get("tool_name") or "")
    if name.startswith("mcp__"):
        return name
    if "/" in name:
        server, _, tool = name.partition("/")
        return "mcp__{}__{}".format(_component(server), _component(tool))
    command = str(payload.get("command") or "")
    server = ""
    if re.match(r"^[A-Za-z0-9_.-]+$", command):
        server = command
    elif payload.get("url"):
        server = urlparse(str(payload["url"])).hostname or ""
    return "mcp__{}__{}".format(_component(server or "unknown"), _component(name or "unknown"))


def _component(value: str) -> str:
    return value.replace("__", "_") or "unknown"
