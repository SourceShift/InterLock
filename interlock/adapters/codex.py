"""OpenAI Codex CLI: PreToolUse, PermissionRequest, PostToolUse, SessionStart, Stop.

Codex's hook protocol is narrower than Claude Code's (verified by agentjail
against Codex CLI 0.145-0.153):

- **PreToolUse** allows with no output and denies with exit code 2 and the
  reason on stderr. It cannot open an approval prompt - Codex continues the
  call - so an ESCALATE is refused, as is a rewrite this adapter cannot prove
  Codex applies. Both are recorded with the policy's verdict alongside.
- **PermissionRequest** fires when Codex itself is about to ask. Here a BLOCK
  answers ``deny``; anything else stays silent so Codex's own prompt decides.
  An ALLOW never answers ``allow``: the hook adds restrictions, it does not
  approve.
- **PostToolUse** cannot withhold output, so result findings are recorded as
  observed and surfaced as a ``systemMessage``.
- ``apply_patch`` is split into one event per ``*** ... File:`` target.

Codex needs ``[features] hooks = true`` in ``~/.codex/config.toml`` and asks you
to trust new hooks (``/hooks``, then ``t``) - ``interlock install-hook`` sets the
first and tells you about the second.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from typing import Any, Dict, Optional, Tuple

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

TOOL_MATCHER = "^(Bash|apply_patch|mcp__.*)$"
EVENTS: Dict[str, Optional[str]] = {
    "SessionStart": "",
    "PreToolUse": TOOL_MATCHER,
    "PermissionRequest": TOOL_MATCHER,
    "PostToolUse": TOOL_MATCHER,
    "Stop": "",
}


class CodexAdapter(Adapter):
    name = "codex"
    title = "Codex"

    def parse(self, payload: Dict[str, Any]) -> HookCall:
        event = str(payload.get("hook_event_name", ""))
        session = payload.get("session_id")
        cwd = payload.get("cwd") or None
        tool = str(payload.get("tool_name", ""))
        raw_input = payload.get("tool_input")
        tool_input = dict(raw_input) if isinstance(raw_input, dict) else {}
        command = tool_input.get("command")
        if isinstance(command, list) and all(isinstance(c, str) for c in command):
            tool_input["command"] = shlex.join(command)
        call = HookCall(agent=self.name, kind="ignore", event_name=event, tool_name=tool,
                        tool_input=normalize_args(tool_input, cwd), session_id=session,
                        cwd=cwd, can_ask=False, can_rewrite=False,
                        can_rewrite_result=False, can_block_result=False, native=payload)
        call.call_id = derive_call_id(payload.get("tool_use_id"), session, tool,
                                      raw_input if isinstance(raw_input, dict) else {})
        if event in ("PreToolUse", "PermissionRequest"):
            call.kind = "pre"
            call.can_ask = event == "PermissionRequest"
            call.events = call_events(self.name, tool, tool_input, session_id=session,
                                      call_id=call.call_id, cwd=cwd)
        elif event == "PostToolUse":
            response = payload.get("tool_response")
            status = _exit_code(response)
            if status not in (None, 0):
                call.kind = "failure"
                call.error = _text(response)
            else:
                call.kind = "post"
                call.result = response
        elif event in ("SessionStart", "Stop"):
            call.kind = "lifecycle"
        return call

    def render(self, call: HookCall, outcome: HookOutcome) -> Rendered:
        if call.kind == "post":
            if outcome.observed:
                return _out({"systemMessage": "⚠ interlock flagged this tool output (Codex "
                                              "hooks cannot withhold it): {}".format(outcome.reason)}), "", 0
            return "", "", 0
        if call.kind != "pre":
            return "", "", 0
        if call.event_name == "PermissionRequest":
            if outcome.verdict == Verdict.BLOCK:
                return _out({"hookSpecificOutput": {"hookEventName": "PermissionRequest",
                                                    "decision": {"behavior": "deny",
                                                                 "message": outcome.message}}}), "", 0
            return "", "", 0  # let Codex's own prompt decide
        if outcome.verdict == Verdict.ALLOW:
            if outcome.observed:
                return _out({"systemMessage": "interlock monitor: would have refused - {}".format(
                    outcome.reason)}), "", 0
            return "", "", 0
        return "", outcome.message + "\n", 2

    def render_lifecycle(self, call: HookCall, summary: str) -> Rendered:
        return _out({"continue": True, "systemMessage": "🔒 interlock: {}".format(summary)}), "", 0

    def render_error(self, call: Optional[HookCall], message: str, *, fail_open: bool) -> Rendered:
        if fail_open or (call is not None and call.kind != "pre"):
            return _out({"systemMessage": "⚠ interlock is NOT enforcing: {} "
                                          "(run: interlock doctor)".format(message)}), "", 0
        return "", "interlock could not decide ({}); denied fail-closed. Run `interlock doctor` " \
                   "outside the agent.\n".format(message), 2

    # --- installation -------------------------------------------------------
    def settings_path(self) -> str:
        return os.path.join(os.path.expanduser("~"), ".codex", "hooks.json")

    def config_path(self, settings: Optional[str] = None) -> str:
        return os.path.join(os.path.dirname(settings or self.settings_path()), "config.toml")

    def install(self, command: str, settings: Optional[str] = None) -> Tuple[str, str]:
        path = settings or self.settings_path()
        data = read_json(path)
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
        data["hooks"] = merge_command_hooks(hooks, EVENTS, command, timeout=30)
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

    def ensure_feature_flag(self, settings: Optional[str] = None) -> str:
        """Turn on ``[features] hooks = true`` if that is unambiguous.

        Returns ``"set"``, ``"already"`` or a sentence explaining why the file
        was left alone. Like agentjail, this refuses to edit TOML it does not
        fully understand: it only appends a missing ``[features]`` table or
        adds the key to a ``[features]`` table that lacks it.
        """
        path = self.config_path(settings)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            text = ""
        except OSError as exc:
            return "could not read {}: {}".format(path, exc)
        tables = re.findall(r"(?m)^\s*\[([^\]\n]+)\]\s*$", text)
        if "features" not in [t.strip() for t in tables]:
            if re.search(r"(?m)^\s*features\s*[.=]", text):
                return "{} defines features some other way; add hooks = true by hand".format(path)
            new = text + ("" if text.endswith("\n") or not text else "\n") + "\n[features]\nhooks = true\n"
        else:
            section = re.search(r"(?ms)^\s*\[features\]\s*$(.*?)(?=^\s*\[|\Z)", text)
            body = section.group(1) if section else ""
            setting = re.search(r"(?m)^\s*hooks\s*=\s*(\S+)", body)
            if setting:
                return "already" if setting.group(1).lower() == "true" else \
                    "{} sets hooks = {}; change it to true by hand".format(path, setting.group(1))
            assert section is not None
            insert_at = section.start(1)
            new = text[:insert_at] + "\nhooks = true" + text[insert_at:]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        return "set"


def _exit_code(response: Any) -> Optional[int]:
    if isinstance(response, dict):
        for key in ("exit_code", "exitCode", "exit_status"):
            value = response.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        meta = response.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("exit_code"), int):
            return meta["exit_code"]
    return None


def _text(response: Any) -> str:
    if isinstance(response, dict):
        return " ".join(str(response.get(k, "")) for k in ("error", "stderr", "output", "stdout"))
    return str(response or "")


def _out(body: Dict[str, Any]) -> str:
    return json.dumps(body, default=str)
