"""A minimal MCP server over stdio, with no dependencies.

MCP's stdio transport is newline-delimited JSON-RPC 2.0, so a read-only tool
server needs ``initialize``, ``tools/list``, ``tools/call`` and ``ping``, and
nothing else. interlock uses this to tell an agent how its review is doing
(``interlock reviews mcp``) without pulling in an SDK.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, IO, List, Optional

PROTOCOL_VERSION = "2025-06-18"


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]


class StdioServer:
    def __init__(self, name: str, version: str, tools: List[Tool],
                 instructions: str = "") -> None:
        self.name = name
        self.version = version
        self.tools = {t.name: t for t in tools}
        self.instructions = instructions

    def handle(self, message: Any) -> Optional[Dict[str, Any]]:
        """One JSON-RPC message in, one response out (None for notifications)."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "invalid request")
        method = message.get("method")
        msg_id = message.get("id")
        if msg_id is None:  # a notification: never answered
            return None
        params = message.get("params") or {}
        if method == "initialize":
            return _result(msg_id, {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": self.version},
                "instructions": self.instructions,
            })
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": [
                {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
                for t in self.tools.values()]})
        if method == "tools/call":
            tool = self.tools.get(params.get("name"))
            if tool is None:
                return _error(msg_id, -32602, "unknown tool {!r}".format(params.get("name")))
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return _error(msg_id, -32602, "arguments must be an object")
            try:
                payload = tool.handler(arguments)
                is_error = False
            except Exception as exc:  # report, don't crash the server
                payload = {"error": "{}: {}".format(type(exc).__name__, exc)}
                is_error = True
            return _result(msg_id, {
                "content": [{"type": "text", "text": json.dumps(payload, default=str)}],
                "structuredContent": payload,
                "isError": is_error,
            })
        return _error(msg_id, -32601, "method not found: {}".format(method))

    def serve(self, stdin: IO[str] = None, stdout: IO[str] = None) -> None:  # type: ignore[assignment]
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except ValueError:
                response: Optional[Dict[str, Any]] = _error(None, -32700, "parse error")
            else:
                response = self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


def _result(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
