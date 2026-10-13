"""Hook adapters that put interlock in front of coding agents.

``interlock install-hook --for claude-code|codex|cursor`` registers
``interlock hook --agent <name>`` in the agent's hook settings; every tool call
the agent makes is then decided by your interlock policy (by default the
``builtin:coding-agent`` pack). See :mod:`interlock.adapters.base` for what
each agent can and cannot express.
"""
from typing import Dict, Type

from .base import Adapter, HookCall, HookOutcome, run_hook
from .claude_code import ClaudeCodeAdapter
from .codex import CodexAdapter
from .cursor import CursorAdapter

ADAPTERS: Dict[str, Type[Adapter]] = {
    "claude-code": ClaudeCodeAdapter,
    "codex": CodexAdapter,
    "cursor": CursorAdapter,
}


def get_adapter(name: str) -> Adapter:
    try:
        return ADAPTERS[name]()
    except KeyError:
        raise ValueError("unknown agent {!r}; choose one of {}".format(
            name, ", ".join(sorted(ADAPTERS))))


__all__ = ["ADAPTERS", "Adapter", "HookCall", "HookOutcome", "get_adapter", "run_hook"]
