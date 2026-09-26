"""interlock: in-process guardrails for AI agents.

Hook an agent's tool / MCP / model calls inside its own process, and block or
modify a bad action before it runs. M0 ships the opt-in @guard decorator and a
Python-rule policy engine; automatic import-hook interception (MCP, model SDKs)
and a native fast-path land in later milestones.
"""
from __future__ import annotations

from typing import Any, List, Optional

from . import brace
from ._runtime import get_engine, set_engine
from .brace import Sandbox, SandboxProfile, compile_profile
from .context import (
    current_parent_principal,
    current_principal,
    current_span,
    new_span,
    set_principal,
    span,
)
from .enforce import Blocked, Decision, Verdict
from .event import SensorEvent
from .interceptors.decorator import guard, monitor
from .interceptors.langchain import guard_langchain_tools
from .interceptors.mcp import enforce_tool_call, enforce_tool_result, guard_mcp_session
from .policy.engine import PolicyEngine, Rule, deny_tool, deny_when
from .receipt import set_sink

__version__ = "0.0.1"

__all__ = [
    "install",
    "guard",
    "monitor",
    "guard_mcp_session",
    "enforce_tool_call",
    "enforce_tool_result",
    "guard_langchain_tools",
    "PolicyEngine",
    "Rule",
    "deny_tool",
    "deny_when",
    "Decision",
    "Verdict",
    "Blocked",
    "SensorEvent",
    "brace",
    "Sandbox",
    "SandboxProfile",
    "compile_profile",
    "span",
    "new_span",
    "current_span",
    "current_principal",
    "current_parent_principal",
    "set_principal",
    "set_engine",
    "get_engine",
    "__version__",
]


def install(
    engine: Optional[PolicyEngine] = None,
    rules: Optional[List[Rule]] = None,
    sink: Optional[Any] = None,
) -> PolicyEngine:
    """Wire the guard runtime and return the active engine.

    Pass rules to build an engine from scratch, or pass your own engine.
    Later milestones also turn on the automatic import/MCP/LLM hooks here.

    ``sink`` optionally installs a receipt sink (e.g. ``interlock.sink.FileSink``),
    the explicit opt-in that turns decision receipts on; without one no
    receipt is ever written.
    """
    if engine is None:
        engine = PolicyEngine(rules=rules)
    elif rules:
        for rule in rules:
            engine.add_rule(rule)
    if sink is not None:
        set_sink(sink)
    set_engine(engine)
    return engine
