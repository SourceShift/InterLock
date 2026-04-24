"""interlock: in-process guardrails for AI agents.

Hook an agent's tool / MCP / model calls inside its own process, and block or
modify a bad action before it runs. M0 ships the opt-in @guard decorator and a
Python-rule policy engine; automatic import-hook interception (MCP, model SDKs)
and a native fast-path land in later milestones.
"""
from __future__ import annotations

from typing import List, Optional

from ._runtime import get_engine, set_engine
from .context import current_principal, current_span, new_span, set_principal, span
from .enforce import Blocked, Decision, Verdict
from .event import SensorEvent
from .interceptors.decorator import guard, monitor
from .interceptors.langchain import guard_langchain_tools
from .interceptors.mcp import enforce_tool_call, guard_mcp_session
from .policy.engine import PolicyEngine, Rule, deny_tool, deny_when

__version__ = "0.0.1"

__all__ = [
    "install",
    "guard",
    "monitor",
    "guard_mcp_session",
    "enforce_tool_call",
    "guard_langchain_tools",
    "PolicyEngine",
    "Rule",
    "deny_tool",
    "deny_when",
    "Decision",
    "Verdict",
    "Blocked",
    "SensorEvent",
    "span",
    "new_span",
    "current_span",
    "current_principal",
    "set_principal",
    "set_engine",
    "get_engine",
    "__version__",
]


def install(
    engine: Optional[PolicyEngine] = None,
    rules: Optional[List[Rule]] = None,
) -> PolicyEngine:
    """Wire the guard runtime and return the active engine.

    Pass rules to build an engine from scratch, or pass your own engine.
    Later milestones also turn on the automatic import/MCP/LLM hooks here.
    """
    if engine is None:
        engine = PolicyEngine(rules=rules)
    elif rules:
        for rule in rules:
            engine.add_rule(rule)
    set_engine(engine)
    return engine
