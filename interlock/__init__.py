"""interlock: in-process guardrails for AI agents.

Hook an agent's tool / MCP / model calls inside its own process, and block or
modify a bad action before it runs. The seams are explicit - ``@guard``, the
``guard_*_tool_loop`` adapters, ``guard_mcp_session`` - and ``attach()`` is the
one opt-in import hook: it guards MCP client sessions at the class, so a
session is covered from birth without per-session wiring. ``uncovered()``
reports the surfaces that still need an explicit adapter.
"""
from __future__ import annotations

from typing import Any, List, Optional

from . import brace
from . import sink
from ._runtime import get_engine, set_engine
from .approval import (
    Approval,
    ApprovalRequest,
    approve_for,
    approve_for_session,
    approve_once,
    set_approver,
)
from .attach import attach, check_seam, detach, inspect_surfaces
from .attach import monitor as attach_monitor
from .attach import uncovered
from .brace import Sandbox, SandboxProfile, compile_profile
from .context import (
    current_parent_principal,
    current_principal,
    current_span,
    new_span,
    set_principal,
    span,
)
from .enforce import Blocked, Decision, NotApproved, Verdict
from .event import SensorEvent, new_call_id
from .interceptors import (
    guard_adk_tool_loop,
    guard_crewai_tool_loop,
    guard_litellm_tool_loop,
)
from .interceptors.decorator import guard, monitor
from .interceptors.langchain import guard_langchain_tools
from .interceptors.mcp import enforce_tool_call, enforce_tool_result, guard_mcp_session
from .interceptors.openai import guard_tool_loop
from .policy.engine import PolicyEngine, Rule, deny_tool, deny_when
from .receipt import set_sink

__version__ = "0.0.1"

__all__ = [
    "install",
    "guard",
    "monitor",
    "guard_mcp_session",
    "attach",
    "attach_monitor",
    "check_seam",
    "detach",
    "inspect_surfaces",
    "uncovered",
    "enforce_tool_call",
    "enforce_tool_result",
    "guard_langchain_tools",
    "guard_tool_loop",
    "guard_litellm_tool_loop",
    "guard_crewai_tool_loop",
    "guard_adk_tool_loop",
    "PolicyEngine",
    "Rule",
    "deny_tool",
    "deny_when",
    "Decision",
    "Verdict",
    "Blocked",
    "NotApproved",
    "SensorEvent",
    "new_call_id",
    "set_approver",
    "Approval",
    "ApprovalRequest",
    "approve_once",
    "approve_for_session",
    "approve_for",
    "brace",
    "sink",
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
    approver: Optional[Any] = None,
) -> PolicyEngine:
    """Wire the guard runtime and return the active engine.

    Pass rules to build an engine from scratch, or pass your own engine.
    Import-time interception is separate and opt-in: call :func:`attach` to
    guard MCP client sessions at the class.

    ``sink`` optionally installs a receipt sink (e.g. ``interlock.sink.FileSink``),
    the explicit opt-in that turns decision receipts on; without one no
    receipt is ever written.

    ``approver`` installs the callable that decides ESCALATE verdicts (see
    :mod:`interlock.approval`). Without one, every escalation is blocked.
    """
    if engine is None:
        engine = PolicyEngine(rules=rules)
    elif rules:
        if not hasattr(engine, "add_rule"):
            raise TypeError(
                "{} takes no extra rules: pass rules=[...] only with a "
                "PolicyEngine. For a ScopedEngine, bind them at the root scope "
                "through a template instead.".format(type(engine).__name__)
            )
        for rule in rules:
            engine.add_rule(rule)
    if sink is not None:
        set_sink(sink)
    if approver is not None:
        set_approver(approver)
    set_engine(engine)
    return engine
