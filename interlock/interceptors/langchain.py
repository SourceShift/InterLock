"""Guard the tools a LangChain agent already has, without editing them.

An MCP agent goes through ``session.call_tool``; a LangChain agent goes through
a list of ``BaseTool`` objects it invokes by name. :func:`guard_langchain_tools`
is the LangChain counterpart of :func:`interlock.guard_mcp_session`: hand it the
tools you already give the agent and it returns drop-in replacements with the
same name, description, and argument schema, whose execution is first run
through the policy engine. Blocked before effect, arguments rewritten on MODIFY.

Both adapters funnel through the one transport-agnostic core,
:func:`interlock.enforce_tool_call`, so a rule you write once (a tool allowlist,
an egress guard) enforces identically whether the agent speaks MCP or LangChain.

LangChain is imported lazily inside the function, so importing interlock never
imports LangChain: the core stays dependency-free and this module costs nothing
until you call it.
"""
from __future__ import annotations

from typing import Any, List, Optional

from ..policy.engine import PolicyEngine
from .mcp import enforce_tool_call


def guard_langchain_tools(
    tools: List[Any],
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> List[Any]:
    """Return guarded copies of LangChain tools, same shape, checked on call.

    Each returned tool has the original's name / description / args schema, so
    the agent binds and calls it identically. On invocation the call is turned
    into a :class:`~interlock.event.SensorEvent` and run through the engine: a
    BLOCK raises :class:`~interlock.enforce.Blocked` before the real tool runs, a
    MODIFY hands the rewritten arguments to the real tool, an ALLOW is a
    pass-through. ``enforcement="monitor"`` records the decision and never
    intervenes.
    """
    from langchain_core.tools import StructuredTool  # lazy: optional dependency

    return [
        _guard_one(tool, StructuredTool, engine, enforcement, principal)
        for tool in tools
    ]


def _guard_one(
    tool: Any,
    structured_tool_cls: Any,
    engine: Optional[PolicyEngine],
    enforcement: str,
    principal: Optional[str],
) -> Any:
    name = tool.name

    def _run(**kwargs: Any) -> Any:
        safe = enforce_tool_call(
            name, kwargs, engine=engine,
            enforcement=enforcement, principal=principal,
        )
        # Delegate to the untouched original with the vetted arguments. Its own
        # sync/async paths and error handling stay exactly as the author wrote
        # them; interlock only gates the entry.
        return tool.invoke(safe)

    return structured_tool_cls.from_function(
        func=_run,
        name=name,
        description=tool.description,
        args_schema=tool.args_schema,
    )
