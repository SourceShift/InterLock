"""Guard a CrewAI agent's tools, without importing CrewAI.

A CrewAI agent runs a tool by calling the tool object's ``run`` entrypoint with
the arguments the model produced (``crewai.tools.BaseTool.run``). That call is
the seam this guards::

    from interlock.interceptors.crewai import guard_tool_loop

    dispatch = guard_tool_loop(run_tool)          # run_tool(name, args) -> result
    result = dispatch("search", {"query": "..."})

``tool`` may be the ``(name, args) -> result`` dispatcher your own glue exposes,
or the CrewAI tool object itself - it is recognized by duck-typing on ``run`` /
``_run`` and never by importing CrewAI. Either way the returned callable is
invoked as ``(name, args)`` and every call funnels through the one
transport-agnostic core, so the rules guarding your MCP and LangChain calls
guard these too. A BLOCK raises :class:`interlock.Blocked` before the tool runs;
a MODIFY rewrites the arguments; the result is checked on the way back.

CrewAI is never imported here, so ``import interlock`` stays dependency-free.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..policy.engine import PolicyEngine
from ._framework import guard_runner, module_available

#: Name used in the mode registry and in doctor's ``framework.<name>`` check.
FRAMEWORK = "crewai"
#: The package ``interlock doctor`` probes for this surface.
MODULE = "crewai"
#: One line naming the real public entrypoint this adapter wraps, for doctor.
SURFACE = "a CrewAI tool's run entrypoint (crewai.tools.BaseTool.run)"


def framework_available() -> bool:
    """Whether the ``crewai`` package is importable here. Read-only."""
    return module_available(MODULE)


def guard_tool_loop(
    tool: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable[..., Any]:
    """Guard a tool: return a ``(name, args)`` callable that enforces.

    ``tool`` is the ``(name, args) -> result`` callable your glue exposes, or a
    CrewAI tool object exposing ``run`` / ``_run`` (its ``name`` is used for the
    mode registry and the policy's ``action``). The returned callable keeps the
    ``(name, args)`` shape: ALLOW returns the tool's value, BLOCK raises
    :class:`~interlock.enforce.Blocked` before the tool runs, MODIFY calls the
    tool with the rewritten arguments, and the result is checked on the way back.

    ``engine`` defaults to the process engine set by :func:`interlock.install`,
    resolved per call. ``enforcement="monitor"`` records without intervening.
    """
    return guard_runner(
        tool, site=FRAMEWORK, engine=engine,
        enforcement=enforcement, principal=principal,
    )
