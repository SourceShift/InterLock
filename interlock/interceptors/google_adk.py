"""Guard a Google ADK agent's tools, without importing Google ADK.

A Google ADK agent runs a tool by calling the tool object's ``run_async``
entrypoint with the arguments the model produced (``google.adk.tools.BaseTool.
run_async``). That call is the seam this guards::

    from interlock.interceptors.google_adk import guard_tool_loop

    dispatch = guard_tool_loop(run_tool)          # run_tool(name, args) -> result
    result = await dispatch("search", {"query": "..."})

``tool`` may be the ``(name, args) -> result`` dispatcher your own glue exposes,
or the ADK tool object itself - it is recognized by duck-typing on ``run_async``
/ ``run`` and never by importing ADK. Either way the returned callable is
invoked as ``(name, args)`` (await it when the tool is async) and every call
funnels through the one transport-agnostic core, so the rules guarding your MCP
and LangChain calls guard these too. A BLOCK raises :class:`interlock.Blocked`
before the tool runs; a MODIFY rewrites the arguments; the result is checked on
the way back.

Google ADK is never imported here, so ``import interlock`` stays dependency-free.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..policy.engine import PolicyEngine
from ._framework import guard_runner, module_available

#: Name used in the mode registry and in doctor's ``framework.<name>`` check.
FRAMEWORK = "google_adk"
#: The package ``interlock doctor`` probes for this surface (a dotted name whose
#: top-level ``google`` package may be absent, which the probe handles).
MODULE = "google.adk"
#: One line naming the real public entrypoint this adapter wraps, for doctor.
SURFACE = "a Google ADK tool's run entrypoint (google.adk.tools.BaseTool.run_async)"


def framework_available() -> bool:
    """Whether ``google.adk`` is importable here. Read-only."""
    return module_available(MODULE)


def guard_tool_loop(
    tool: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable[..., Any]:
    """Guard a tool: return a ``(name, args)`` callable that enforces.

    ``tool`` is the ``(name, args) -> result`` callable your glue exposes, or an
    ADK tool object exposing ``run_async`` / ``run`` (its ``name`` is used for the
    mode registry and the policy's ``action``). The returned callable keeps the
    ``(name, args)`` shape and is itself async when the tool is: ALLOW returns
    the tool's value, BLOCK raises :class:`~interlock.enforce.Blocked` before the
    tool runs, MODIFY calls the tool with the rewritten arguments, and the result
    is checked on the way back.

    ``engine`` defaults to the process engine set by :func:`interlock.install`,
    resolved per call. ``enforcement="monitor"`` records without intervening.
    """
    return guard_runner(
        tool, site=FRAMEWORK, engine=engine,
        enforcement=enforcement, principal=principal,
    )
