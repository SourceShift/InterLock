"""Guard a LiteLLM tool loop, without importing LiteLLM.

LiteLLM gives any provider the OpenAI tool-calling shape: ``litellm.completion
(..., tools=[...])`` returns a response whose ``message.tool_calls`` your loop
decodes and dispatches to the functions you registered. That dispatcher -
``(name, args) -> result`` - is the tool runner this guards::

    from interlock.interceptors.litellm import guard_tool_loop

    dispatch = guard_tool_loop(run_tool)          # run_tool(name, args) -> result
    ...
    for call in response.choices[0].message.tool_calls:
        dispatch(call.function.name, json.loads(call.function.arguments))

It funnels through the one transport-agnostic core, so the rules that guard your
MCP and LangChain calls guard these too. A BLOCK raises
:class:`interlock.Blocked` before the tool runs; a MODIFY rewrites the
arguments; the result is checked on the way back.

LiteLLM is never imported here, so ``import interlock`` stays dependency-free.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..policy.engine import PolicyEngine
from ._framework import guard_runner, module_available

#: Name used in the mode registry and in doctor's ``framework.<name>`` check.
FRAMEWORK = "litellm"
#: The package ``interlock doctor`` probes for this surface.
MODULE = "litellm"
#: One line naming the real public entrypoint this adapter wraps, for doctor.
SURFACE = ("the LiteLLM completion tool loop "
           "(litellm.completion -> message.tool_calls -> your dispatcher)")


def framework_available() -> bool:
    """Whether the ``litellm`` package is importable here. Read-only."""
    return module_available(MODULE)


def guard_tool_loop(
    tool: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable[..., Any]:
    """Guard a tool loop: return a ``(name, args)`` dispatcher that enforces.

    ``tool`` is the ``(name, args) -> result`` callable your loop already calls,
    or a native tool object exposing ``run`` / ``run_async``. The returned
    callable keeps that ``(name, args)`` shape: ALLOW returns the tool's value,
    BLOCK raises :class:`~interlock.enforce.Blocked` before the tool runs, MODIFY
    calls the tool with the rewritten arguments, and the result is checked on the
    way back.

    ``engine`` defaults to the process engine set by :func:`interlock.install`,
    resolved per call. ``enforcement="monitor"`` records without intervening.
    """
    return guard_runner(
        tool, site=FRAMEWORK, engine=engine,
        enforcement=enforcement, principal=principal,
    )
