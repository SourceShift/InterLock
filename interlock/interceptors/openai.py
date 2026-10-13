"""Guard an OpenAI SDK tool loop, without importing the SDK.

An agent built on the OpenAI SDK drives tools in a loop: ``client.chat.
completions.create(...)`` returns ``message.tool_calls``, your loop decodes each
call's ``function.arguments`` and dispatches it to the function you registered
under that name. That dispatcher - ``(name, args) -> result`` - is the tool
runner this guards. Hand it to :func:`guard_tool_loop` and every dispatched call
is decided before it runs::

    from interlock.interceptors.openai import guard_tool_loop

    dispatch = guard_tool_loop(run_tool)          # run_tool(name, args) -> result
    ...
    for call in response.choices[0].message.tool_calls:
        dispatch(call.function.name, json.loads(call.function.arguments))

It funnels through the one transport-agnostic core, so a rule you write once
enforces identically whether the agent speaks MCP, LangChain, or the OpenAI SDK.
A BLOCK raises :class:`interlock.Blocked` before the tool runs; a MODIFY hands
the tool the rewritten arguments; the result is checked on the way back.

The SDK is never imported here, so ``import interlock`` stays dependency-free.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..policy.engine import PolicyEngine
from ._framework import guard_runner, module_available

#: Name used in the mode registry and in doctor's ``framework.<name>`` check.
FRAMEWORK = "openai"
#: The package ``interlock doctor`` probes to decide whether to report this
#: surface as detected (covered) or uncovered.
MODULE = "openai"
#: One line naming the real public entrypoint this adapter wraps, for doctor.
SURFACE = ("the OpenAI SDK tool loop "
           "(client.chat.completions.create -> tool_calls -> your dispatcher)")


def framework_available() -> bool:
    """Whether the ``openai`` package is importable here. Read-only."""
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
    callable has the same ``(name, args)`` shape: on ALLOW it returns the tool's
    value, on BLOCK it raises :class:`~interlock.enforce.Blocked` before the tool
    runs, and on MODIFY the tool is called with the rewritten arguments. Its
    result is checked too, so an injected instruction in what the tool returned
    is caught before the model reads it.

    ``engine`` defaults to the process engine set by :func:`interlock.install`,
    resolved per call, so installing a new engine afterwards is honoured.
    ``enforcement="monitor"`` records the would-be decision without intervening.
    """
    return guard_runner(
        tool, site=FRAMEWORK, engine=engine,
        enforcement=enforcement, principal=principal,
    )
