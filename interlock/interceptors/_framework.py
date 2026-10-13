"""The one shape every framework sensor adapter is built from.

An MCP agent goes through ``session.call_tool`` and a LangChain agent through
``BaseTool.invoke``; an agent driven by a model SDK or an agent framework - the
OpenAI SDK tool loop, LiteLLM, CrewAI, Google ADK - goes through a *tool
runner*: the function the application writes to execute whatever tool the model
asked for. That runner is the seam this package guards.

Each adapter module (:mod:`interlock.interceptors.openai` and friends) is a
thin, framework-named façade over :func:`guard_runner`, which funnels every call
through the same transport-agnostic core
(:func:`interlock.interceptors.mcp.enforce_tool_call` /
:func:`enforce_tool_result`). A rule you write once enforces identically whether
the agent speaks MCP, LangChain, or a raw model loop.

Nothing here imports a framework. A plain ``(name, args) -> result`` runner needs
no SDK at all - which is what keeps ``import interlock`` dependency-free - and a
native tool object is recognized by duck-typing, never by importing its package.
"""
from __future__ import annotations

import asyncio
import functools
import importlib.util
import types
from typing import Any, Callable, Dict, Mapping, Optional

from ..event import new_call_id
from ..policy.engine import PolicyEngine
from .mcp import enforce_tool_call, enforce_tool_result

#: Attributes a framework's native tool object exposes to run itself, in the
#: order we prefer them. ``run_async`` first: a tool that offers both is the one
#: an async agent reaches for.
_RUN_ATTRS = ("run_async", "run", "_run", "invoke")

#: Types whose metadata :func:`functools.update_wrapper` can copy safely. A
#: callable *instance* is skipped: copying its ``__dict__`` would leak the
#: runner's own state (recorded calls, fixtures) onto the guarded function.
_WRAPPABLE = (types.FunctionType, types.MethodType, types.BuiltinFunctionType)


def module_available(module: str) -> bool:
    """Whether ``module`` can be imported here. Read-only; never imports it.

    ``find_spec`` on a dotted name whose top-level package is absent raises
    ``ModuleNotFoundError`` rather than returning ``None``, so both are caught.
    A parent package that is itself broken surfaces as ``ValueError`` from
    ``__spec__ is None``; that is "not usable", not a crash.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _as_args(arguments: Any) -> Dict[str, Any]:
    """The arguments a policy sees for a call whose payload may not be a dict.

    A mapping is carried as itself; a bare value (a string, a list, nothing at
    all) rides under ``"input"``, mirroring the JS ``guardToolMap`` - a tool that
    took no arguments is not suspicious, and the model's value is never dropped
    from the policy's view.
    """
    if arguments is None:
        return {}
    if isinstance(arguments, Mapping):
        return dict(arguments)
    return {"input": arguments}


def _copy_meta(wrapper: Any, wrapped: Any) -> None:
    if isinstance(wrapped, _WRAPPABLE):
        functools.update_wrapper(wrapper, wrapped)


def _is_async_callable(obj: Any) -> bool:
    """Whether calling ``obj`` yields a coroutine.

    ``asyncio.iscoroutinefunction`` is False for a callable *instance* whose
    ``__call__`` is ``async def``: the instance is not itself a coroutine
    function, its ``__call__`` is. Routing such a runner through the sync path
    would call it, take the bare coroutine object as the tool's *result*, and
    hand that to the result phase - so a result-side rule never sees what the
    tool actually returned and every call passes unchecked. Unwrap the instance
    to its ``__call__`` so both shapes dispatch to the async path.
    """
    if asyncio.iscoroutinefunction(obj):
        return True
    call = getattr(obj, "__call__", None)
    return call is not None and asyncio.iscoroutinefunction(call)


def guard_runner(
    runner: Any,
    *,
    site: str,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable[..., Any]:
    """Wrap a tool runner so every call is decided before it runs.

    ``runner`` is either a ``(name, args) -> result`` callable - the app-written
    dispatcher every model-SDK and framework loop bottoms out in - or a native
    tool object exposing ``run_async`` / ``run`` / ``_run`` / ``invoke``. Either
    way the returned callable is invoked as ``(name, args)``:

    * the arguments are run through :func:`enforce_tool_call` first, so a BLOCK
      raises :class:`~interlock.enforce.Blocked` BEFORE the tool runs and a
      MODIFY hands the tool the rewritten arguments;
    * the tool's result is then run through :func:`enforce_tool_result` on the
      same ``call_id``, so a result-phase rule can redact or withhold it.

    A target that is neither callable nor a recognizable tool object is refused
    with :class:`TypeError` - wrapping it would silently pass every call, the
    exact failure this package exists to prevent.

    The runner's own sync/async nature is preserved: an async runner yields an
    async guarded callable. ``enforcement="monitor"`` records the would-be
    decision and never intervenes. ``site`` names the framework in the mode
    registry and in a refusal's message.
    """
    resolved = runner if callable(runner) else _native_runner(runner, site)
    key = (getattr(resolved, "__name__", None)
           or getattr(runner, "name", None)
           or site)
    from .decorator import register_mode  # local: decorator imports mcp
    register_mode("{}:{}".format(site, key), enforcement)

    def decide(name: str, arguments: Any, call_id: str) -> Dict[str, Any]:
        return enforce_tool_call(
            name, _as_args(arguments), engine=engine,
            enforcement=enforcement, principal=principal, call_id=call_id,
        )

    def finish(name: str, result: Any, call_id: str) -> Any:
        return enforce_tool_result(
            name, result, engine=engine,
            enforcement=enforcement, principal=principal, call_id=call_id,
        )

    if _is_async_callable(resolved):

        async def async_guarded(name: str, arguments: Any = None) -> Any:
            call_id = new_call_id()
            safe = decide(name, arguments, call_id)
            return finish(name, await resolved(name, safe), call_id)

        _copy_meta(async_guarded, resolved)
        return async_guarded

    def sync_guarded(name: str, arguments: Any = None) -> Any:
        call_id = new_call_id()
        safe = decide(name, arguments, call_id)
        return finish(name, resolved(name, safe), call_id)

    _copy_meta(sync_guarded, resolved)
    return sync_guarded


def _native_runner(tool: Any, site: str) -> Callable[..., Any]:
    """Adapt a framework's native tool object to a ``(name, args)`` runner.

    Duck-typed on :data:`_RUN_ATTRS`, so no framework SDK is imported to
    recognize one; the tool carries its own name. Args arrive as a mapping and
    are spread into the tool method the way the framework itself would call it.
    """
    method_name = next(
        (attr for attr in _RUN_ATTRS if callable(getattr(tool, attr, None))), None
    )
    if method_name is None:
        raise TypeError(
            "{} adapter: cannot guard {!r}: it is neither a callable "
            "(name, args) -> result runner nor a tool exposing one of ({}). "
            "Refusing to wrap it rather than let its calls pass unchecked.".format(
                site, tool, ", ".join(_RUN_ATTRS))
        )
    method = getattr(tool, method_name)
    tool_name = str(getattr(tool, "name", None) or getattr(tool, "__name__", site))

    if _is_async_callable(method):

        async def arun(_name: str, arguments: Any = None) -> Any:
            return await method(**_as_args(arguments))

        arun.__name__ = tool_name
        return arun

    def run(_name: str, arguments: Any = None) -> Any:
        return method(**_as_args(arguments))

    run.__name__ = tool_name
    return run
