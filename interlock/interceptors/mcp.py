"""M1 keystone: intercept MCP tool calls in-process, block before effect.

An agent that talks to MCP servers makes every tool call through an MCP client
session: ``session.call_tool(name, arguments)``. :func:`guard_mcp_session` wraps
that one method so each outbound call is turned into a :class:`SensorEvent`, run
through the policy engine, and blocked or modified BEFORE it reaches the server.
No gateway, no proxy, no per-tool decorator. This is what makes interlock a
runtime guard rather than an opt-in helper: it sees the action the agent
actually takes, at the point the action happens.

It is dependency-free on purpose. It duck-types on ``.call_tool`` and never
imports the MCP SDK, so it wraps any client exposing that method and is testable
with a fake session. The real ``mcp`` package drops in unchanged.

:func:`enforce_tool_call` is the transport-agnostic core: give it a tool name and
an arguments dict and it returns the arguments to actually use (rewritten by a
MODIFY verdict) or raises :class:`Blocked`. A LangChain / model-SDK adapter in a
later milestone funnels through the same function.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable, Dict, Optional

from .._runtime import get_engine
from ..context import current_parent_principal, current_principal, current_span
from ..enforce import Blocked, Verdict
from ..event import SensorEvent
from ..policy.engine import PolicyEngine

_log = logging.getLogger("interlock")


def enforce_tool_call(
    action: str,
    arguments: Optional[Dict[str, Any]],
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Dict[str, Any]:
    """Decide on one tool call and enforce the verdict before it runs.

    Returns the arguments to actually use: unchanged on ALLOW, rewritten on
    MODIFY (``modified_args`` merged in). Raises :class:`Blocked` on BLOCK under
    the default ``enforcement="blocking"``. Under ``enforcement="monitor"`` it
    records the would-be decision and never intervenes.
    """
    args: Dict[str, Any] = dict(arguments or {})
    event = SensorEvent(
        action=action,
        args=args,
        principal=principal or current_principal(),
        span_id=current_span(),
        parent_principal=current_parent_principal(),
    )
    decision = (engine or get_engine()).evaluate(event)

    if decision.verdict == Verdict.ALLOW or enforcement == "monitor":
        _log.debug(
            "mcp action=%s verdict=%s observed=%s attributed_to=%s",
            action, decision.verdict.name, enforcement == "monitor",
            decision.attributed_to,
        )
        return args
    if decision.verdict == Verdict.BLOCK:
        _log.debug(
            "mcp action=%s BLOCK reason=%s attributed_to=%s",
            action, decision.reason, decision.attributed_to,
        )
        raise Blocked(decision, action)
    if decision.verdict == Verdict.MODIFY and decision.modified_args:
        args.update(decision.modified_args)
    return args


def enforce_tool_result(
    action: str,
    result: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Any:
    """Decide on one tool result and enforce the verdict before it is returned.

    Transport-agnostic core of the result path, the twin of
    :func:`enforce_tool_call`. The result payload is observed as a
    ``phase="result"`` SensorEvent: a dict result is carried as itself, any
    other shape rides under the ``"result"`` key.

    Returns the value the caller actually receives: the original result on
    ALLOW, ``decision.modified_result`` on MODIFY (the whole return value is
    replaced - ``modified_args`` rewrites the request, not the response).
    Under ``enforcement="monitor"`` the would-be decision is recorded and the
    original result passes through untouched.

    BLOCK on the result path does NOT un-run the tool: the call already
    happened and its side effects stand. It raises :class:`Blocked` in place
    of delivering the payload, so the caller sees the policy refusal, never
    what the tool said.
    """
    payload: Dict[str, Any] = dict(result) if isinstance(result, dict) else {"result": result}
    event = SensorEvent(
        action=action,
        args=payload,
        principal=principal or current_principal(),
        span_id=current_span(),
        parent_principal=current_parent_principal(),
        phase="result",
    )
    decision = (engine or get_engine()).evaluate(event)

    if decision.verdict == Verdict.ALLOW or enforcement == "monitor":
        _log.debug(
            "mcp result action=%s verdict=%s observed=%s attributed_to=%s",
            action, decision.verdict.name, enforcement == "monitor",
            decision.attributed_to,
        )
        return result
    if decision.verdict == Verdict.BLOCK:
        _log.debug(
            "mcp result action=%s BLOCK reason=%s attributed_to=%s",
            action, decision.reason, decision.attributed_to,
        )
        raise Blocked(decision, action)
    if decision.verdict == Verdict.MODIFY and decision.modified_result is not None:
        return decision.modified_result
    return result


def guard_mcp_session(
    session: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Any:
    """Wrap an MCP client session so every ``call_tool`` is guarded in-process.

    Call once on a freshly created session. Works whether ``call_tool`` is sync
    or async. Returns the same session for convenience::

        session = guard_mcp_session(await make_client_session())
        await session.call_tool("write_file", {"path": "/etc/passwd"})  # Blocked

    ``engine`` defaults to the process engine set by :func:`interlock.install`.
    """
    original: Callable[..., Any] = session.call_tool

    @functools.wraps(original)
    async def async_wrapper(name: str, arguments: Optional[Dict[str, Any]] = None,
                            *rest: Any, **kw: Any) -> Any:
        safe = enforce_tool_call(
            name, arguments, engine=engine,
            enforcement=enforcement, principal=principal,
        )
        out = await original(name, safe, *rest, **kw)
        return enforce_tool_result(
            name, out, engine=engine,
            enforcement=enforcement, principal=principal,
        )

    @functools.wraps(original)
    def sync_wrapper(name: str, arguments: Optional[Dict[str, Any]] = None,
                     *rest: Any, **kw: Any) -> Any:
        safe = enforce_tool_call(
            name, arguments, engine=engine,
            enforcement=enforcement, principal=principal,
        )
        out = original(name, safe, *rest, **kw)
        return enforce_tool_result(
            name, out, engine=engine,
            enforcement=enforcement, principal=principal,
        )

    session.call_tool = (
        async_wrapper if asyncio.iscoroutinefunction(original) else sync_wrapper
    )
    return session
