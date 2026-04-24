"""The opt-in @guard decorator: the explicit escape hatch for custom tools.

Automatic interception (import hooks for MCP and the model SDKs) lands in M1
and M3; this decorator is what covers bespoke in-house tools the auto-hooks
cannot see. It captures a SensorEvent, asks the engine for a verdict, and
enforces it before the wrapped function runs.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from typing import Any, Callable, Dict, Optional, Tuple

from .._runtime import get_engine
from ..context import current_principal, current_span
from ..enforce import Blocked, Decision, Verdict
from ..event import SensorEvent

_log = logging.getLogger("interlock")


def _event_for(
    func: Callable,
    args: tuple,
    kwargs: Dict[str, Any],
    principal: Optional[str],
) -> SensorEvent:
    try:
        bound = inspect.signature(func).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        arg_map = dict(bound.arguments)
    except Exception:
        arg_map = dict(kwargs)
    return SensorEvent(
        action=getattr(func, "__name__", "unknown"),
        args=arg_map,
        principal=principal or current_principal(),
        span_id=current_span(),
    )


def _emit(event: SensorEvent, decision: Decision, observed: bool = False) -> None:
    # M4 replaces this with signed receipts + an audit sink.
    _log.debug(
        "action=%s verdict=%s reason=%s span=%s observed=%s",
        event.action,
        decision.verdict.name,
        decision.reason,
        event.span_id,
        observed,
    )


def _enforce(
    decision: Decision,
    args: tuple,
    kwargs: Dict[str, Any],
    enforcement: str,
    event: SensorEvent,
) -> Tuple[tuple, Dict[str, Any]]:
    if decision.verdict == Verdict.ALLOW:
        _emit(event, decision)
        return args, kwargs
    if enforcement == "monitor":
        # Observe-only: record what would have happened, never intervene.
        _emit(event, decision, observed=True)
        return args, kwargs
    if decision.verdict == Verdict.BLOCK:
        _emit(event, decision)
        raise Blocked(decision, event.action)
    if decision.verdict == Verdict.MODIFY:
        if decision.modified_args:
            # M0 applies modifications to keyword arguments only.
            kwargs = dict(kwargs)
            kwargs.update(decision.modified_args)
        _emit(event, decision)
        return args, kwargs
    return args, kwargs


def guard(
    policy_id: Optional[str] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable:
    """Wrap a tool so every call is checked before it runs.

    enforcement="blocking" (default) raises Blocked on a deny and applies
    modifications. enforcement="monitor" only records the would-be decision.
    Works on both sync and async callables.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            event = _event_for(func, args, kwargs, principal)
            decision = get_engine().evaluate(event)
            args, kwargs = _enforce(decision, args, kwargs, enforcement, event)
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            event = _event_for(func, args, kwargs, principal)
            decision = get_engine().evaluate(event)
            args, kwargs = _enforce(decision, args, kwargs, enforcement, event)
            return await func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def monitor(
    policy_id: Optional[str] = None, principal: Optional[str] = None
) -> Callable:
    """Observe-only variant of guard: records decisions, never blocks."""
    return guard(policy_id=policy_id, enforcement="monitor", principal=principal)
