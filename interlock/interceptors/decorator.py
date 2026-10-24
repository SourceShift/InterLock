"""The opt-in @guard decorator: the explicit escape hatch for custom tools.

Automatic interception (import hooks for MCP and the model SDKs) lands in M1
and M3; this decorator is what covers bespoke in-house tools the auto-hooks
cannot see. It captures a SensorEvent, asks the engine for a verdict, and
enforces it before the wrapped function runs.
"""
from __future__ import annotations

import asyncio
import dataclasses
import functools
import inspect
import logging
import shlex
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .._runtime import get_engine
from ..context import current_parent_principal, current_principal, current_span
from ..credentials import get_store, substitute_call
from ..enforce import Decision, Verdict
from ..event import SensorEvent, new_call_id
from ..receipt import emit_receipt
from ._settle import record_failure, settle
from .mcp import _enforce_result

_log = logging.getLogger("interlock")

# What each guarded callable was wrapped with, keyed "module.qualname". Read by
# interlock.posture so attest() can say "these tools only observe".
_MODES: Dict[str, str] = {}


def register_mode(name: str, enforcement: str) -> None:
    """Record a wrapper's enforcement mode for :func:`interlock.posture.attest`."""
    _MODES[name] = enforcement


def registered_modes() -> Dict[str, str]:
    """Every guarded callable seen so far and its enforcement mode."""
    return dict(_MODES)


def _exposed_arguments(
    sig: inspect.Signature, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """Shape a bound call so rules can see every argument by its caller name.

    ``arguments`` is a fresh dict of the bound arguments; any mapping nested in
    it is copied here, so a rule that edits ``event.args`` cannot reach the
    caller's mapping or the call. A keyword-variadic mapping is flattened into
    the top level (a declared parameter of the same name wins) while the
    variadic parameter keeps the caller's mapping under its own key. A variadic
    positional tuple made only of strings is exposed as one shell-joined
    command; anything else stays the original sequence. The call itself is
    untouched - this is only what a rule sees.
    """
    for param in sig.parameters.values():
        name = param.name
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            entries = arguments.get(name)
            if not isinstance(entries, dict):
                continue
            entries = dict(entries)
            # Keep the variadic key, but never the caller's mapping object.
            arguments[name] = entries
            for key, value in entries.items():
                arguments.setdefault(key, value)
        elif param.kind is inspect.Parameter.VAR_POSITIONAL:
            value = arguments.get(name)
            if (
                isinstance(value, (tuple, list))
                and value
                and all(isinstance(item, str) for item in value)
            ):
                arguments[name] = shlex.join(value)
    return arguments


def _event_for(
    func: Callable,
    args: tuple,
    kwargs: Dict[str, Any],
    principal: Optional[str],
) -> SensorEvent:
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        arg_map = _exposed_arguments(sig, dict(bound.arguments))
    except Exception:
        arg_map = dict(kwargs)
    return SensorEvent(
        action=getattr(func, "__name__", "unknown"),
        args=arg_map,
        principal=principal or current_principal(),
        span_id=current_span(),
        parent_principal=current_parent_principal(),
        call_id=new_call_id(),
    )


def _emit(event: SensorEvent, decision: Decision, observed: bool = False) -> None:
    _log.debug(
        "action=%s verdict=%s reason=%s span=%s observed=%s attributed_to=%s",
        event.action,
        decision.verdict.name,
        decision.reason,
        event.span_id,
        observed,
        decision.attributed_to,
    )
    # M4: the decision also becomes a chained receipt in the audit sink, when
    # one is installed; with no sink this writes nothing. A monitor-mode
    # decision that would have intervened is marked observed, so the record
    # does not read as enforcement.
    emit_receipt(event, decision, observed=observed)


def _labelled(decision: Decision, policy_id: Optional[str]) -> Decision:
    """Give a decision that names no policy the guard's own ``policy_id``."""
    if policy_id and decision.verdict != Verdict.ALLOW and not decision.policy_id:
        return dataclasses.replace(decision, policy_id=policy_id)
    return decision


def _apply_modified_args(
    func: Callable,
    args: tuple,
    kwargs: Dict[str, Any],
    modified: Dict[str, Any],
) -> Tuple[tuple, Dict[str, Any]]:
    """Merge a MODIFY rewrite into the call, in the slot each argument came from.

    A rewrite names arguments, but the caller may have passed them positionally:
    merging into kwargs alone would hand the function the same argument twice
    (and cannot reach a positional-only parameter at all). Binding against the
    signature puts each rewritten value back where it belongs. A name the
    signature does not declare goes into ``**kwargs`` when the function takes
    one, and is otherwise passed as a keyword, exactly as before.
    """
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        # No signature, or a call that does not bind: keep the keyword merge.
        merged = dict(kwargs)
        merged.update(modified)
        return args, merged

    var_keyword = next(
        (p.name for p in sig.parameters.values() if p.kind is p.VAR_KEYWORD), None
    )
    undeclared: Dict[str, Any] = {}
    for name, value in modified.items():
        param = sig.parameters.get(name)
        if param is not None and param.kind is inspect.Parameter.VAR_KEYWORD:
            # A rewrite naming the keyword-variadic parameter itself must stay
            # a mapping; merge it so the caller's other entries survive.
            if isinstance(value, dict):
                bound.arguments[name] = {
                    **bound.arguments.get(name, {}), **value,
                }
        elif param is not None and param.kind is inspect.Parameter.VAR_POSITIONAL:
            # A positional-variadic rewrite has no safe slot: a string would be
            # spread character by character. Leave the call untouched (see the
            # guard docstring); only a tuple can be applied.
            if isinstance(value, (tuple, list)):
                bound.arguments[name] = tuple(value)
        elif param is not None:
            bound.arguments[name] = value
        elif var_keyword is not None:
            bound.arguments[var_keyword] = {
                **bound.arguments.get(var_keyword, {}), name: value,
            }
        else:
            undeclared[name] = value
    return bound.args, {**bound.kwargs, **undeclared}


def _enforce(
    func: Callable,
    decision: Decision,
    args: tuple,
    kwargs: Dict[str, Any],
    enforcement: str,
    event: SensorEvent,
    engine: Any = None,
    elapsed_us: Optional[int] = None,
) -> Tuple[tuple, Dict[str, Any]]:
    outcome = settle(
        event, decision, engine=engine if engine is not None else get_engine(),
        enforcement=enforcement, elapsed_us=elapsed_us,
    )
    if outcome.verdict == Verdict.MODIFY and outcome.modified_args:
        args, kwargs = _apply_modified_args(func, args, kwargs, outcome.modified_args)
    if get_store() is not None:
        # Placeholders become secrets only now, after the decision is final.
        packed = substitute_call(event, [list(args), dict(kwargs)], enforcement=enforcement)
        args, kwargs = tuple(packed[0]), packed[1]
    return args, kwargs


def _decide(func: Callable, args: tuple, kwargs: Dict[str, Any],
            principal: Optional[str], policy_id: Optional[str]):
    event = _event_for(func, args, kwargs, principal)
    engine = get_engine()
    started = time.perf_counter()
    decision = _labelled(engine.evaluate(event), policy_id)
    elapsed_us = int((time.perf_counter() - started) * 1_000_000)
    return event, engine, decision, elapsed_us


def guard(
    policy_id: Optional[str] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> Callable:
    """Wrap a tool so every call is checked before it runs.

    enforcement="blocking" (default) raises Blocked on a deny and applies
    modifications. enforcement="monitor" only records the would-be decision.

    policy_id labels every decision on this tool that names no policy of its
    own, in logs, ``Blocked`` and receipts. A rule's own policy_id always wins.
    Works on both sync and async callables.

    The return value is also checked on the way back: result-phase rules see
    it as a phase="result" event, and may rewrite it (MODIFY) or withhold it
    (Blocked - the tool already ran, but the caller never receives the
    payload).

    An ESCALATE runs the tool only if the installed approver approves this
    exact call (see :mod:`interlock.approval`); otherwise it raises
    :class:`NotApproved`, a :class:`Blocked`. Both receipts of one call share a
    ``call_id``, and a tool that raises after being allowed leaves a
    ``phase="outcome"`` receipt.

    Rules see the call's arguments under the names the caller used: declared
    parameters by name, each ``**kwargs`` entry flattened to the top level (the
    variadic parameter keeps the caller's mapping under its own name), and a
    ``*args`` tuple of strings as one shell-joined command. Only a string-only
    variadic positional tuple is joined; anything else stays the original
    sequence. The event's argument map is a copy, so a rule that edits it
    cannot change the call. The wrapped callable always receives exactly what
    the caller passed. Rewriting the positional-variadic parameter itself with
    ``modified_args`` is not supported.
    """

    def decorator(func: Callable) -> Callable:
        register_mode(
            "{}.{}".format(getattr(func, "__module__", "?"),
                           getattr(func, "__qualname__", repr(func))),
            enforcement,
        )

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            event, engine, decision, elapsed = _decide(func, args, kwargs, principal, policy_id)
            args, kwargs = _enforce(func, decision, args, kwargs, enforcement, event,
                                    engine, elapsed)
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                record_failure(event, exc, engine=engine)
                raise
            return _enforce_result(
                event.action, result, None, enforcement, principal, policy_id,
                call_id=event.call_id,
            )

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            event, engine, decision, elapsed = _decide(func, args, kwargs, principal, policy_id)
            args, kwargs = _enforce(func, decision, args, kwargs, enforcement, event,
                                    engine, elapsed)
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                record_failure(event, exc, engine=engine)
                raise
            return _enforce_result(
                event.action, result, None, enforcement, principal, policy_id,
                call_id=event.call_id,
            )

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def monitor(
    policy_id: Optional[str] = None, principal: Optional[str] = None
) -> Callable:
    """Observe-only variant of guard: records decisions, never blocks."""
    return guard(policy_id=policy_id, enforcement="monitor", principal=principal)
