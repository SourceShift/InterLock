"""The opt-in @guard decorator: the explicit escape hatch for custom tools.

Automatic interception covers MCP sessions (an import hook on
``ClientSession.call_tool``), the model SDKs and agent frameworks (adapters
over the same ``enforce_tool_call`` core), and the Node client's patched
surfaces. This decorator is what covers bespoke in-house tools none of those
can see. It captures a SensorEvent, asks the engine for a verdict, and
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
from ..event import SensorEvent, new_call_id, strip_trust_labels
from ..flow import get_tracker
from ..receipt import emit_receipt
from ._settle import record_failure, settle
from .mcp import _enforce_result

_log = logging.getLogger("interlock")

#: View-only prefix that keeps a declared parameter reachable when a ``**kwargs``
#: entry shadows it. A rewrite naming ``__declared__<name>`` addresses the
#: declared slot; the key is reserved in the exposed view and never passed on.
_DECLARED_PREFIX = "__declared__"

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

    ``arguments`` is a fresh dict of the bound arguments; the top level and a
    keyword-variadic mapping are copied here, so a rule that replaces an entry
    cannot reach the caller's mapping or the call. A container nested *inside* a
    value is still the caller's object and is not copied.

    A keyword-variadic mapping is flattened into the top level while the
    variadic parameter keeps the caller's mapping under its own key. When a
    flattened key collides with a declared parameter (as ``def upload(path, /,
    **extra)`` allows), the exposed name carries the variadic value - what the
    callee's ``extra["path"]`` reads - and the declared value stays addressable
    as ``__declared__<name>``, a reserved view-only key. A variadic positional
    tuple made only of strings is exposed as one shell-joined command; anything
    else stays the original sequence. The call itself is untouched - this is
    only what a rule sees.
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
                if key == name:
                    continue
                if key.startswith(_DECLARED_PREFIX) and key not in sig.parameters:
                    # The alias namespace is view-only: a caller cannot claim
                    # it. The entry stays reachable in the variadic mapping.
                    continue
                declared = sig.parameters.get(key)
                if (
                    declared is not None
                    and declared.kind
                    not in (inspect.Parameter.VAR_KEYWORD,
                            inspect.Parameter.VAR_POSITIONAL)
                ):
                    # A real declared parameter of this name is shadowed. Show
                    # the variadic value (the fail-closed choice: the callee
                    # may read it) and keep the declared one reachable.
                    alias = _DECLARED_PREFIX + key
                    if key in arguments and alias not in sig.parameters:
                        arguments[alias] = arguments[key]
                    arguments[key] = value
                else:
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
    span_id = current_span()
    args_view = strip_trust_labels(arg_map)
    return SensorEvent(
        action=getattr(func, "__name__", "unknown"),
        # The caller's arguments may be model-produced; a reserved trust key in
        # them is stripped from the event only. The wrapped function still
        # receives exactly what the caller passed.
        args=args_view,
        principal=principal or current_principal(),
        span_id=span_id,
        parent_principal=current_parent_principal(),
        call_id=new_call_id(),
        origins=get_tracker().origins_for(args_view, span_id=span_id),
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
) -> Tuple[tuple, Dict[str, Any], Optional[str]]:
    """Merge a MODIFY rewrite into the call, in the slot each argument came from.

    A rewrite names arguments, but the caller may have passed them positionally:
    merging into kwargs alone would hand the function the same argument twice
    (and cannot reach a positional-only parameter at all). Binding against the
    signature puts each rewritten value back where it belongs. A name the
    signature does not declare goes into ``**kwargs`` when the function takes
    one, and is otherwise passed as a keyword, exactly as before.

    Returns ``(args, kwargs, refusal)``. ``refusal`` is the name of an argument
    whose rewrite cannot be applied to this call - a ``dict`` aimed at the
    positional-variadic parameter (that is the shape ``**kwargs`` uses), a
    non-mapping aimed at ``**kwargs``, or a shell string that does not split -
    so the caller can refuse rather than report a rewrite it did not make.

    A positional-variadic rewrite is applied in the shape the rule was shown: a
    string is split back with :func:`shlex.split` (the inverse of the
    shell-joined view), a list/tuple becomes the argv, and any other scalar
    becomes a one-item argv. When a ``**kwargs`` entry collides with a declared
    parameter, a rewrite of that name lands in the variadic mapping (where the
    exposed value came from) and a rewrite of ``__declared__<name>`` lands in
    the declared parameter.
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        # No signature: keep the keyword merge. Nothing here can be shape-checked.
        merged = dict(kwargs)
        merged.update(modified)
        return args, merged, None

    var_keyword = next(
        (p.name for p in sig.parameters.values() if p.kind is p.VAR_KEYWORD), None
    )
    # A *args parameter cannot be passed by keyword in a real call: a keyword
    # of that name is either captured by **kwargs (and must stay there) or the
    # call itself is invalid. Never reroute such a keyword into the *args slot.
    try:
        bound = sig.bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        # A call that does not bind: keep the keyword merge, as before.
        merged = dict(kwargs)
        merged.update(modified)
        return args, merged, None

    variadic: Optional[Dict[str, Any]] = None
    if var_keyword is not None:
        current = bound.arguments.get(var_keyword)
        if isinstance(current, dict):
            variadic = dict(current)
    # Names a **kwargs entry shadowed: rewriting the name must reach the
    # variadic mapping the exposed value came from, not the declared slot.
    collisions = set()
    for key in variadic or {}:
        param = sig.parameters.get(key)
        if param is not None and param.kind not in (
            inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL,
        ):
            collisions.add(key)

    undeclared: Dict[str, Any] = {}
    for name, value in modified.items():
        if name.startswith(_DECLARED_PREFIX) and sig.parameters.get(name) is None:
            target = name[len(_DECLARED_PREFIX):]
            if target in collisions:
                bound.arguments[target] = value
                continue
        param = sig.parameters.get(name)
        if param is not None and param.kind is inspect.Parameter.VAR_KEYWORD:
            # A rewrite naming the keyword-variadic parameter itself must stay
            # a mapping; merge it so the caller's other entries survive.
            if not isinstance(value, dict):
                return args, kwargs, name
            variadic = {**(variadic or {}), **value}
            bound.arguments[name] = variadic
        elif param is not None and param.kind is inspect.Parameter.VAR_POSITIONAL:
            if isinstance(value, dict):
                return args, kwargs, name
            if isinstance(value, str):
                try:
                    replacement = tuple(shlex.split(value))
                except ValueError:
                    return args, kwargs, name
            elif isinstance(value, (tuple, list)):
                replacement = tuple(value)
            else:
                replacement = (value,)
            bound.arguments[name] = replacement
        elif param is not None:
            if name in collisions and var_keyword is not None:
                variadic = {**(variadic or {}), name: value}
                bound.arguments[var_keyword] = variadic
            else:
                bound.arguments[name] = value
        elif var_keyword is not None:
            variadic = {**(variadic or {}), name: value}
            bound.arguments[var_keyword] = variadic
        else:
            undeclared[name] = value
    if variadic is not None and var_keyword is not None:
        bound.arguments[var_keyword] = variadic
    return bound.args, {**bound.kwargs, **undeclared}, None


def _refuse_rewrite(decision: Decision, argument: str) -> Decision:
    """Turn a MODIFY whose rewrite cannot be applied into a fail-closed BLOCK.

    The argument name is kept as ``attributed_to`` (unless the rule named a
    different argument) and the decision's ``policy_id`` is preserved, so the
    refusal reads as the same policy decision rather than a new one.
    """
    return Decision.block(
        "modified_args rewrite for {!r} cannot be applied to this call; "
        "denied fail-closed".format(argument),
        policy_id=decision.policy_id,
        attributed_to=decision.attributed_to or argument,
    )


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
    # Decide applicability before settle: settle writes the receipt, so a
    # MODIFY it emits must be one this call can actually apply. An escalation
    # may carry rewrites too (an approved call runs them), so check those now.
    applied: Optional[Tuple[tuple, Dict[str, Any], Optional[str]]] = None
    if (
        decision.verdict in (Verdict.MODIFY, Verdict.ESCALATE)
        and decision.modified_args
    ):
        applied = _apply_modified_args(func, args, kwargs, decision.modified_args)
        if applied[2] is not None:
            decision = _refuse_rewrite(decision, applied[2])
            applied = None
    outcome = settle(
        event, decision, engine=engine if engine is not None else get_engine(),
        enforcement=enforcement, elapsed_us=elapsed_us,
    )
    if outcome.verdict == Verdict.MODIFY and outcome.modified_args:
        if applied is None:
            applied = _apply_modified_args(func, args, kwargs, outcome.modified_args)
        args, kwargs, refusal = applied
        if refusal is not None:
            # Only reachable if settle itself introduced a rewrite it did not
            # see pre-settle. Refuse it with its own receipt rather than run
            # unmodified under a MODIFY receipt.
            settle(
                event, _refuse_rewrite(outcome, refusal),
                engine=engine if engine is not None else get_engine(),
                enforcement=enforcement, elapsed_us=elapsed_us,
            )
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
    sequence. When a ``**kwargs`` entry collides with a declared parameter, the
    flattened name shows the variadic value and the declared value stays under
    the reserved key ``__declared__<name>``.

    The event's argument map is shallow-copied: its top level and a variadic
    keyword mapping are new dicts, so replacing an entry cannot change the
    call, but a container nested inside a value is still the caller's object.

    A MODIFY applies ``modified_args`` in the slot the exposed value came from:
    a string rewrite of the shell-joined ``*args`` is split back with
    ``shlex.split``, a list/tuple becomes the argv, and any other scalar becomes
    a one-item argv. A rewrite that cannot be applied (a ``dict`` aimed at
    ``*args``, or a shell string that does not split) is refused as a block
    rather than run unmodified. The wrapped callable otherwise receives exactly
    what the caller passed.
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
