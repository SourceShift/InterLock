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
from dataclasses import replace
from typing import Any, Callable, Dict, Mapping, Optional

from .._runtime import get_engine
from ..context import current_parent_principal, current_principal, current_span
from ..enforce import Blocked, Verdict
from ..event import SensorEvent, result_payload
from ..policy.engine import PolicyEngine
from ..receipt import emit_receipt

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
    # The event gets its own copy: a rule that edits event.args in place must not
    # change the arguments the tool is called with. Only a MODIFY verdict can.
    event = SensorEvent(
        action=action,
        args=dict(args),
        principal=principal or current_principal(),
        span_id=current_span(),
        parent_principal=current_parent_principal(),
    )
    decision = (engine or get_engine()).evaluate(event)

    if decision.verdict == Verdict.ALLOW or enforcement == "monitor":
        observed = enforcement == "monitor" and decision.verdict != Verdict.ALLOW
        _log.debug(
            "mcp action=%s verdict=%s observed=%s attributed_to=%s",
            action, decision.verdict.name, enforcement == "monitor",
            decision.attributed_to,
        )
        emit_receipt(event, decision, observed=observed)
        return args
    if decision.verdict == Verdict.BLOCK:
        _log.debug(
            "mcp action=%s BLOCK reason=%s attributed_to=%s",
            action, decision.reason, decision.attributed_to,
        )
        emit_receipt(event, decision)
        raise Blocked(decision, action)
    if decision.verdict == Verdict.MODIFY:
        # The MODIFY branch had no log site at all: the one verdict a policy
        # rewrote the call with went unrecorded. It is a receipt site now.
        # The receipt digests the arguments the caller passed, not the
        # rewritten ones.
        emit_receipt(event, decision)
        if decision.modified_args:
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
    ``phase="result"`` SensorEvent shaped by :func:`interlock.event.result_payload`:
    a dict result is carried as itself, any other shape rides under the
    ``"result"`` key, and an MCP ``CallToolResult`` has its text content joined
    into ``"result"`` so result rules can read it.

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
    return _enforce_result(action, result, engine, enforcement, principal, None)


def _enforce_result(
    action: str,
    result: Any,
    engine: Optional[PolicyEngine],
    enforcement: str,
    principal: Optional[str],
    default_policy_id: Optional[str],
) -> Any:
    """The body of :func:`enforce_tool_result`; ``default_policy_id`` labels a
    decision that names no policy (``@guard(policy_id=...)`` passes its own)."""
    event = SensorEvent(
        action=action,
        args=result_payload(result),
        principal=principal or current_principal(),
        span_id=current_span(),
        parent_principal=current_parent_principal(),
        phase="result",
    )
    decision = (engine or get_engine()).evaluate(event)
    if default_policy_id and decision.verdict != Verdict.ALLOW and not decision.policy_id:
        decision = replace(decision, policy_id=default_policy_id)

    if decision.verdict == Verdict.ALLOW or enforcement == "monitor":
        observed = enforcement == "monitor" and decision.verdict != Verdict.ALLOW
        _log.debug(
            "mcp result action=%s verdict=%s observed=%s attributed_to=%s",
            action, decision.verdict.name, enforcement == "monitor",
            decision.attributed_to,
        )
        emit_receipt(event, decision, observed=observed)
        return result
    if decision.verdict == Verdict.BLOCK:
        _log.debug(
            "mcp result action=%s BLOCK reason=%s attributed_to=%s",
            action, decision.reason, decision.attributed_to,
        )
        emit_receipt(event, decision)
        raise Blocked(decision, action)
    if decision.verdict == Verdict.MODIFY:
        # Same hole as the call side: this MODIFY branch never recorded
        # anything, and it is the verdict that rewrites what the caller gets.
        emit_receipt(event, decision)
        if decision.modified_result is not None:
            return decision.modified_result
    return result


#: Argument keys the MCP trust detectors read as facts about a call: which
#: server it is for (``__origin__``), the tool schema the server declared
#: (``__schema__``), its attestation (``__attestation__``) and listing
#: (``__tools__``). Only your own code may set them, never the model.
TRUST_LABELS = frozenset({"__origin__", "__schema__", "__attestation__", "__tools__"})


def guard_mcp_session(
    session: Any,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
    origin: Optional[str] = None,
    schemas: Optional[Mapping[str, str]] = None,
) -> Any:
    """Wrap an MCP client session so every ``call_tool`` is guarded in-process.

    Call once on a freshly created session. Works whether ``call_tool`` is sync
    or async. Returns the same session for convenience::

        session = guard_mcp_session(await make_client_session(), origin="github")
        await session.call_tool("write_file", {"path": "/etc/passwd"})  # Blocked

    ``engine`` defaults to the process engine set by :func:`interlock.install`.

    ``origin`` names the server this session talks to, and ``schemas`` maps a
    tool name to the schema string that server declared for it. They become the
    ``__origin__`` and ``__schema__`` labels the MCP trust detectors read
    (``mcp_trust_registry``, ``mcp_capability_lease``, ``mcp_tool_pinning``,
    ...). Any :data:`TRUST_LABELS` key in the arguments the caller passes is
    dropped first - those arguments usually come from the model, and a label it
    wrote would let it claim to be a trusted server. Labels are added only for
    the policy check and are never sent to the server.
    """
    original: Callable[..., Any] = session.call_tool
    schema_map: Dict[str, str] = dict(schemas or {})

    def labelled(name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        args = {k: v for k, v in (arguments or {}).items() if k not in TRUST_LABELS}
        if origin is not None:
            args["__origin__"] = origin
        if name in schema_map:
            args["__schema__"] = schema_map[name]
        return args

    def check(name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        safe = enforce_tool_call(
            name, labelled(name, arguments), engine=engine,
            enforcement=enforcement, principal=principal,
        )
        return {k: v for k, v in safe.items() if k not in TRUST_LABELS}

    @functools.wraps(original)
    async def async_wrapper(name: str, arguments: Optional[Dict[str, Any]] = None,
                            *rest: Any, **kw: Any) -> Any:
        out = await original(name, check(name, arguments), *rest, **kw)
        return enforce_tool_result(
            name, out, engine=engine,
            enforcement=enforcement, principal=principal,
        )

    @functools.wraps(original)
    def sync_wrapper(name: str, arguments: Optional[Dict[str, Any]] = None,
                     *rest: Any, **kw: Any) -> Any:
        out = original(name, check(name, arguments), *rest, **kw)
        return enforce_tool_result(
            name, out, engine=engine,
            enforcement=enforcement, principal=principal,
        )

    session.call_tool = (
        async_wrapper if asyncio.iscoroutinefunction(original) else sync_wrapper
    )
    return session
