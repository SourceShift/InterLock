"""The event a sensor produces for every intercepted action."""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

#: Argument keys reserved for facts a trust detector relies on: which server a
#: call is for (``__origin__``), the tool schema the server declared
#: (``__schema__``), its attestation (``__attestation__``) and its listing
#: (``__tools__``). Arguments are model-influenced, so an integration must never
#: read one of these keys out of them: every model-facing boundary strips them
#: (:func:`strip_trust_labels`) and an integration that knows the fact sets it
#: on :attr:`SensorEvent.labels` instead.
TRUST_LABELS = frozenset({"__origin__", "__schema__", "__attestation__", "__tools__"})


def strip_trust_labels(args: Any) -> Dict[str, Any]:
    """A shallow copy of ``args`` without any :data:`TRUST_LABELS` key.

    A non-mapping yields ``{}``, so a caller can strip unconditionally and
    still hand a dict to the event. The input is never mutated: the keys a
    wrapped tool or an MCP server receives are the caller's own.
    """
    if not isinstance(args, dict):
        return {}
    return {key: value for key, value in args.items() if key not in TRUST_LABELS}


def trust_label(event: "SensorEvent", key: str) -> Any:
    """Read a reserved label from the trusted channel, else the args fallback.

    The trusted channel (:attr:`SensorEvent.labels`, set by interlock's own
    integration code) wins. Reading ``args`` next is the documented fallback
    for an event an integration built by hand - the boundary helpers strip
    those keys from anything a model supplied, so it cannot reach here.
    """
    labels = event.labels
    if isinstance(labels, dict) and key in labels:
        return labels[key]
    args = event.args
    if isinstance(args, dict):
        return args.get(key)
    return None


def trust_label_source(event: "SensorEvent", key: str) -> Optional[str]:
    """Where :func:`trust_label` read ``key`` from: ``"labels"``, ``"args"``, or None.

    Detectors use this to decide ``attributed_to``: an argument-sourced label
    names the argument, while a trusted-channel label names none the model
    could have written.
    """
    labels = event.labels
    if isinstance(labels, dict) and key in labels:
        return "labels"
    args = event.args
    if isinstance(args, dict) and key in args:
        return "args"
    return None


@dataclass
class SensorEvent:
    """One observed action, as the guard sees it before the effect happens.

    action:    the tool / function / MCP-call name.
    args:      the call arguments the policy is allowed to inspect. On a
               result-phase event this carries the result payload instead
               (a dict result as itself, any other shape under "result").
    principal: who is acting (agent id, user id), if known.
    span_id:   run identity, so every event is attributable to one agent run.
    ts:        wall-clock time the event was captured.
    """

    action: str
    args: Dict[str, Any] = field(default_factory=dict)
    principal: Optional[str] = None
    span_id: Optional[str] = None
    ts: float = field(default_factory=time.time)
    parent_principal: Optional[str] = None  # audit trail: who spawned this principal
    # Which side of the call this event describes: "call" (the default, the
    # arguments being sent) or "result" (the payload coming back). Defaulting
    # to the call side keeps every event constructed today meaning what it
    # meant - including call-shaped events whose action name says
    # "tool_result".
    phase: str = "call"
    # One guarded call's identity, shared by its call-side and result-side
    # events (and by an agent hook's PreToolUse/PostToolUse pair, R18), so the
    # receipts of one action can be joined. None when the caller did not mint
    # one; see new_call_id().
    call_id: Optional[str] = None
    # The directory the action runs in, when the sensor knows it (an agent
    # hook's session cwd), so a relative path in a shell command resolves
    # where the command will run. None: the guard's own directory.
    cwd: Optional[str] = None
    # Trust facts about the action - which server it is for, the schema it
    # declared, its attestation and listing - under the reserved
    # :data:`TRUST_LABELS` keys. Set ONLY by interlock's own integration code
    # (``guard_mcp_session`` and friends); never decoded from a wire frame,
    # copied from a model's arguments, or taken from an agent hook payload.
    # A model can shape ``args``; it cannot reach this mapping.
    labels: Dict[str, Any] = field(default_factory=dict)
    # Where each argument's value entered, as argument path -> origin labels
    # ("tool:fetch_url", "principal:acme/agent42"). Populated at the
    # interception boundary (the tracker in :mod:`interlock.flow`), or supplied
    # by an integration that knows a value's source. A flow rule constrains
    # source -> sink over this map; a flat rule can ignore it.
    origins: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Accept the convenient shapes an integration reaches for - one label,
        # a list, a set, a generator - and store immutable tuples. Provenance
        # is metadata: a malformed map is dropped, never raised, so a boundary
        # cannot fail open because a source label was misspelled.
        self.origins = _normalise_origins(self.origins)


def _normalise_origins(origins: Any) -> Dict[str, Tuple[str, ...]]:
    if not isinstance(origins, Mapping):
        return {}
    cleaned: Dict[str, Tuple[str, ...]] = {}
    for key, value in origins.items():
        if not isinstance(key, str) or not key:
            continue
        if isinstance(value, str):
            value = (value,)
        try:
            items: Iterable[Any] = iter(value)  # type: ignore[arg-type]
        except TypeError:
            continue
        labels = []
        for item in items:
            if len(labels) >= 32:
                break
            if isinstance(item, str) and item.strip():
                label = item.strip()
                if label not in labels:
                    labels.append(label)
        if labels:
            cleaned[key] = tuple(labels)
    return cleaned


def new_call_id() -> str:
    """A fresh, unguessable id for one guarded call."""
    return secrets.token_hex(8)


def result_payload(result: Any) -> Dict[str, Any]:
    """Shape a tool's return value as the ``args`` of a result-phase event.

    A dict result is carried as itself, any other value under ``"result"``. An
    MCP tool result (the official SDK's ``CallToolResult``, or the same shape as
    plain JSON) is a wrapper whose text sits in a ``content`` list, out of reach
    of rules that read top-level strings - which is every built-in result rule.
    For that shape the text items are joined into ``"result"``, so a rule sees
    what the agent will read. A bare content-block array is joined the same
    way. The top-level fields of the structured content
    (``structured_content`` or ``structuredContent``) ride alongside, never
    replacing ``"result"``, and ``is_error`` is carried when the result reports
    it.
    """
    if isinstance(result, dict):
        payload = dict(result)
        text = _mcp_text(result.get("content"))
        if text is not None and "result" not in payload:
            payload["result"] = text
        return payload
    if isinstance(result, (list, tuple)):
        # A bare content-block array (an MCP result, or a tool that returns
        # blocks directly) hides its text from top-level string rules too.
        text = _mcp_text(result)
        if text is not None:
            return {"result": text}
        return {"result": result}
    text = _mcp_text(getattr(result, "content", None))
    if text is None:
        return {"result": result}
    payload: Dict[str, Any] = {"result": text}
    # The SDK has spelled these both ways (camelCase on the wire, snake_case
    # attributes in newer releases); read whichever the object has.
    structured = _first_attr(result, "structured_content", "structuredContent")
    if isinstance(structured, dict):
        for key, value in structured.items():
            payload.setdefault(str(key), value)
    is_error = _first_attr(result, "is_error", "isError")
    if isinstance(is_error, bool):
        payload["is_error"] = is_error
    return payload


def _first_attr(obj: Any, *names: str) -> Any:
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return None


def _mcp_text(content: Any) -> Optional[str]:
    """Join the text items of an MCP ``content`` list, or None if it isn't one."""
    if not isinstance(content, (list, tuple)) or not content:
        return None
    texts = []
    for item in content:
        if isinstance(item, str):
            text = item
        elif isinstance(item, dict):
            text = item.get("text")
        else:
            text = getattr(item, "text", None)
        if isinstance(text, str):
            texts.append(text)
    return "\n".join(texts) if texts else None
