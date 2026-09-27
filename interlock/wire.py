"""The wire protocol between an out-of-process sensor and the policy engine.

An agent running in another language (see the Node.js sensor, R13) does not get
its own rules. It gets a socket to this process, which owns the one engine. Two
frames cross it, both newline-delimited canonical JSON:

    request   {"v":1,"id":...,"event":{action,args,principal,span_id,
                                       parent_principal,phase,ts}}
    response  {"v":1,"id":...,"verdict":0|1|2,"reason":...,"policy_id":...,
               "attributed_to":...,"modified_args":...,"modified_result":...}

``verdict`` is the integer ``Verdict`` value, not the name: ``enforce.py``
already documents 0/1/2 as the engine's out-param contract for a native core, so
the wire inherits an encoding that has a reason to be stable instead of
inventing one.

Two decisions here are fail-closed choices, not style:

- **Unknown keys are refused, not ignored.** A client that misspells ``args`` as
  ``arg`` must not have its arguments silently dropped: an engine shown an event
  with no arguments finds no opinion and allows. A permissive parser turns one
  typo into an allow-all, so the parser accepts an exact key set and rejects
  anything else.
- **A rule's rewrite must be transmittable.** ``modified_args`` and
  ``modified_result`` come from a rule and can hold anything a Python object can.
  A value the codec cannot represent raises :class:`Unrepresentable` rather than
  being coerced or dropped, because a sanitizer that silently declines to
  sanitize is worse than one that refuses.
"""
from __future__ import annotations

import base64
import json
import math
from typing import Any, Dict, Tuple

from .enforce import Decision, Verdict
from .event import SensorEvent

PROTOCOL_VERSION = 1

# One frame per line, both directions. A line at or above this is refused rather
# than read: a bound the peer cannot exceed is what keeps a malformed or hostile
# client from allocating without limit.
MAX_LINE = 8 * 1024 * 1024

# The tag marking a value JSON cannot carry. Chosen to be a key no real tool
# argument uses; decode only converts a dict that is *exactly* this shape, so an
# argument dict that merely contains the key passes through untouched.
_TAG = "__interlock__"
_BYTES = "bytes"

_REQUEST_KEYS = frozenset({"v", "id", "event"})
_EVENT_KEYS = frozenset(
    {"action", "args", "principal", "span_id", "parent_principal", "phase", "ts"}
)
_RESPONSE_KEYS = frozenset(
    {
        "v",
        "id",
        "verdict",
        "reason",
        "policy_id",
        "attributed_to",
        "modified_args",
        "modified_result",
    }
)
_PHASES = ("call", "result")


class WireError(Exception):
    """A frame that cannot be honoured. ``code`` is one of the wire codes.

    Every code is fail-closed at the far end: a client that receives an error
    has no verdict, so it must block. There is deliberately no code for "a rule
    raised" - a raising rule is a *denied decision* (see ``sidecar.server``),
    not a malformed frame, and it is recorded as one.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Unrepresentable(WireError):
    def __init__(self, message: str) -> None:
        super().__init__("unrepresentable", message)


def canonical(obj: Any) -> str:
    """The one serialization used on the wire: sorted keys, tight separators.

    ``allow_nan=False`` because ``NaN``/``Infinity`` are not JSON: the stdlib
    emits them by default and a strict parser (JS ``JSON.parse``) rejects the
    result. Refusing here fails at the boundary that can explain itself.
    """
    try:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except ValueError as exc:
        raise Unrepresentable("value is not JSON-representable: {}".format(exc))


# --- the value codec ---------------------------------------------------------

def encode_value(value: Any) -> Any:
    """Convert a Python value to JSON, escaping what JSON lacks.

    Lossy by design, and the losses are named: a ``set`` becomes a sorted list
    (JSON has no set; sorting by canonical form keeps it deterministic for
    mixed-type members, which ``sorted`` alone cannot do) and a ``tuple`` becomes
    a list. ``bytes`` is escaped rather than lost, because tool arguments carry
    binary (a file's contents) and a silently dropped payload is the exact
    failure this module exists to prevent.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        canonical(value)  # rejects NaN / Infinity
        return value
    if isinstance(value, (bytes, bytearray)):
        return {
            _TAG: _BYTES,
            "b64": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                # json.dumps would coerce an int key to a string silently,
                # handing the tool a key it never received.
                raise Unrepresentable(
                    "object key must be a string, got {}".format(type(key).__name__)
                )
            out[key] = encode_value(item)
        return out
    if isinstance(value, (list, tuple)):
        return [encode_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(
            (encode_value(item) for item in value), key=canonical
        )
    raise Unrepresentable(
        "cannot represent a {}".format(type(value).__name__)
    )


def decode_value(value: Any) -> Any:
    """Invert :func:`encode_value` for the shapes it escapes."""
    if isinstance(value, dict):
        if set(value.keys()) == {_TAG, "b64"} and value[_TAG] == _BYTES:
            try:
                return base64.b64decode(value["b64"], validate=True)
            except Exception as exc:
                raise WireError(
                    "bad_request", "invalid base64 in bytes envelope: {}".format(exc)
                )
        return {key: decode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode_value(item) for item in value]
    return value


# --- frames -----------------------------------------------------------------

def encode_frame(frame: Dict[str, Any]) -> bytes:
    """One framed line: canonical JSON plus its newline, as UTF-8 bytes."""
    return canonical(frame).encode("utf-8") + b"\n"


def decode_line(line: Any) -> Dict[str, Any]:
    """Parse one line into a frame dict, checking the version.

    Takes bytes or str; the caller has already bounded the length (``MAX_LINE``)
    because a bound belongs where the bytes are read.
    """
    if isinstance(line, (bytes, bytearray)):
        try:
            text = bytes(line).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WireError("bad_request", "frame is not valid UTF-8: {}".format(exc))
    else:
        text = line
    try:
        frame = json.loads(text)
    except ValueError as exc:
        raise WireError("bad_request", "frame is not valid JSON: {}".format(exc))
    if not isinstance(frame, dict):
        raise WireError("bad_request", "frame must be a JSON object")
    if frame.get("v") != PROTOCOL_VERSION:
        raise WireError(
            "bad_version",
            "unsupported protocol version {!r} (expected {})".format(
                frame.get("v"), PROTOCOL_VERSION
            ),
        )
    return frame


def _check_keys(frame: Dict[str, Any], allowed: frozenset, what: str) -> None:
    unknown = set(frame.keys()) - allowed
    if unknown:
        raise WireError(
            "bad_request",
            "unknown {} key(s): {}".format(what, ", ".join(sorted(unknown))),
        )


def _opt_str(frame: Dict[str, Any], key: str) -> Any:
    value = frame.get(key)
    if value is not None and not isinstance(value, str):
        raise WireError("bad_request", "{} must be a string or null".format(key))
    return value


def request_frame(op_id: str, event: SensorEvent) -> Dict[str, Any]:
    """Build the frame that asks the engine to decide one event."""
    payload: Dict[str, Any] = {
        "action": event.action,
        "args": encode_value(event.args),
        "phase": event.phase,
    }
    for key in ("principal", "span_id", "parent_principal"):
        value = getattr(event, key, None)
        if value is not None:
            payload[key] = value
    if event.ts:
        payload["ts"] = event.ts
    return {"v": PROTOCOL_VERSION, "id": op_id, "event": payload}


def parse_request(frame: Dict[str, Any]) -> Tuple[str, SensorEvent]:
    """Read a request frame into ``(op_id, SensorEvent)``.

    ``action`` and ``args`` are required. A missing ``args`` is refused rather
    than defaulted to ``{}``: an engine shown an empty argument dict finds no
    opinion and allows, so defaulting here would quietly convert a client bug
    into a bypass.
    """
    _check_keys(frame, _REQUEST_KEYS, "request")
    op_id = frame.get("id")
    if not isinstance(op_id, str) or not op_id:
        raise WireError("bad_request", "id must be a non-empty string")

    event = frame.get("event")
    if not isinstance(event, dict):
        raise WireError("bad_request", "event must be a JSON object")
    _check_keys(event, _EVENT_KEYS, "event")

    action = event.get("action")
    if not isinstance(action, str) or not action:
        raise WireError("bad_request", "event.action must be a non-empty string")
    if "args" not in event:
        raise WireError("bad_request", "event.args is required")
    args = event.get("args")
    if not isinstance(args, dict):
        raise WireError("bad_request", "event.args must be a JSON object")

    phase = event.get("phase", "call")
    if phase not in _PHASES:
        raise WireError(
            "bad_request",
            "event.phase must be one of {}".format(", ".join(_PHASES)),
        )

    ts = event.get("ts")
    if ts is not None and not isinstance(ts, (int, float)):
        raise WireError("bad_request", "event.ts must be a number")
    if isinstance(ts, float) and not math.isfinite(ts):
        raise WireError("bad_request", "event.ts must be finite")

    principal = _opt_str(event, "principal")
    span_id = _opt_str(event, "span_id")
    parent_principal = _opt_str(event, "parent_principal")

    kwargs: Dict[str, Any] = {}
    if ts is not None:
        kwargs["ts"] = float(ts)
    return op_id, SensorEvent(
        action=action,
        args=decode_value(args),
        principal=principal,
        span_id=span_id,
        parent_principal=parent_principal,
        phase=phase,
        **kwargs,
    )


def response_frame(op_id: str, decision: Decision) -> Dict[str, Any]:
    """Build the frame carrying one decision. Raises on an unrepresentable
    rewrite, which the caller turns into an error frame - the far end then has
    no verdict and blocks."""
    if decision.modified_args is not None and not isinstance(
        decision.modified_args, dict
    ):
        raise WireError(
            "internal", "modified_args must be an object or null"
        )
    return {
        "v": PROTOCOL_VERSION,
        "id": op_id,
        "verdict": int(decision.verdict),
        "reason": decision.reason,
        "policy_id": decision.policy_id,
        "attributed_to": decision.attributed_to,
        "modified_args": encode_value(decision.modified_args),
        "modified_result": encode_value(decision.modified_result),
    }


def parse_response(frame: Dict[str, Any], op_id: str) -> Decision:
    """Read a response frame into a ``Decision``, or raise on an error frame.

    ``modified_result`` of ``None`` means "no replacement", matching the
    in-process path (``interceptors/mcp.py`` only applies a MODIFY result when it
    is not ``None``). The wire invents no semantics the Python path lacks, so one
    conformance corpus can describe both.
    """
    if "error" in frame:
        error = frame.get("error")
        if not isinstance(error, dict):
            raise WireError("internal", "error must be an object")
        raise WireError(
            str(error.get("code", "internal")), str(error.get("message", ""))
        )
    _check_keys(frame, _RESPONSE_KEYS, "response")
    if frame.get("id") != op_id:
        raise WireError(
            "bad_request",
            "response id {!r} does not match request {!r}".format(
                frame.get("id"), op_id
            ),
        )
    raw_verdict = frame.get("verdict")
    if not isinstance(raw_verdict, int) or isinstance(raw_verdict, bool):
        raise WireError("bad_request", "verdict must be an integer")
    try:
        verdict = Verdict(raw_verdict)
    except ValueError:
        raise WireError("bad_request", "unknown verdict {!r}".format(raw_verdict))

    reason = frame.get("reason", "")
    if not isinstance(reason, str):
        raise WireError("bad_request", "reason must be a string")

    modified_args = frame.get("modified_args")
    if modified_args is not None and not isinstance(modified_args, dict):
        raise WireError("bad_request", "modified_args must be an object or null")

    return Decision(
        verdict=verdict,
        reason=reason,
        policy_id=_opt_str(frame, "policy_id"),
        modified_args=(
            None if modified_args is None else decode_value(modified_args)
        ),
        attributed_to=_opt_str(frame, "attributed_to"),
        modified_result=decode_value(frame.get("modified_result")),
    )


def error_frame(op_id: str, code: str, message: str) -> Dict[str, Any]:
    """Build the frame that answers a request with a failure instead of a
    verdict. The far end must treat any of these as a block."""
    return {
        "v": PROTOCOL_VERSION,
        "id": op_id,
        "error": {"code": code, "message": message},
    }
