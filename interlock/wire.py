"""The wire protocol between an out-of-process sensor and the policy engine.

An agent running in another language (see the Node.js sensor, R13) does not get
its own rules. It gets a socket to this process, which owns the one engine. Two
frames cross it, both newline-delimited canonical JSON:

    request   {"v":1,"id":...,"event":{action,args,principal,span_id,
                                       parent_principal,phase,ts,call_id},
               "scope":{... signed scope document, optional ...}}
    response  {"v":1,"id":...,"verdict":0|1|2|3,"reason":...,"policy_id":...,
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

A request may also carry a **signed scope document** under the optional
``scope`` key. It is the same signed envelope the offline fallback policy uses
(``interlock.sidecar.fallback``): ``version``/``written_at``/``policy``/``mac``,
with ``policy`` the document as a canonical-JSON string and ``mac`` an
HMAC-SHA256 over ``"<written_at>\\n<policy>"``. Carrying it as a string means the
Python and Node.js peers verify the same bytes without agreeing on a JSON
canonicalization. An overlay the far end cannot verify is refused rather than
ignored: a scope document that silently fails to verify would let a client
believe it is governed by a scope set the daemon never applied. The MAC is
verified by the daemon (which holds the key); :func:`parse_request` refuses an
overlay that is unsigned or malformed before it reaches the engine.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from .enforce import Decision, Verdict
from .event import SensorEvent, strip_trust_labels

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

_REQUEST_KEYS = frozenset({"v", "id", "event", "scope"})
_EVENT_KEYS = frozenset(
    {"action", "args", "principal", "span_id", "parent_principal", "phase", "ts",
     "call_id"}
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

# The signed scope-document envelope. Same key set and MAC formula as the
# offline fallback policy (``interlock.sidecar.fallback``); a scope document is
# signed and verified exactly like one.
SCOPE_VERSION = 1
SCOPE_KEYS = frozenset({"version", "written_at", "policy", "mac"})


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


class UnauthenticatedScope(WireError):
    """A scope-document overlay that is unsigned, malformed, or does not verify.

    Its own code (``unauthenticated_scope``) so a client can tell "your scope
    document is not the one this daemon trusts" apart from a generic bad frame.
    Every rung of the ladder - absent, wrong version, non-str ``mac``, MAC
    mismatch - is this same refusal: the client has no verified scope, so it must
    block.
    """

    def __init__(self, message: str) -> None:
        super().__init__("unauthenticated_scope", message)


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


# --- the signed scope document ----------------------------------------------

def scope_mac(key: bytes, written_at: int, policy: str) -> str:
    """The MAC over a scope document: ``HMAC-SHA256(key, "<written_at>\\n<policy>")``.

    Identical to the fallback policy's MAC (``interlock.sidecar.fallback._mac``),
    and deliberately so: one formula means one place to reason about, and the
    Node.js peer can verify a scope document with the code it already uses for
    the fallback policy.
    """
    message = "{}\n{}".format(written_at, policy).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def scope_envelope(
    document: Mapping[str, Any], key: bytes, *, written_at: Optional[int] = None
) -> Dict[str, Any]:
    """Sign ``document`` into the envelope that travels on the wire and to disk.

    The document is serialized to a canonical JSON *string* and the MAC covers
    those exact bytes, so a verifier never has to re-serialize the document (and
    never has to agree on a canonicalization) to check the signature.
    """
    policy = canonical(document)
    stamp = int(time.time()) if written_at is None else int(written_at)
    return {
        "version": SCOPE_VERSION,
        "written_at": stamp,
        "policy": policy,
        "mac": scope_mac(key, stamp, policy),
    }


def verify_scope_envelope(envelope: Any, key: bytes) -> str:
    """Verify a signed scope envelope under ``key``; return its ``policy`` string.

    The refusal ladder mirrors ``read_fallback``'s: a non-object, a wrong or
    missing version, a non-str/absent ``mac``, an absent/non-str ``policy``, and
    a MAC mismatch all raise :class:`UnauthenticatedScope`. Fail-closed at every
    rung - a scope document that cannot be proven is refused, never assumed.
    """
    if not isinstance(envelope, dict):
        raise UnauthenticatedScope("scope document must be an object")
    if envelope.get("version") != SCOPE_VERSION:
        raise UnauthenticatedScope("not a scope document (bad or missing version)")
    written_at = envelope.get("written_at")
    policy = envelope.get("policy")
    mac = envelope.get("mac")
    if not isinstance(written_at, int) or isinstance(written_at, bool):
        raise UnauthenticatedScope("scope document is missing a written_at int")
    if not isinstance(policy, str) or not isinstance(mac, str) or not mac:
        raise UnauthenticatedScope("scope document is unsigned or malformed")
    if not hmac.compare_digest(scope_mac(key, written_at, policy), mac):
        raise UnauthenticatedScope("scope document signature does not verify")
    return policy


def scope_identity(envelope: Mapping[str, Any]) -> str:
    """A signed scope document's identity: ``"<written_at>:<mac>"``.

    Identifies *which* document decided without carrying any of its content -
    the same name-not-value rule ``attributed_to`` and the receipt's args digest
    follow. Two documents with the same identity are the same signed bytes.
    """
    return "{}:{}".format(envelope.get("written_at"), envelope.get("mac"))


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


def request_frame(
    op_id: str,
    event: SensorEvent,
    *,
    scope: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the frame that asks the engine to decide one event.

    ``scope``, when given, is the signed scope-document envelope
    (:func:`scope_envelope`) the client presents for this call; it is omitted
    entirely when absent, so a client with no scope document sends exactly the
    frame earlier clients sent.
    """
    payload: Dict[str, Any] = {
        "action": event.action,
        "args": encode_value(event.args),
        "phase": event.phase,
    }
    for key in ("principal", "span_id", "parent_principal", "call_id"):
        value = getattr(event, key, None)
        if value is not None:
            payload[key] = value
    if event.ts:
        payload["ts"] = event.ts
    frame: Dict[str, Any] = {"v": PROTOCOL_VERSION, "id": op_id, "event": payload}
    if scope is not None:
        frame["scope"] = scope
    return frame


def parse_scope(frame: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Read the optional signed scope overlay out of a request frame.

    Returns None when the frame carries no scope. When it does, the envelope's
    *shape* is checked here - exact keys, the right version, an int
    ``written_at``, a str ``policy`` that is valid JSON, and a non-empty ``mac``
    - and any shortfall raises :class:`UnauthenticatedScope`. The MAC itself is
    not checked here because this module holds no key; the daemon verifies it
    with :func:`verify_scope_envelope` before the overlay is trusted. Shape
    first, then signature: an overlay with no ``mac`` is refused as unsigned
    without ever reaching the key check.
    """
    scope = frame.get("scope")
    if scope is None:
        return None
    if not isinstance(scope, dict):
        raise UnauthenticatedScope("scope must be a JSON object")
    _check_keys(scope, SCOPE_KEYS, "scope")
    if scope.get("version") != SCOPE_VERSION:
        raise UnauthenticatedScope(
            "scope.version must be {}".format(SCOPE_VERSION)
        )
    written_at = scope.get("written_at")
    if not isinstance(written_at, int) or isinstance(written_at, bool):
        raise UnauthenticatedScope("scope.written_at must be an integer")
    policy = scope.get("policy")
    if not isinstance(policy, str):
        raise UnauthenticatedScope("scope.policy must be a string")
    try:
        json.loads(policy)
    except ValueError as exc:
        raise UnauthenticatedScope("scope.policy is not valid JSON: {}".format(exc))
    mac = scope.get("mac")
    if not isinstance(mac, str) or not mac:
        raise UnauthenticatedScope("scope document is unsigned (no mac)")
    return scope


def parse_request(frame: Dict[str, Any]) -> Tuple[str, SensorEvent]:
    """Read a request frame into ``(op_id, SensorEvent)``.

    ``action`` and ``args`` are required. A missing ``args`` is refused rather
    than defaulted to ``{}``: an engine shown an empty argument dict finds no
    opinion and allows, so defaulting here would quietly convert a client bug
    into a bypass.

    The decoded arguments cross a process boundary and are model-influenced, so
    the reserved :data:`~interlock.event.TRUST_LABELS` keys are stripped here.
    The wire carries no trusted-label channel: the far end can never set a
    trust fact, only the daemon's own integrations can.
    """
    _check_keys(frame, _REQUEST_KEYS, "request")
    parse_scope(frame)
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
    call_id = _opt_str(event, "call_id")

    kwargs: Dict[str, Any] = {}
    if ts is not None:
        kwargs["ts"] = float(ts)
    return op_id, SensorEvent(
        action=action,
        args=strip_trust_labels(decode_value(args)),
        principal=principal,
        span_id=span_id,
        parent_principal=parent_principal,
        phase=phase,
        call_id=call_id,
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
