"""The receipt log viewer: reading, filtering, verification and the SSE
stream generator behind ``/api/receipts``, ``/api/receipts/verify`` and
``/api/receipts/stream``. Routes are registered into the shared tables from
``server.py``, so this module never edits the request handler class.

The key given on the command line never leaves this process: it is held only
as the raw bytes needed to call :func:`interlock.sink.verify_file`, and no
response built here ever serializes it.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import select
import socket
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from ..receipt import GENESIS, Receipt
from ..sink import verify_file
from .server import HEALTH_CONTRIBUTORS, ROUTES

VALID_VERDICTS = ("ALLOW", "BLOCK", "MODIFY", "ESCALATE", "OBSERVED")
VALID_ORDERS = ("asc", "desc")

DEFAULT_LIMIT = 100
MIN_LIMIT = 1
MAX_LIMIT = 500

#: Receipt's fields, in declaration order. Every one is a scalar except
#: ``masked``, a flat ``{str: int}`` dict, so a shallow copy is all a page needs.
_RECEIPT_FIELDS = tuple(f.name for f in dataclasses.fields(Receipt))

#: How often the stream polls the receipt file's size for new receipts or a
#: truncation, in seconds. Set below the spec's 1-second visibility bound: an
#: append landing right after a tick is only caught on the next one, and the
#: read-and-send work that follows (file I/O, JSON encode, the SSE write)
#: still has to land inside the 1-second window, so the poll period alone
#: cannot be the full second.
POLL_SECONDS = 0.9

#: How often the stream sends a ``: keepalive`` comment while idle, in seconds.
KEEPALIVE_SECONDS = 15.0


def _not_configured() -> Dict[str, Any]:
    return {
        "error": {
            "code": "receipts_not_configured",
            "message": "the console was started without --receipts",
        }
    }


def _bad_query(message: str) -> Dict[str, Any]:
    return {"error": {"code": "bad_query", "message": message}}


def _query_params(handler: Any) -> Dict[str, List[str]]:
    return parse_qs(urlsplit(handler.path).query)


def _first(qs: Dict[str, List[str]], name: str) -> Optional[str]:
    values = qs.get(name)
    return values[0] if values else None


def _int_param(qs: Dict[str, List[str]], name: str, default: int) -> int:
    value = _first(qs, name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _parse_receipt_line(raw_line: bytes, index: int) -> Dict[str, Any]:
    """One complete line turned into a receipt dict, or an ``unreadable``
    placeholder.

    A line that is not valid UTF-8 (F18), is not valid JSON, or is missing a
    required field must not raise: it still occupies a line position, so it
    is reported rather than aborting whichever endpoint is reading the log
    (the page, verify or the stream).
    """
    try:
        text = raw_line.decode("utf-8")
    except UnicodeDecodeError:
        return {"index": index, "unreadable": True}
    try:
        receipt = Receipt.from_json(text.strip())
    except Exception:
        return {"index": index, "unreadable": True}
    if _receipt_shape_error(receipt) is not None:
        return {"index": index, "unreadable": True}
    fields = _receipt_fields(receipt)
    fields["index"] = index
    return fields


#: String fields every receipt carries. A missing one is already a parse
#: error; these are the fields whose *type* the viewer relies on.
_REQUIRED_STRING_FIELDS = (
    "action",
    "verdict",
    "reason",
    "phase",
    "args_digest",
    "prev",
    "mac",
)

#: Optional string fields: absent (``None``) or a string, never another type.
_OPTIONAL_STRING_FIELDS = (
    "policy_id",
    "attributed_to",
    "principal",
    "span_id",
    "call_id",
    "policy_epoch",
    "policy_verdict",
    "approval",
    "outcome",
    "enforcer",
    "scope_document",
)


def _receipt_shape_error(receipt: Receipt) -> Optional[str]:
    """Why ``receipt`` cannot be shown as a row, or ``None`` when it can.

    ``Receipt.from_json`` does no type checking (it is shared with the writer
    path and must stay that way), so a line carrying, say, a list for
    ``policy_id`` parses fine and then makes the page's set of policy ids
    unhashable. Checking shape here, at the viewer's parse boundary, turns
    that line into the same ``unreadable`` placeholder a non-JSON line gets.

    This deliberately does not run before :func:`interlock.sink.verify_file`:
    a wrong-typed receipt is still verified (and so still reports the chain
    broken); the check only decides what the viewer renders.
    """
    ts = receipt.ts
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return "ts is not a number"
    for name in _REQUIRED_STRING_FIELDS:
        if not isinstance(getattr(receipt, name), str):
            return "{} is not a string".format(name)
    if not isinstance(receipt.observed, bool):
        return "observed is not a boolean"
    for name in _OPTIONAL_STRING_FIELDS:
        value = getattr(receipt, name)
        if value is not None and not isinstance(value, str):
            return "{} is not a string or null".format(name)
    for name in ("elapsed_us", "tokens"):
        value = getattr(receipt, name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            return "{} is not an integer or null".format(name)
    masked = receipt.masked
    if masked is not None:
        if not isinstance(masked, dict):
            return "masked is not an object"
        for key, value in masked.items():
            if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int):
                return "masked is not a map of counts"
    return None


def _receipt_fields(receipt: Receipt) -> Dict[str, Any]:
    """A receipt as a plain dict, without :func:`dataclasses.asdict`.

    ``asdict`` deep-copies every value recursively; on a 10k-receipt log that
    was about 70% of every page load (239k recursive calls a request). The
    fields are scalars plus one flat dict, so copying that dict is enough.
    """
    out = {name: getattr(receipt, name) for name in _RECEIPT_FIELDS}
    masked = out.get("masked")
    if isinstance(masked, dict):
        out["masked"] = dict(masked)
    return out


def _complete_lines(raw: bytes) -> List[bytes]:
    """Every newline-terminated line in ``raw``, in file order.

    A trailing chunk with no newline yet is not a line (F19): it is
    invisible until a later write terminates it. ``bytes.split`` always
    leaves exactly one such element at the end - the empty string after a
    final ``\\n``, or the partial tail of an unterminated write - and that
    is the element dropped here.
    """
    return raw.split(b"\n")[:-1]


class _ParsedLog:
    """One receipt log, parsed incrementally and shared by every reader.

    Every page load, filter click, verify, activity view and stream
    handshake reads the whole log, and re-parsing it each time made a
    10k-receipt log take seconds per request. The log is append-only, so only
    the lines written since the previous read are parsed now. ``prefix`` is
    the exact bytes already parsed: when the file no longer starts with them
    (truncated, rotated, edited in place) everything is parsed again and
    ``generation`` moves on, so a cached view is never stale. Reading the raw
    bytes stays per request; it costs milliseconds even for megabytes.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.prefix = b""
        self.receipts: List[Dict[str, Any]] = []
        self.next_index = 0
        self.generation = 0
        #: (generation, end offset, key, problem) of the last verification.
        self.verified: Optional[tuple] = None


_LOGS: Dict[str, _ParsedLog] = {}
_LOGS_LOCK = threading.Lock()


def _parsed_log(path: str) -> _ParsedLog:
    with _LOGS_LOCK:
        log = _LOGS.get(path)
        if log is None:
            log = _LOGS[path] = _ParsedLog()
        return log


def _log_snapshot(path: str) -> "tuple[List[Dict[str, Any]], int, int, int]":
    """The log's receipts, the byte offset just past its last complete line,
    its complete-line count and the cache generation, all from one read.

    A trailing line with no newline yet is left unparsed (F19) and picked up
    once a later write terminates it.
    """
    log = _parsed_log(path)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        raw = b""
    with log.lock:
        # A prefix match alone cannot tell an append from a rollback to an
        # earlier prefix: restoring an old copy can leave the new bytes a
        # strict prefix of the parsed ones. The byte length is what
        # distinguishes them, so a shorter file starts over and its cached
        # verify is invalidated with it.
        if len(raw) < len(log.prefix) or not raw.startswith(log.prefix):
            log.prefix, log.receipts, log.next_index = b"", [], 0
            log.generation += 1
        end = raw.rfind(b"\n") + 1
        if end > len(log.prefix):
            for raw_line in _complete_lines(raw[len(log.prefix):end]):
                if raw_line.strip():
                    log.receipts.append(_parse_receipt_line(raw_line, log.next_index))
                log.next_index += 1
            log.prefix = raw[:end]
        return list(log.receipts), len(log.prefix), log.next_index, log.generation


def _read_receipts(path: str) -> List[Dict[str, Any]]:
    """Every complete receipt in ``path``, each carrying its 0-based file
    line position. The dicts are shared between requests: read, never mutate."""
    return _log_snapshot(path)[0]


def _handle_receipts(handler: Any) -> Any:
    path = handler.server.receipts_path
    if path is None:
        return 404, _not_configured()

    qs = _query_params(handler)
    verdict = _first(qs, "verdict")
    if verdict is not None and verdict not in VALID_VERDICTS:
        return 400, _bad_query("verdict must be one of {}".format(", ".join(VALID_VERDICTS)))
    order = _first(qs, "order") or "desc"
    if order not in VALID_ORDERS:
        return 400, _bad_query("order must be one of {}".format(", ".join(VALID_ORDERS)))
    action = _first(qs, "action")
    policy = _first(qs, "policy")
    text = (_first(qs, "q") or "").strip().lower()
    offset = _int_param(qs, "offset", 0)
    limit = _int_param(qs, "limit", DEFAULT_LIMIT)
    limit = max(MIN_LIMIT, min(MAX_LIMIT, limit))

    receipts = _read_receipts(path)
    count_all = len(receipts)
    index = _first(qs, "index")
    if index is not None:
        # One receipt by its line index: the detail drawer's deep link.
        wanted = _int_param(qs, "index", -1)
        found = [r for r in receipts if r.get("index") == wanted]
        return 200, {"total": len(found), "count_all": count_all, "receipts": found,
                     "rules": []}
    filtered = [r for r in receipts if _matches(r, verdict, action, policy, text)]
    total = len(filtered)
    ordered = list(reversed(filtered)) if order == "desc" else filtered
    page = ordered[offset:offset + limit]
    rules = sorted({r["policy_id"] for r in receipts if r.get("policy_id")})
    return 200, {"total": total, "count_all": count_all, "receipts": page, "rules": rules}


def _matches(r: Dict[str, Any], verdict: Optional[str], action: Optional[str],
             policy: Optional[str], text: str) -> bool:
    """One receipt against the page's filters. An unreadable line only shows
    when nothing narrows the list: it has no fields to match."""
    if r.get("unreadable"):
        return verdict is None and action is None and policy is None and not text
    if verdict == "OBSERVED":
        if not r.get("observed"):
            return False
    elif verdict == "ESCALATE":
        if r.get("policy_verdict") != "ESCALATE":
            return False
    elif verdict is not None and (r.get("verdict") != verdict or r.get("observed")):
        return False
    if action is not None and r.get("action") != action:
        return False
    if policy is not None and r.get("policy_id") != policy:
        return False
    if text:
        hay = " ".join(str(r.get(k) or "") for k in ("action", "principal", "span_id", "policy_id",
                                                      "call_id", "reason")).lower()
        if text not in hay:
            return False
    return True


def _handle_verify(handler: Any) -> Any:
    path = handler.server.receipts_path
    if path is None:
        return 404, _not_configured()

    receipts, end, _lines, generation = _log_snapshot(path)
    count = len(receipts)
    head = receipts[-1].get("mac", GENESIS) if receipts else GENESIS
    # The anchor is the mac the operator recorded elsewhere; it is not the
    # response's ``head``, which stays the last receipt actually on disk.
    anchor = getattr(handler.server, "receipts_head", None)

    key = handler.server.receipts_key
    if key is None:
        return 200, {
            "status": "unverified",
            "problem": "no key was configured to verify this log",
            "count": count,
            "head": head,
            "expected_head": anchor,
        }

    problem = _verify_cached(path, key, generation, end, anchor)
    status = "intact" if problem is None else "broken"
    broken_index = None
    if problem:
        match = re.match(r"^receipt (\d+)", problem)
        readable = [r for r in receipts if not r.get("unreadable")]
        if match and int(match.group(1)) < len(receipts):
            # verify_file counts receipts in chain order; map that to the line index.
            position = int(match.group(1))
            ordered = readable if position < len(readable) else receipts
            broken_index = ordered[min(position, len(ordered) - 1)].get("index")
    return 200, {"status": status, "problem": problem, "count": count, "head": head,
                 "broken_index": broken_index, "expected_head": anchor}


def _verify_cached(path: str, key: bytes, generation: int, end: int,
                   head: Optional[str] = None) -> Optional[str]:
    """Verify the chain, or reuse the answer for bytes already verified.

    A verification reads and MACs every receipt; the result can only change
    when the log's bytes do, which a new generation (rewrite) or a new end
    offset (append) both signal. The anchor is part of the key too: an
    anchored and an unanchored answer must never share a slot.
    """
    log = _parsed_log(path)
    with log.lock:
        cached = log.verified
    if cached is not None and cached[:4] == (generation, end, key, head):
        return cached[4]
    problem = _verify_without_partial_tail(path, key, head)
    with log.lock:
        log.verified = (generation, end, key, head, problem)
    return problem


def _verify_without_partial_tail(path: str, key: bytes,
                                 head: Optional[str] = None) -> Optional[str]:
    """``verify_file``, but never fed a trailing line with no newline yet.

    ``verify_file`` lives in ``interlock/sink.py``, which this deliverable
    may not edit, and reads the whole file itself. A trailing unterminated
    line must stay invisible to it too (F19), so when the log currently ends
    in one, verify runs against a temp copy with that tail cut off instead of
    the real path. A complete non-UTF-8 line (F18) is still handed to
    ``verify_file``, whose own text-mode read raises decoding it; that is
    reported the same way as any other verification failure: ``broken``.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw or raw.endswith(b"\n"):
        target, cleanup = path, None
    else:
        truncated = raw[: raw.rfind(b"\n") + 1]
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmp.write(truncated)
        finally:
            tmp.close()
        target, cleanup = tmp.name, tmp.name
    try:
        try:
            return verify_file(target, key=key, head=head)
        except UnicodeDecodeError:
            return "a receipt line is not valid UTF-8"
    finally:
        if cleanup is not None:
            os.unlink(cleanup)


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _write_sse(wfile: Any, event: str, data: Dict[str, Any]) -> None:
    chunk = "event: {}\ndata: {}\n\n".format(event, json.dumps(data))
    wfile.write(chunk.encode("utf-8"))
    wfile.flush()


def _tail_from(path: str, offset: int, line_index: int) -> "tuple[List[Dict[str, Any]], int, int]":
    """Complete lines appended to ``path`` at or after byte ``offset``.

    Reads only the bytes from ``offset`` onward, not the whole file, so a
    tick's cost stays proportional to what was appended rather than to the
    log's full size - otherwise the per-tick work keeps growing as the log
    grows, and the 1-second live-tail bound in the spec would eventually
    slip. A trailing line with no newline yet is left unread (F19):
    ``offset`` stops right before it, so the next call starts from the same
    place and picks it up once it is whole.
    """
    with open(path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read()
    receipts: List[Dict[str, Any]] = []
    index = line_index
    for raw_line in _complete_lines(raw):
        if raw_line.strip():
            receipts.append(_parse_receipt_line(raw_line, index))
        index += 1
        offset += len(raw_line) + 1
    return receipts, offset, index


def _initial_tail_state(path: str) -> "tuple[List[Dict[str, Any]], int, int]":
    """The log's current receipts, plus the byte offset and line count a
    stream should start polling from.

    All three come from one pass over the file, so they describe the same
    instant; reading them with separate calls (size, line count, receipts)
    risks a write landing between two of those calls and leaving the stream's
    starting point inconsistent with what it just reported in ``hello``.
    """
    receipts, end, lines, _generation = _log_snapshot(path)
    return receipts, end, lines


def _read_new_receipts(path: str, offset: int, line_index: int) -> "tuple[List[Dict[str, Any]], int, int]":
    """Receipts appended to ``path`` after byte ``offset``."""
    return _tail_from(path, offset, line_index)


#: The most receipt streams the console answers at once (F16). Chosen as a
#: small, fixed cap rather than left unbounded: each stream holds a request
#: thread open indefinitely, and a reloaded audit page that opens several
#: before its old ones are noticed gone must still be refused loudly rather
#: than exhaust the server's threads one reload at a time.
MAX_STREAMS = 8


#: How long a new stream waits for a slot when all are taken. A client that
#: just hung up frees its slot within milliseconds; waiting this long first
#: means a reloaded page never meets a 503 from its own dying streams, while
#: a genuinely full console still refuses promptly.
SLOT_GRACE_SECONDS = 0.5


def _slots(server: Any) -> threading.Condition:
    with server._stream_lock:
        cond = getattr(server, "_stream_slots", None)
        if cond is None:
            cond = server._stream_slots = threading.Condition()
        return cond


def _acquire_stream_slot(server: Any) -> bool:
    cond = _slots(server)
    deadline = time.monotonic() + SLOT_GRACE_SECONDS
    with cond:
        while server._open_streams >= MAX_STREAMS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            cond.wait(remaining)
        server._open_streams += 1
        return True


def _release_stream_slot(server: Any) -> None:
    cond = _slots(server)
    with cond:
        server._open_streams -= 1
        cond.notify()


def _too_many_streams() -> Dict[str, Any]:
    return {
        "error": {
            "code": "too_many_streams",
            "message": "the console already has {} receipt streams open".format(MAX_STREAMS),
        }
    }


def _client_gone(sock: socket.socket) -> bool:
    """True once the client's end of ``sock`` has closed.

    A stream that only ever writes never learns its client is gone until
    its next write attempt, which the 15-second keepalive cadence (spec 04)
    can leave far later than the 2-second slot release Q2 requires.
    ``select`` on the read side catches this without waiting for a write: a
    client that closed its end makes the socket readable, and a
    non-blocking peek then returns ``b""`` (EOF) rather than data, since a
    stream's GET client never sends any.
    """
    readable, _, _ = select.select([sock], [], [], 0)
    if not readable:
        return False
    try:
        return sock.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def _handle_stream(handler: Any) -> Any:
    path = handler.server.receipts_path
    if path is None:
        handler._send_json(404, _not_configured())
        return None

    if not _acquire_stream_slot(handler.server):
        handler._send_json(503, _too_many_streams())
        return None

    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        wfile = handler.wfile
        sock = handler.connection

        receipts, offset, line_index = _initial_tail_state(path)

        try:
            _write_sse(wfile, "hello", {"count": len(receipts)})
            last_keepalive = time.monotonic()
            next_poll = time.monotonic() + POLL_SECONDS
            while True:
                delay = next_poll - time.monotonic()
                if delay > 0:
                    # Wait on the socket, not the clock: a client that hangs
                    # up makes it readable at once, so its slot is free again
                    # within milliseconds rather than at the next poll.
                    select.select([sock], [], [], delay)
                if _client_gone(sock):
                    break
                if time.monotonic() < next_poll:
                    continue
                next_poll += POLL_SECONDS

                size = _file_size(path)
                if size < offset:
                    _write_sse(wfile, "reset", {})
                    _, offset, line_index = _initial_tail_state(path)
                    last_keepalive = time.monotonic()
                    continue
                if size > offset:
                    new_receipts, offset, line_index = _read_new_receipts(path, offset, line_index)
                    for fields in new_receipts:
                        _write_sse(wfile, "receipt", fields)
                        last_keepalive = time.monotonic()
                now = time.monotonic()
                if now - last_keepalive >= KEEPALIVE_SECONDS:
                    wfile.write(b": keepalive\n\n")
                    wfile.flush()
                    last_keepalive = now
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
    finally:
        _release_stream_slot(handler.server)
    return None


def _health_contributor(handler: Any) -> Dict[str, Any]:
    return {
        "receipts": handler.server.receipts_path is not None,
        "verify": handler.server.receipts_key is not None,
    }


ROUTES["/api/receipts"] = {"GET": _handle_receipts}
ROUTES["/api/receipts/verify"] = {"GET": _handle_verify}
ROUTES["/api/receipts/stream"] = {"GET": _handle_stream}
HEALTH_CONTRIBUTORS.append(_health_contributor)
