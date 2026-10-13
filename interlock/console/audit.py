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
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from ..receipt import GENESIS, Receipt
from ..sink import verify_file
from .server import ROUTES
from .server import _health as _base_health

VALID_VERDICTS = ("ALLOW", "BLOCK", "MODIFY", "ESCALATE", "OBSERVED")
VALID_ORDERS = ("asc", "desc")

DEFAULT_LIMIT = 100
MIN_LIMIT = 1
MAX_LIMIT = 500

#: How often the stream polls the receipt file's size for new receipts or a
#: truncation, in seconds. Set below the spec's 1-second visibility bound: an
#: append landing right after a tick is only caught on the next one, and the
#: read-and-send work that follows (file I/O, JSON encode, the SSE write)
#: still has to land inside the 1-second window, so the poll period alone
#: cannot be the full second.
POLL_SECONDS = 0.9

#: How often the stream sends a ``: keepalive`` comment while idle, in seconds.
KEEPALIVE_SECONDS = 15.0


def read_key_file(path: str) -> bytes:
    """Read a receipt MAC key: 64 hex characters, or raw bytes.

    Trailing newlines are stripped before that test, because the difference
    between a key and the same key with a newline is a different key. Raises
    ``ValueError`` for a path that is missing, unreadable or empty - the CLI
    turns that into a one-line refusal before the server binds.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read().rstrip(b"\r\n")
    except OSError as exc:
        raise ValueError(
            "cannot read key file {}: {}".format(path, exc.strerror or exc)
        )
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except ValueError:
            pass
    if not raw:
        raise ValueError("key file {} is empty".format(path))
    return raw


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


def _parse_receipt_line(stripped: str, index: int) -> Dict[str, Any]:
    """One line turned into a receipt dict, or an ``unreadable`` placeholder.

    A line that is not valid JSON or is missing a required field must not
    raise: it still occupies a line position, so it is reported rather than
    aborting whichever endpoint is reading the log (the page, verify or the
    stream).
    """
    try:
        fields = dataclasses.asdict(Receipt.from_json(stripped))
    except Exception:
        return {"index": index, "unreadable": True}
    fields["index"] = index
    return fields


def _read_receipts(path: str) -> List[Dict[str, Any]]:
    """Every receipt in ``path``, each carrying its 0-based file line position."""
    if not os.path.exists(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            stripped = line.strip()
            if not stripped:
                continue
            out.append(_parse_receipt_line(stripped, index))
    return out


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

    receipts = _read_receipts(path)
    count = len(receipts)
    head = receipts[-1].get("mac", GENESIS) if receipts else GENESIS

    key = handler.server.receipts_key
    if key is None:
        return 200, {
            "status": "unverified",
            "problem": "no key was configured to verify this log",
            "count": count,
            "head": head,
        }

    problem = verify_file(path, key=key)
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
                 "broken_index": broken_index}


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _write_sse(wfile: Any, event: str, data: Dict[str, Any]) -> None:
    chunk = "event: {}\ndata: {}\n\n".format(event, json.dumps(data))
    wfile.write(chunk.encode("utf-8"))
    wfile.flush()


def _initial_tail_state(path: str) -> "tuple[List[Dict[str, Any]], int, int]":
    """The log's current receipts, plus the byte offset and line count a
    stream should start polling from.

    All three come from one pass over the file, so they describe the same
    instant; reading them with separate calls (size, line count, receipts)
    risks a write landing between two of those calls and leaving the stream's
    starting point inconsistent with what it just reported in ``hello``.
    """
    receipts: List[Dict[str, Any]] = []
    line_index = 0
    offset = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    receipts.append(_parse_receipt_line(stripped, line_index))
                line_index += 1
                offset = fh.tell()
    return receipts, offset, line_index


def _read_new_receipts(path: str, offset: int, line_index: int) -> "tuple[List[Dict[str, Any]], int, int]":
    """Receipts appended to ``path`` after byte ``offset``.

    Reads only the bytes written since the last poll tick, not the whole
    file, so a tick's cost stays proportional to what was appended rather
    than to the log's full size - otherwise the per-tick work keeps growing
    as the log grows, and the 1-second live-tail bound in the spec would
    eventually slip. A trailing line with no newline yet is left unread: the
    next tick starts from the same offset and picks it up once it is whole.
    """
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        fh.seek(offset)
        while True:
            line = fh.readline()
            if not line or not line.endswith("\n"):
                break
            stripped = line.strip()
            if stripped:
                out.append(_parse_receipt_line(stripped, line_index))
            line_index += 1
            offset = fh.tell()
    return out, offset, line_index


def _handle_stream(handler: Any) -> Any:
    path = handler.server.receipts_path
    if path is None:
        handler._send_json(404, _not_configured())
        return None

    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    wfile = handler.wfile

    receipts, offset, line_index = _initial_tail_state(path)

    try:
        _write_sse(wfile, "hello", {"count": len(receipts)})
        last_keepalive = time.monotonic()
        next_poll = time.monotonic() + POLL_SECONDS
        while True:
            delay = next_poll - time.monotonic()
            if delay > 0:
                time.sleep(delay)
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
    return None


def _health_with_receipts(handler: Any) -> Any:
    status, body = _base_health(handler)
    body = dict(body)
    body["receipts"] = handler.server.receipts_path is not None
    body["verify"] = handler.server.receipts_key is not None
    return status, body


ROUTES["/api/receipts"] = {"GET": _handle_receipts}
ROUTES["/api/receipts/verify"] = {"GET": _handle_verify}
ROUTES["/api/receipts/stream"] = {"GET": _handle_stream}
ROUTES["/api/health"]["GET"] = _health_with_receipts
