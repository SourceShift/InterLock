"""Real tool calls, from the coding agent's own transcripts.

Receipts keep a digest of each call's arguments, never the arguments. Claude
Code keeps both the arguments and what the tool returned, in its session
transcripts: ``~/.claude/projects/<project>/<session>.jsonl``, with each
subagent's calls under ``<session>/subagents/``. This module reads them -
nothing else, and never writes - to:

- **explain a receipt**: find its call by ``call_id`` (the hook stamps Claude
  Code's ``tool_use`` id), show the file or command and the output the model
  saw, and prove the match by recomputing the argument digest;
- offer **recent real calls** as playground events;
- **backtest** a policy, and **sweep** the detector catalog, over those calls.

Calls become events through the Claude Code hook adapter itself, so a rule
sees exactly what it sees live (``Bash`` with ``command``, absolute paths).
Evaluating never emits a receipt or touches metrics: ``PolicyEngine.evaluate``
is pure.

Transcripts are large (gigabytes), so everything is bounded: a receipt lookup
reads only that session's files; the corpus reads the newest transcripts until
it has ``limit`` calls or has read :data:`BYTE_BUDGET` bytes, and a file read
before is read again only from where the last read stopped. Arguments and outputs sent to the page are
masked with the credential patterns of ``tool_output_secret_redactor``;
backtests and sweeps evaluate them unmasked.
"""
from __future__ import annotations

import glob
import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .server import PREFIX_ROUTES, ROUTES
from .session import ApiError, handles_errors, read_json_body, setting

BYTE_BUDGET = 400 * 1024 * 1024
MAX_RESULT = 64 * 1024
DEFAULT_LIMIT = 300
MAX_LIMIT = 2000
FILE_LIST_TTL = 15.0


@dataclass
class Call:
    call_id: str
    tool: str
    input: Dict[str, Any]
    ts: float
    cwd: Optional[str]
    session: str
    file: str
    subagent: bool
    result: Optional[str] = None
    is_error: bool = False


# --- reading transcripts ----------------------------------------------------------


def default_root() -> str:
    return os.path.join(os.path.expanduser("~"), ".claude", "projects")


def _root(handler: Any) -> str:
    return setting(handler, "transcripts_root") or default_root()


def _ts(text: Any) -> float:
    if not isinstance(text, str):
        return 0.0
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _absorb(lines: Iterable[str], path: str, calls: Dict[str, Call], order: List[str]) -> None:
    """Fold transcript lines into ``calls`` (by tool_use id) and ``order``."""
    subagent = "/subagents/" in path
    stem = os.path.splitext(os.path.basename(path))[0]
    for line in lines:
        if '"tool_use"' not in line and '"tool_result"' not in line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("message") if isinstance(entry, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                raw_input = block.get("input")
                tool_input: Dict[str, Any] = raw_input if isinstance(raw_input, dict) else {}
                call = Call(call_id=block["id"], tool=str(block.get("name") or ""), input=tool_input,
                            ts=_ts(entry.get("timestamp")), cwd=entry.get("cwd"),
                            session=str(entry.get("sessionId") or stem), file=path, subagent=subagent)
                if call.call_id not in calls:
                    order.append(call.call_id)
                calls[call.call_id] = call
            elif block.get("type") == "tool_result":
                found = calls.get(str(block.get("tool_use_id")))
                if found is not None:
                    found.result = _result_text(block.get("content"))[:MAX_RESULT]
                    found.is_error = bool(block.get("is_error"))


def _parse_lines(lines: Iterable[str], path: str) -> List[Call]:
    calls: Dict[str, Call] = {}
    order: List[str] = []
    _absorb(lines, path, calls, order)
    return [calls[i] for i in order]


class _Parsed:
    """One transcript as parsed so far: complete lines up to ``offset``."""

    __slots__ = ("inode", "offset", "calls", "order")

    def __init__(self, inode: int) -> None:
        self.inode = inode
        self.offset = 0
        self.calls: Dict[str, Call] = {}
        self.order: List[str] = []


class TranscriptIndex:
    """Parsed transcript files, kept between requests and read incrementally."""

    def __init__(self) -> None:
        self._files: Dict[str, _Parsed] = {}
        self._listing: Tuple[float, str, List[Tuple[float, int, str]]] = (0.0, "", [])
        self._lock = threading.Lock()

    def calls_in(self, path: str) -> List[Call]:
        """Every call in ``path``. Transcripts only grow, so a file seen before
        is read from where the last read stopped; a shorter or replaced file is
        read again from the start."""
        try:
            st = os.stat(path)
        except OSError:
            return []
        with self._lock:
            parsed = self._files.get(path)
        if parsed is None or parsed.inode != st.st_ino or st.st_size < parsed.offset:
            parsed = _Parsed(st.st_ino)
        if st.st_size > parsed.offset:
            try:
                with open(path, "rb") as fh:
                    fh.seek(parsed.offset)
                    chunk = fh.read()
            except OSError:
                return [parsed.calls[i] for i in parsed.order]
            complete = chunk.rfind(b"\n") + 1  # a half-written last line waits
            lines = chunk[:complete].decode("utf-8", errors="replace").splitlines()
            _absorb(lines, path, parsed.calls, parsed.order)
            parsed.offset += complete
        with self._lock:
            self._files[path] = parsed
        return [parsed.calls[i] for i in parsed.order]

    def listing(self, root: str) -> List[Tuple[float, int, str]]:
        """(mtime, size, path) for every transcript under ``root``, newest first."""
        with self._lock:
            made, made_root, files = self._listing
        if made_root == root and time.monotonic() - made < FILE_LIST_TTL:
            return files
        out: List[Tuple[float, int, str]] = []
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                if name.endswith(".jsonl"):
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    out.append((st.st_mtime, st.st_size, path))
        out.sort(reverse=True)
        with self._lock:
            self._listing = (time.monotonic(), root, out)
        return out

    def recent(self, root: str, limit: int) -> Tuple[List[Call], int]:
        """The newest ``limit`` calls, and how many files were read for them."""
        calls: List[Call] = []
        read = 0
        files = 0
        for _mtime, size, path in self.listing(root):
            if len(calls) >= limit or read >= BYTE_BUDGET:
                break
            calls.extend(self.calls_in(path))
            read += size
            files += 1
        calls.sort(key=lambda c: c.ts, reverse=True)
        return calls[:limit], files

    def find(self, root: str, call_id: str, session: Optional[str] = None,
             ts: Optional[float] = None) -> Tuple[Optional[Call], int]:
        """The call with ``call_id``: in its session's files when the session is
        known, else in transcripts written at or after ``ts``."""
        if session:
            candidates = glob.glob(os.path.join(glob.escape(root), "*", glob.escape(session) + ".jsonl"))
            candidates += glob.glob(os.path.join(glob.escape(root), "*", glob.escape(session), "subagents", "*.jsonl"))
        else:
            floor = (ts or 0) - 300
            candidates = [p for m, _s, p in self.listing(root) if m >= floor][:300]
        needle = call_id.encode("utf-8")
        searched = 0
        for path in candidates:
            searched += 1
            try:
                with open(path, "rb") as fh:
                    if needle not in fh.read():
                        continue
            except OSError:
                continue
            for call in self.calls_in(path):
                if call.call_id == call_id:
                    return call, searched
        return None, searched


INDEX = TranscriptIndex()


# --- calls as events ------------------------------------------------------------------


def events_of(call: Call) -> Tuple[List[Any], Optional[Any]]:
    """The call-phase events and the result event, built by the hook adapter."""
    from ..adapters import get_adapter
    from ..adapters.base import result_event

    adapter = get_adapter("claude-code")
    pre = adapter.parse({"hook_event_name": "PreToolUse", "session_id": call.session, "cwd": call.cwd,
                         "tool_name": call.tool, "tool_input": call.input, "tool_use_id": call.call_id})
    result = None
    if call.result is not None:
        post = adapter.parse({"hook_event_name": "PostToolUse", "session_id": call.session,
                              "cwd": call.cwd, "tool_name": call.tool, "tool_input": call.input,
                              "tool_response": call.result, "tool_use_id": call.call_id})
        result = result_event(post)
    return list(pre.events or []), result


def mask(value: Any, depth: int = 0) -> Any:
    from ..detectors.tool_output_secret_redactor import redact_text

    if isinstance(value, str):
        return redact_text(value)[0]
    if depth < 8 and isinstance(value, dict):
        return {k: mask(v, depth + 1) for k, v in value.items()}
    if depth < 8 and isinstance(value, list):
        return [mask(v, depth + 1) for v in value]
    return value


_TARGET_KEYS = ("file_path", "notebook_path", "path", "command", "url", "pattern", "query",
                "description", "prompt", "skill", "subject")


def target_of(call: Call) -> str:
    """One line naming what the call acted on: the file, the command, the URL."""
    for key in _TARGET_KEYS:
        value = call.input.get(key)
        if isinstance(value, list):
            value = " ".join(map(str, value))
        if isinstance(value, str) and value.strip():
            text = mask(" ".join(value.split()))
            return text if len(text) <= 240 else text[:238] + "…"
    return ""


# --- receipts for calls ---------------------------------------------------------------

_receipts_cache: Dict[str, Tuple[int, Dict[str, List[Dict[str, Any]]]]] = {}


def receipts_by_call(handler: Any) -> Dict[str, List[Dict[str, Any]]]:
    from .audit import _read_receipts

    path = getattr(handler.server, "receipts_path", None)
    if not path or not os.path.exists(path):
        return {}
    size = os.path.getsize(path)
    hit = _receipts_cache.get(path)
    if hit and hit[0] == size:
        return hit[1]
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in _read_receipts(path):
        if not r.get("unreadable") and r.get("call_id"):
            out.setdefault(r["call_id"], []).append(
                {k: r.get(k) for k in ("index", "ts", "phase", "verdict", "policy_verdict", "policy_id",
                                      "reason", "approval", "observed", "args_digest", "masked")})
    _receipts_cache[path] = (size, out)
    return out


def _actual(receipts: List[Dict[str, Any]], phase: str) -> Optional[Dict[str, Any]]:
    """What the guard decided for one phase of a call (the enforced receipt)."""
    hits = [r for r in receipts if r.get("phase") == phase and not r.get("observed")]
    return hits[-1] if hits else None


def _verdict_of(row: Optional[Dict[str, Any]]) -> Optional[str]:
    if row is None:
        return None
    return row.get("policy_verdict") or row.get("verdict")


def summary_of(call: Call, receipts: List[Dict[str, Any]], *, with_result: bool) -> Dict[str, Any]:
    events, result = events_of(call)
    out: Dict[str, Any] = {
        "call_id": call.call_id, "ts": call.ts, "tool": call.tool, "target": target_of(call),
        "cwd": call.cwd, "session": call.session, "subagent": call.subagent,
        "args": mask(events[0].args if events else call.input),
        "has_result": call.result is not None, "is_error": call.is_error,
        "result_len": len(call.result or ""),
        "receipts": [{k: r.get(k) for k in ("index", "phase", "verdict", "policy_verdict", "policy_id")}
                     for r in receipts],
    }
    if with_result and result is not None:
        out["result"] = mask(result.args)
    return out


# --- routes ---------------------------------------------------------------------------


def _qs(handler: Any) -> Dict[str, List[str]]:
    return parse_qs(urlsplit(handler.path).query)


def _int(qs: Dict[str, List[str]], name: str, default: int) -> int:
    try:
        return max(1, min(MAX_LIMIT, int((qs.get(name) or [default])[0])))
    except ValueError:
        raise ApiError(400, "bad_query", "{} must be a number".format(name))


@handles_errors
def _list_calls(handler: Any) -> Tuple[int, dict]:
    qs = _qs(handler)
    root = _root(handler)
    if not os.path.isdir(root):
        return 200, {"root": root, "available": False, "calls": [], "tools": {}}
    limit = _int(qs, "limit", 200)
    tool = (qs.get("tool") or [""])[0]
    text = (qs.get("q") or [""])[0].strip().lower()
    calls, files = INDEX.recent(root, MAX_LIMIT if (tool or text) else limit)
    tools: Dict[str, int] = {}
    for c in calls:
        tools[c.tool] = tools.get(c.tool, 0) + 1
    if tool:
        calls = [c for c in calls if c.tool == tool]
    if text:
        calls = [c for c in calls if text in (c.tool + " " + target_of(c) + " " + (c.cwd or "")).lower()]
    by_call = receipts_by_call(handler)
    rows = [summary_of(c, by_call.get(c.call_id, []), with_result=True) for c in calls[:limit]]
    return 200, {"root": root, "available": True, "files": files, "calls": rows,
                 "tools": dict(sorted(tools.items(), key=lambda kv: -kv[1]))}


@handles_errors
def _one_call(handler: Any) -> Tuple[int, dict]:
    from ..receipt import digest_args

    call_id = handler.path_tail.strip("/")
    if not call_id:
        raise ApiError(404, "not_found", "no such API path")
    qs = _qs(handler)
    session = (qs.get("session") or [None])[0]
    try:
        ts = float((qs.get("ts") or ["0"])[0])
    except ValueError:
        ts = 0.0
    root = _root(handler)
    call, searched = INDEX.find(root, call_id, session, ts)
    receipts = receipts_by_call(handler).get(call_id, [])
    if call is None:
        return 200, {"found": False, "call_id": call_id, "searched": searched, "root": root,
                     "receipts": receipts}
    events, result = events_of(call)
    digest = digest_args(events[0].args) if events else None
    recorded = _actual(receipts, "call")
    return 200, {
        "found": True, "call_id": call_id, "tool": call.tool, "target": target_of(call),
        "ts": call.ts, "cwd": call.cwd, "session": call.session, "subagent": call.subagent,
        "transcript": call.file, "args": mask(events[0].args if events else call.input),
        "result": mask(call.result) if call.result is not None else None,
        "result_len": len(call.result or ""), "is_error": call.is_error,
        "digest": {"computed": digest, "receipt": recorded.get("args_digest") if recorded else None,
                   "match": (digest == recorded.get("args_digest")) if (recorded and digest) else None},
        "receipts": receipts,
    }


def _decide(engine: Any, events: List[Any]) -> Tuple[str, Optional[str], str]:
    """One verdict for a call's events, the way the hook combines them."""
    from ..adapters.base import combine

    decisions = []
    for ev in events:
        try:
            decisions.append(engine.evaluate(ev))
        except Exception as exc:  # a rule that raises blocks, as at the hook
            from ..enforce import Decision
            decisions.append(Decision.block("rule error: {}".format(type(exc).__name__), "rule_error"))
    if not decisions:
        return "ALLOW", None, ""
    d = combine(decisions)
    return d.verdict.name, d.policy_id, d.reason or ""


@handles_errors
def _backtest(handler: Any) -> Tuple[int, dict]:
    """Run a policy - the draft in the body, or the saved file - over recent real calls."""
    from ..policy import declarative as dl
    from .policy_api import _policy_path, _read

    body = read_json_body(handler)
    limit = max(1, min(MAX_LIMIT, int(body.get("limit") or DEFAULT_LIMIT)))
    path = _policy_path(handler)
    text = body.get("text")
    source = "draft" if isinstance(text, str) else "saved"
    if not isinstance(text, str):
        _, text, _ = _read(path)
    try:
        doc = dl.parse_policy_text(text, source=path)
        engine = dl.load_policy(doc, source=path, base_dir=os.path.dirname(path))
    except dl.PolicyError as exc:
        raise ApiError(400, "does_not_load", str(exc).replace(path + ": ", "", 1))
    root = _root(handler)
    if not os.path.isdir(root):
        raise ApiError(404, "no_transcripts", "no Claude Code transcripts at {}".format(root))
    started = time.monotonic()
    calls, files = INDEX.recent(root, limit)
    by_call = receipts_by_call(handler)
    counts = {"ALLOW": 0, "MODIFY": 0, "BLOCK": 0, "ESCALATE": 0}
    changed = unrecorded = recorded = 0
    rows: List[Dict[str, Any]] = []
    for call in calls:
        events, result = events_of(call)
        receipts = by_call.get(call.call_id, [])
        for phase, evs in (("call", events), ("result", [result] if result is not None else [])):
            if not evs:
                continue
            verdict, policy_id, reason = _decide(engine, evs)
            counts[verdict] = counts.get(verdict, 0) + 1
            actual_row = _actual(receipts, phase)
            actual = _verdict_of(actual_row)
            if actual is None:
                if phase == "call" and not receipts:
                    unrecorded += 1
                status = "unrecorded"
            else:
                recorded += 1 if phase == "call" else 0
                status = "same" if actual == verdict else "changed"
                changed += status == "changed"
            if status == "changed" or (status == "unrecorded" and verdict != "ALLOW"):
                rows.append({
                    "call_id": call.call_id, "ts": call.ts, "tool": call.tool, "target": target_of(call),
                    "session": call.session, "phase": phase, "status": status,
                    "would": {"verdict": verdict, "policy_id": policy_id, "reason": mask(reason)},
                    "actual": {"verdict": actual, "policy_id": actual_row.get("policy_id"),
                               "index": actual_row.get("index")} if actual_row else None,
                })
    rows.sort(key=lambda r: (r["status"] != "changed", -r["ts"]))
    return 200, {
        "source": source, "epoch": engine.epoch, "calls": len(calls), "files": files,
        "would": counts, "recorded": recorded, "changed": changed, "unrecorded": unrecorded,
        "rows": rows[:300], "truncated": len(rows) > 300,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


@handles_errors
def _sweep(handler: Any) -> Tuple[int, dict]:
    """Every catalog detector, at its defaults, over recent real calls."""
    import importlib

    from ..policy.engine import PolicyEngine
    from .catalog import build_catalog

    body = read_json_body(handler)
    limit = max(1, min(MAX_LIMIT, int(body.get("limit") or 200)))
    root = _root(handler)
    if not os.path.isdir(root):
        raise ApiError(404, "no_transcripts", "no Claude Code transcripts at {}".format(root))
    started = time.monotonic()
    calls, _files = INDEX.recent(root, limit)
    prepared = []
    for call in calls:
        events, result = events_of(call)
        prepared.append((call, events + ([result] if result is not None else [])))
    detectors, skipped = [], []
    for det in build_catalog()["detectors"]:
        module = importlib.import_module("interlock.detectors." + det["module"])
        for factory in det["factories"]:
            needs = [p["name"] for p in factory["params"] if p["required"]]
            if needs:
                skipped.append({"module": det["module"], "factory": factory["name"], "needs": needs})
                continue
            try:
                engine = PolicyEngine([getattr(module, factory["name"])()])
            except Exception as exc:
                skipped.append({"module": det["module"], "factory": factory["name"],
                                "needs": [], "error": type(exc).__name__})
                continue
            verdicts: Dict[str, int] = {}
            examples: List[Dict[str, Any]] = []
            errors = 0
            for call, events in prepared:
                for ev in events:
                    try:
                        d = engine.evaluate(ev)
                    except Exception:
                        errors += 1
                        continue
                    if d.verdict.name == "ALLOW":
                        continue
                    verdicts[d.verdict.name] = verdicts.get(d.verdict.name, 0) + 1
                    if len(examples) < 5:
                        examples.append({"call_id": call.call_id, "ts": call.ts, "tool": call.tool,
                                         "target": target_of(call), "phase": ev.phase,
                                         "verdict": d.verdict.name, "reason": mask(d.reason or ""),
                                         "session": call.session})
            detectors.append({"module": det["module"], "factory": factory["name"],
                              "fired": sum(verdicts.values()), "verdicts": verdicts,
                              "errors": errors, "examples": examples})
    detectors.sort(key=lambda d: (-d["fired"], d["module"]))
    return 200, {"calls": len(prepared), "events": sum(len(e) for _, e in prepared),
                 "detectors": detectors, "skipped": skipped,
                 "elapsed_ms": round((time.monotonic() - started) * 1000)}


ROUTES["/api/calls"] = {"GET": _list_calls}
PREFIX_ROUTES["/api/calls/"] = {"GET": _one_call}
ROUTES["/api/policy/backtest"] = {"POST": _backtest}
ROUTES["/api/detectors/sweep"] = {"POST": _sweep}
