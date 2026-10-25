"""Record a receipt log's head outside it, and verify the log still reaches it.

  interlock anchor audit.jsonl --key-file audit.key            # verify, then record
  interlock anchor audit.jsonl --key-file audit.key --check    # is it still there?
  interlock anchor audit.jsonl --key-file audit.key --out /mnt/worm/audit.anchor --json

A hash chain catches edits, deletions and reordering inside a log, but a log
with its last receipts removed is still a valid, shorter chain. The anchor
closes that: it records the last mac and the receipt count in a small signed
file *outside* the log, on storage the log's writer cannot reach (a WORM
volume, another host, a committed git repository).

`record` verifies the chain first, then refuses to move backwards - the log
must still contain the receipt the existing anchor names at the same position,
and must not be shorter than the anchored count. So a rolled-back log cannot
bless itself by re-anchoring. `--check` is the same comparison without
writing, and accepts a log that has grown since the anchor.

Exit codes: 0 the log reaches its anchor, 2 the chain or the anchor is broken,
3 a file could not be read, 64 bad arguments.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from typing import Any, Dict, List, Optional

#: The anchor document's schema; bumped only on an incompatible change.
ANCHOR_VERSION = 1


class AnchorError(ValueError):
    """An anchor that is unreadable, edited, or belongs to another log."""


def default_anchor_path(log: str) -> str:
    return log + ".anchor"


def _anchor_mac(key: bytes, doc: Dict[str, Any]) -> str:
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def read_anchor(path: str, key: bytes) -> Optional[Dict[str, Any]]:
    """The anchor at ``path``, or None when it does not exist yet."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(65536)
    except FileNotFoundError:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AnchorError("{} is not valid JSON; refusing to use it".format(path))
    fields = ("version", "log", "count", "head", "ts")
    if (not isinstance(doc, dict) or any(name not in doc for name in fields)
            or doc["version"] != ANCHOR_VERSION or not isinstance(doc["log"], str)
            or not isinstance(doc["count"], int) or doc["count"] < 0
            or not (doc["head"] is None or isinstance(doc["head"], str))
            or not isinstance(doc["ts"], (int, float)) or not isinstance(doc.get("mac"), str)):
        raise AnchorError("{} is not a readable anchor; refusing to use it".format(path))
    expected = _anchor_mac(key, {name: doc[name] for name in fields})
    if not hmac.compare_digest(doc["mac"], expected):
        raise AnchorError(
            "{} does not match its signature: it was signed with another key or edited"
            .format(path))
    return doc


def _write_anchor(path: str, doc: Dict[str, Any]) -> None:
    """Replace the anchor atomically, mode 0600, never leaving a half file."""
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = os.path.join(directory, ".anchor-{}-{}".format(os.getpid(), secrets.token_hex(4)))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            os.unlink(tmp)
            raise
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise AnchorError("cannot write {}: {}".format(path, exc))


def _prefix_problem(anchor: Dict[str, Any], log: str, receipts: List[Any],
                    path: str) -> Optional[str]:
    """Why the log no longer reaches the anchor, or None when it still does."""
    if anchor["log"] != log:
        return ("the anchor at {} belongs to {}, not {}: point --out at this log's own anchor"
                .format(path, anchor["log"], log))
    count = int(anchor["count"])
    if count > len(receipts):
        return ("the log is shorter than its anchor: {} receipt(s) anchored at {}, {} present - "
                "the tail was truncated or an older copy was restored"
                .format(count, _when(anchor["ts"]), len(receipts)))
    if count and receipts[count - 1].mac != anchor["head"]:
        return ("receipt {} is not the one the anchor records: the log was rewritten or rolled "
                "back".format(count))
    return None


def _when(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def add_arguments(parser) -> None:
    parser.add_argument("file", help="a receipt log written by FileSink")
    parser.add_argument("--key-file", required=True, metavar="FILE",
                        help="the MAC key that signed the log (and this anchor)")
    parser.add_argument("--out", metavar="FILE",
                        help="where to keep the anchor (default: <log>.anchor). Put it on "
                             "storage the log's writer cannot reach")
    parser.add_argument("--check", action="store_true",
                        help="verify against the recorded anchor instead of writing a new one")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def run(args) -> int:
    from ..report import read_receipts, verification
    from ..sidecar.__main__ import _read_key
    from ..sidecar.rules import RulesError

    try:
        key = _read_key(args.key_file)
    except (OSError, RulesError) as exc:
        sys.stderr.write("interlock anchor: {}\n".format(exc))
        return 3
    try:
        receipts, bad = read_receipts(args.file)
    except OSError as exc:
        sys.stderr.write("interlock anchor: cannot read {}: {}\n".format(args.file, exc))
        return 3
    if bad:
        sys.stderr.write("interlock anchor: line {} of {} is not a receipt; repair or move the "
                         "log aside\n".format(bad[0], args.file))
        return 2
    check = verification(receipts, key=key)
    if check["status"] != "verified":
        sys.stderr.write("interlock anchor: the chain is broken: {}\n".format(check["detail"]))
        return 2

    log = os.path.abspath(args.file)
    out = args.out or default_anchor_path(args.file)
    try:
        anchor = read_anchor(out, key)
    except AnchorError as exc:
        sys.stderr.write("interlock anchor: {}\n".format(exc))
        return 2
    except OSError as exc:
        sys.stderr.write("interlock anchor: cannot read {}: {}\n".format(out, exc))
        return 3
    if anchor is not None:
        problem = _prefix_problem(anchor, log, receipts, out)
        if problem is not None:
            sys.stderr.write("interlock anchor: {}\n".format(problem))
            return 2

    delay = "" if anchor is None else ", {} receipt(s) since the anchor".format(
        len(receipts) - int(anchor["count"]))
    head = receipts[-1].mac if receipts else None
    if args.check:
        if anchor is None:
            sys.stderr.write("interlock anchor: no anchor at {}; record one first\n".format(out))
            return 2
        if args.json:
            print(json.dumps({"status": "intact", "log": log, "count": len(receipts),
                              "anchored": anchor["count"], "anchor": out}))
        else:
            print("intact: {} receipt(s){}; anchored {} at {}".format(
                len(receipts), delay, anchor["count"], _when(anchor["ts"])))
        return 0

    doc = {"version": ANCHOR_VERSION, "log": log, "count": len(receipts), "head": head,
           "ts": time.time()}
    doc["mac"] = _anchor_mac(key, doc)
    try:
        _write_anchor(out, doc)
    except AnchorError as exc:
        sys.stderr.write("interlock anchor: {}\n".format(exc))
        return 3
    if args.json:
        print(json.dumps(dict(doc, status="anchored")))
    else:
        print("anchored {} receipt(s) at {}{} -> {}".format(
            len(receipts), head[:12] + "..." if head else "nothing", delay, out))
    return 0
