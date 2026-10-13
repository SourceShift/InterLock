"""Summarize a receipt log: what interlock blocked, rewrote and escalated, what
monitor mode would have done, how long evaluation took, and whether any
receipts were lost.

  interlock report audit.jsonl --key-file audit.key
  interlock report audit.jsonl --since 24h --monitor     # "would have blocked"
  interlock report audit.jsonl --json

The chain is verified first when --key-file is given; the report always says
whether it was. Receipts hold argument digests, never values.

Exit codes: 0 ok, 2 the chain is broken, 3 the log could not be read.
"""
from __future__ import annotations

import sys


def add_arguments(parser) -> None:
    parser.add_argument("file", help="a receipt log written by FileSink")
    parser.add_argument("--since", default=None, metavar="DURATION",
                        help="only receipts newer than this: 30m, 24h, 7d (default: all)")
    parser.add_argument("--monitor", action="store_true",
                        help="show what monitor mode would have blocked or rewritten")
    parser.add_argument("--top", type=int, default=10, metavar="N", help="rows per table")
    parser.add_argument("--key-file", metavar="FILE", help="the MAC key, to verify the chain")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def run(args) -> int:
    from ..report import parse_since, read_receipts, render, summarize, to_json, verification

    try:
        since = parse_since(args.since)
    except ValueError as exc:
        sys.stderr.write("interlock report: {}\n".format(exc))
        return 64
    try:
        receipts, bad = read_receipts(args.file)
    except OSError as exc:
        sys.stderr.write("interlock report: cannot read {}: {}\n".format(args.file, exc))
        return 3
    key = None
    if args.key_file:
        from ..sidecar.__main__ import _read_key
        from ..sidecar.rules import RulesError
        try:
            key = _read_key(args.key_file)
        except RulesError as exc:
            sys.stderr.write("interlock report: {}\n".format(exc))
            return 3
    verified = verification(receipts, key=key)
    if bad:
        verified = {"status": "broken",
                    "detail": "line {} is not a receipt ({} unreadable line(s))".format(
                        bad[0], len(bad))}
    summary = summarize(receipts, since_seconds=since, top=args.top)
    if args.json:
        sys.stdout.write(to_json(summary, verified) + "\n")
    else:
        from . import use_color
        sys.stdout.write(render(summary, verified, monitor=args.monitor,
                                color=use_color(flag=False if args.no_color else None)) + "\n")
    return 2 if verified["status"] == "broken" else 0
