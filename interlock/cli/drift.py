"""Diff a live surface's tool listing against a recorded corpus.

  interlock drift --corpus corpus.json --live "my-mcp-server --list-tools"
  interlock drift --corpus corpus.json --live "..." --surface demo
  interlock drift --corpus corpus.json --live "..." --json

The corpus records each covered surface's tool-listing fingerprint and schema
shapes (see ``interlock/drift.py``). ``--live`` runs a command and reads its
standard output as the live tool listing: one tool name per line, or one JSON
object per line when you also record schema shapes. ``--live`` is a shell
string, so a command with arguments or quoted paths works as written.

Every added tool, removed tool and changed schema shape is reported with a
severity, and any finding is drift. **Nothing is written back and nothing is
filed** - the corpus is only ever read - so the diff is a report you act on.

Exit codes: 0 no drift, 1 drift found, 64 the command line was wrong,
3 the corpus could not be read or the live command failed.
"""
from __future__ import annotations

import sys


def add_arguments(parser) -> None:
    parser.add_argument("--corpus", metavar="FILE",
                        help="the recorded corpus to diff against")
    parser.add_argument("--live", metavar="CMD",
                        help="a shell command whose stdout is the live tool listing")
    parser.add_argument("--surface", metavar="NAME",
                        help="which corpus surface the live command describes"
                             " (default: the corpus's only surface)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def run(args) -> int:
    import subprocess

    from ..drift import (LiveOutputError, diff, load_corpus, parse_live,
                         render, select_surface, to_json)

    if not args.corpus or not args.live:
        sys.stderr.write("interlock drift: --corpus FILE and --live CMD are required\n")
        return 64
    try:
        corpus = load_corpus(args.corpus)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock drift: cannot read {}: {}\n".format(args.corpus, exc))
        return 3
    try:
        surface = select_surface(corpus, args.surface)
    except ValueError as exc:
        sys.stderr.write("interlock drift: {}\n".format(exc))
        return 64

    # The shell string is the contract (the smoke passes "$PY $WORK/server.py"),
    # so run it through the shell rather than shlex-splitting it ourselves.
    completed = subprocess.run(args.live, shell=True, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()
        sys.stderr.write("interlock drift: live command failed ({}): {}\n".format(
            completed.returncode, detail or args.live))
        return 3
    try:
        live = parse_live(completed.stdout)
    except LiveOutputError as exc:
        sys.stderr.write("interlock drift: {}\n".format(exc))
        return 3

    report = diff(surface, live)
    if args.json:
        sys.stdout.write(to_json(report) + "\n")
    else:
        sys.stdout.write(render(report) + "\n")
    return 1 if report["drift"] else 0
