"""Draft a reviewable policy from a receipt log: the actions your guard
actually allowed, and an escalation for everything else.

  interlock learn --receipts audit.jsonl --out baseline.json
  interlock learn --receipts audit.jsonl --out baseline.json --name acme-baseline

Reads a receipt log written by FileSink, keeps the actions observed with an
ALLOW verdict (matched case-insensitively), and writes a declarative policy
whose single rule escalates any action outside that envelope. The draft is
deterministic - two runs over the same log are byte-identical - so a diff
between two drafts is worth reviewing.

It is never auto-enforced: this command only writes the file you name. It
installs nothing, enables nothing, locks nothing and emits no `block` rule.
Review it with `interlock policy check` and install it on purpose.

Exit codes: 0 wrote the policy, 3 the log could not be read, held no
ALLOW-observed receipt, or the output could not be written (no file is written
in those cases); 64 the command line was wrong.
"""
from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_UNUSABLE = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    parser.add_argument("--receipts", metavar="FILE", default=None,
                        help="a receipt log written by FileSink (required)")
    parser.add_argument("--out", metavar="FILE", default=None,
                        help="where to write the draft policy (required)")
    parser.add_argument("--name", metavar="NAME", default=None,
                        help="the policy 'name' field (default: learned-behavioural-baseline)")


def run(args) -> int:
    from .. import learn as learn_lib

    if not args.receipts or not args.out:
        sys.stderr.write("interlock learn: --receipts and --out are required\n")
        return EXIT_USAGE
    name = args.name or learn_lib.DEFAULT_NAME
    try:
        doc, baseline = learn_lib.learn(args.receipts, name=name)
    except OSError as exc:
        sys.stderr.write("interlock learn: cannot read {}: {}\n".format(args.receipts, exc))
        return EXIT_UNUSABLE
    if doc is None:
        detail = ""
        if baseline.excluded:
            detail = " (excluded: {})".format(_describe(baseline.excluded))
        sys.stderr.write("interlock learn: {} holds no ALLOW-observed receipt{}; "
                         "no policy written\n".format(args.receipts, detail))
        return EXIT_UNUSABLE
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        sys.stderr.write("interlock learn: cannot write {}: {}\n".format(args.out, exc))
        return EXIT_UNUSABLE
    sys.stdout.write("interlock learn: {} allowed receipt(s), {} observed action(s); "
                     "wrote {} (review it before installing)\n".format(
                         baseline.total, len(baseline.actions), args.out))
    return EXIT_OK


def _describe(excluded) -> str:
    return ", ".join("{} {}".format(count, label) for label, count in sorted(excluded.items()))
