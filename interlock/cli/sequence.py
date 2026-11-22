"""Seed a sequence journal from a receipt log, so a restart keeps its history.

  interlock sequence hydrate --log audit.jsonl --state /var/lib/interlock/seq.db
  interlock sequence hydrate --log audit.jsonl --state /var/lib/interlock/seq.db \\
      --window 20

The `sequence_guard` detector refuses a call that completes a forbidden
`[before, after]` pair - read a secret, then reach the network - by recalling
the last `window` actions of a run. Given an absolute `state` path that history
survives the process (see the policies guide), but not a restart or a fresh
install: the file begins empty, so the first `http_post` of the day is judged
against nothing.

The receipt log is the older record. This command replays it into the journal:
every `phase="call"` receipt whose action normalises to a non-empty name is
journalled under the same scope the live guard uses (`span_id`, else
`principal`, else `<anon>`), in log order, and each scope keeps only its newest
`window` actions. The replay *replaces* the journal rather than appending, so
running it twice over one log gives the same result.

Only action names and scope identities are copied - a receipt carries no
arguments, and the journal stores none either. A verdict does not filter the
replay: the live guard journals a call whether the rule then allowed, escalated
or blocked it, so a blocked `after` stays blocked.

Exit codes: 0 the journal was seeded, 3 the log or the state path could not be
used, 64 the command line was wrong.
"""
from __future__ import annotations

import sqlite3
import sys

EXIT_OK = 0
EXIT_UNUSABLE = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    commands = parser.add_subparsers(dest="sequence_command", metavar="ACTION")
    hydrate = commands.add_parser(
        "hydrate", help="replay a receipt log into a sequence journal")
    hydrate.add_argument("--log", required=True, metavar="FILE",
                         help="a receipt log written by FileSink (required)")
    hydrate.add_argument("--state", required=True, metavar="FILE",
                         help="the absolute journal path the rule's state= names "
                              "(required)")
    hydrate.add_argument("--window", type=int, default=50, metavar="N",
                         help="actions kept per scope, matching the rule "
                              "(default: 50)")
    hydrate.add_argument("--max-scopes", type=int, default=1024, metavar="N",
                         help="scopes tracked, matching the rule (default: 1024)")


def _positive(name: str, value: int) -> int:
    if isinstance(value, bool) or value <= 0:
        raise ValueError("{} must be a positive integer".format(name))
    return value


def run(args) -> int:
    if getattr(args, "sequence_command", None) != "hydrate":
        sys.stderr.write("interlock sequence: choose an action: hydrate\n")
        return EXIT_USAGE

    from .._sqlite import check_state_path
    from ..actions import canonical_action
    from ..obligations import subject_of
    from ..report import read_receipts
    from ..sequence_ledger import JournalLedger

    try:
        window = _positive("--window", args.window)
        max_scopes = _positive("--max-scopes", args.max_scopes)
        # The same rule the detector applies: a relative path would resolve
        # against whichever directory the seed was run from and leave the
        # guard reading a different file.
        state = check_state_path(args.state)
        if state is None:
            raise ValueError("--state is required")
    except ValueError as exc:
        sys.stderr.write("interlock sequence hydrate: {}\n".format(exc))
        return EXIT_USAGE

    try:
        receipts, bad = read_receipts(args.log)
    except OSError as exc:
        sys.stderr.write("interlock sequence hydrate: cannot read {}: {}\n".format(
            args.log, exc))
        return EXIT_UNUSABLE

    entries = []
    for receipt in receipts:
        if getattr(receipt, "phase", "call") != "call":
            continue
        action = canonical_action(getattr(receipt, "action", None))
        if action:
            entries.append((subject_of(receipt), action))

    try:
        ledger = JournalLedger(state)
        written = ledger.seed(entries, window=window, max_scopes=max_scopes)
    except (OSError, ValueError, sqlite3.Error) as exc:
        sys.stderr.write("interlock sequence hydrate: {}\n".format(exc))
        return EXIT_UNUSABLE

    scopes = {scope for scope, _action in entries}
    if bad:
        sys.stderr.write(
            "interlock sequence hydrate: skipped {} unreadable line(s) in {}\n"
            .format(len(bad), args.log))
    sys.stdout.write(
        "interlock sequence hydrate: {} action(s) across {} scope(s) into {}\n"
        .format(written, len(scopes), args.state))
    return EXIT_OK
