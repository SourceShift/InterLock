"""Derive a capability scope from the receipts your guard already wrote.

  interlock scope suggest --from-receipts audit.jsonl --out scope.json
  interlock scope suggest --from-receipts audit.jsonl --since 30d \\
      --out scope.json --key-file audit.key
  interlock scope suggest --from-receipts audit.jsonl --existing scope.json \\
      --out scope.json

Reads a receipt log written by FileSink, keeps what each principal (its scope
path, split on '/') was allowed to do, and writes a scope document binding the
`action_envelope` template to exactly those actions, with the receipt count
behind each one. Serve it with:

  interlock sidecar --rules interlock.policy.capability:rules \\
      --scope-document scope.json --key-file audit.key

The draft is deterministic - two runs over the same log are byte-identical - and
never wide by accident: `--existing` compares the draft against a scope document
you already serve and refuses (exit 2) when it would grant an action that
document does not allow; pass --allow-widen to accept a widening you meant.

The derived capability is an *action* envelope. Receipts store argument digests,
never values, so a log cannot yield a set of paths, hosts or program names - it
cannot know them. Those belong in bindings you write by hand.

Exit codes: 0 wrote the document, 2 the draft was refused (it would widen the
existing scope) or the existing document is not a scope document, 3 the log
could not be read, held no scoped ALLOW receipt, or the output was not written,
64 the command line was wrong.
"""
from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_UNUSABLE = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    suggest = parser.add_subparsers(dest="scope_command", metavar="ACTION")
    suggest.required = True
    run = suggest.add_parser(
        "suggest", help="derive a capability scope document from a receipt log")
    run.add_argument("--from-receipts", required=True, metavar="FILE",
                     help="a receipt log written by FileSink (required)")
    run.add_argument("--out", required=True, metavar="FILE",
                     help="where to write the scope document (required)")
    run.add_argument("--since", metavar="WINDOW", default=None,
                     help="only receipts from this window, e.g. 30d (default: all)")
    run.add_argument("--min-count", type=int, default=1, metavar="N",
                     help="drop actions seen fewer than N times (default: 1)")
    run.add_argument("--existing", metavar="FILE", default=None,
                     help="a scope document the draft must not widen")
    run.add_argument("--allow-widen", action="store_true",
                     help="accept a draft that grants more than --existing allows")
    run.add_argument("--key-file", metavar="FILE", default=None,
                     help="sign the document for `interlock sidecar`, as it publishes one")


def run(args) -> int:
    from .. import scope_suggest
    from ..report import parse_since

    if args.min_count < 1:
        sys.stderr.write("interlock scope suggest: --min-count must be 1 or more\n")
        return EXIT_USAGE
    try:
        since = parse_since(args.since)
    except ValueError as exc:
        sys.stderr.write("interlock scope suggest: {}\n".format(exc))
        return EXIT_USAGE

    existing = None
    if args.existing:
        try:
            existing = scope_suggest.read_document(args.existing)
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock scope suggest: cannot use {}: {}\n".format(
                args.existing, exc))
            return EXIT_UNUSABLE

    try:
        document, envelope, problems = scope_suggest.suggest(
            args.from_receipts, since_seconds=since, min_count=args.min_count,
            existing=existing, allow_widen=args.allow_widen)
    except OSError as exc:
        sys.stderr.write("interlock scope suggest: cannot read {}: {}\n".format(
            args.from_receipts, exc))
        return EXIT_UNUSABLE
    except ValueError as exc:
        sys.stderr.write("interlock scope suggest: {}: {}\n".format(
            args.from_receipts, exc))
        return EXIT_UNUSABLE

    if document is None:
        if problems:
            sys.stderr.write(
                "interlock scope suggest: refused, the draft would widen {}; "
                "nothing written\n".format(args.existing))
            for problem in problems:
                sys.stderr.write("  {}\n".format(problem))
            sys.stderr.write(
                "  rerun with --allow-widen to accept the widening, or review why "
                "these actions ran\n")
            return EXIT_REFUSED
        detail = ""
        if envelope.excluded:
            detail = " (excluded: {})".format(_describe(envelope.excluded))
        sys.stderr.write(
            "interlock scope suggest: {} holds no scoped ALLOW receipt{}; no "
            "document written\n".format(args.from_receipts, detail))
        return EXIT_UNUSABLE

    key = None
    if args.key_file:
        key = _read_key(args.key_file)
        if key is None:
            return EXIT_UNUSABLE

    if key is not None:
        # Sign it the way the daemon publishes a scope document, so
        # `interlock sidecar --scope-document` verifies this exact file.
        from ..wire import scope_envelope

        output = json.dumps(scope_envelope(document, key)) + "\n"
    else:
        output = scope_suggest.render(document)

    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    except OSError as exc:
        sys.stderr.write("interlock scope suggest: cannot write {}: {}\n".format(
            args.out, exc))
        return EXIT_UNUSABLE

    drawn = ", ".join(
        "{}={}".format(action, count)
        for scope in envelope.scopes
        for action, count in sorted(envelope.counts[scope].items())
        if count >= args.min_count)
    sys.stdout.write(
        "interlock scope suggest: {} allowed receipt(s), {} scope(s), {} observed "
        "action(s) [{}]; wrote {}{}\n".format(
            envelope.total, len(document["bindings"]),
            sum(len(entry.get("observed") or {})
                for entries in document["bindings"].values() for entry in entries),
            drawn or "none", args.out,
            " (signed)" if key is not None else " (unsigned)"))
    if problems:
        sys.stderr.write("interlock scope suggest: accepted a widening ("
                         "--allow-widen):\n")
        for problem in problems:
            sys.stderr.write("  {}\n".format(problem))
    sys.stdout.write("interlock scope suggest: review it before serving it\n")
    return EXIT_OK


def _read_key(path: str):
    """The MAC key at *path*, or None after saying why it could not be read."""
    from ..sidecar.__main__ import _read_key as read
    from ..sidecar.rules import RulesError

    try:
        return read(path)
    except (OSError, RulesError) as exc:
        sys.stderr.write("interlock scope suggest: {}\n".format(exc))
        return None


def _describe(excluded) -> str:
    return ", ".join("{} {}".format(count, label) for label, count in sorted(excluded.items()))
