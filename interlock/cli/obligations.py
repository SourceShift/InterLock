"""Check a receipt log against obligations: what had to happen, by when.

  interlock obligations check --log audit.jsonl --obligations obligations.json
  interlock obligations check --log audit.jsonl --obligations obligations.json \\
      --json
  interlock obligations check --log audit.jsonl --obligations obligations.json \\
      --now now

Every other policy in interlock forbids an action. An obligation binds the
other way: "after `deploy`, an `approve` must be referenced within 600s" is
satisfied by doing nothing wrong and fails by *not* doing the follow-up. The
receipt log is enough to judge it - each receipt carries an action, a verdict
and a timestamp - so this command replays the log and reports each opening:

* `discharged` - the follow-up arrived inside the deadline;
* `breached` - it never arrived, or arrived late (a late one says so);
* `pending` - the deadline has not passed yet.

Obligations are a JSON list (or `{"obligations": [...]}`):

  [{"when": "deploy", "then": "approve", "within": 600},
   {"when": "env_secret_read", "then": "secret_rotate", "within": 3600,
    "approvals_only": true, "policy_id": "rotation"}]

`approvals_only` requires the follow-up receipt to carry an `approval`, so an
unreviewed call does not discharge it. Action names are canonicalised, so
`http.post` and `http_post` are the same step.

Receipts are grouped by the same scope the live guard uses - `span_id`, else
`principal`, else `<anon>` - so one run's deploy cannot be discharged by
another run's approval. Only receipts whose verdict means the call ran
(`ALLOW`/`MODIFY`) count: a `BLOCK` receipt records an action that never
happened, and an escalation still pending or declined is not an approval.

*--now* decides whether an open obligation has lapsed; it defaults to the
newest receipt's timestamp, so two checks over one log agree. Pass `--now now`
to judge against the wall clock instead.

Exit codes: 0 every obligation was kept or is still open, 1 at least one was
breached, 3 the log or the obligation file could not be used, 64 the command
line was wrong.
"""
from __future__ import annotations

import json
import sys

EXIT_OK = 0
EXIT_BREACH = 1
EXIT_UNUSABLE = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    commands = parser.add_subparsers(dest="obligations_command", metavar="ACTION")
    commands.required = True
    check = commands.add_parser(
        "check", help="replay a receipt log against obligations")
    check.add_argument("--log", required=True, metavar="FILE",
                       help="a receipt log written by FileSink (required)")
    check.add_argument("--obligations", required=True, metavar="FILE",
                       help="a JSON obligation list (required)")
    check.add_argument("--json", action="store_true",
                       help="print the verdict as JSON instead of one line each")
    check.add_argument("--now", metavar="TIME", default=None,
                       help="judge open obligations at an epoch second, or 'now' "
                            "(default: the newest receipt's timestamp)")


def _now(text):
    """The ``--now`` argument as an epoch second, or None for the log's clock."""
    if text is None:
        return None
    if text.strip().lower() == "now":
        import time

        return time.time()
    try:
        return float(text)
    except ValueError:
        raise ValueError("--now must be an epoch second or 'now', got {!r}".format(text))


def _load_obligations(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        spec = json.loads(text)
    except ValueError as exc:
        raise ValueError("{} is not JSON: {}".format(path, exc))
    from ..obligations import parse

    try:
        return parse(spec)
    except ValueError as exc:
        raise ValueError("{}: {}".format(path, exc))


def _verdict(status) -> dict:
    obligation = status.obligation
    out = {
        "state": status.state,
        "scope": status.scope,
        "when": obligation.when,
        "then": obligation.then,
        "within": obligation.within,
        "policy_id": obligation.policy_id,
        "approvals_only": obligation.approvals_only,
        "opened_at": status.opened_at,
        "required_by": status.required_by,
        "late": status.late,
    }
    if status.discharged_at is not None:
        out["discharged_at"] = status.discharged_at
    return out


def run(args) -> int:
    from .. import obligations as model
    from ..report import read_receipts

    try:
        now = _now(args.now)
    except ValueError as exc:
        sys.stderr.write("interlock obligations check: {}\n".format(exc))
        return EXIT_USAGE

    try:
        wanted = _load_obligations(args.obligations)
    except OSError as exc:
        sys.stderr.write("interlock obligations check: cannot read {}: {}\n".format(
            args.obligations, exc))
        return EXIT_UNUSABLE
    except ValueError as exc:
        sys.stderr.write("interlock obligations check: {}\n".format(exc))
        return EXIT_UNUSABLE

    try:
        receipts, bad = read_receipts(args.log)
    except OSError as exc:
        sys.stderr.write("interlock obligations check: cannot read {}: {}\n".format(
            args.log, exc))
        return EXIT_UNUSABLE

    found = model.evaluate(receipts, wanted, now=now)
    counts = model.counts(found)
    breaches = counts[model.BREACHED]

    if args.json:
        sys.stdout.write(json.dumps({
            "obligations": [_verdict(status) for status in found],
            "counts": counts,
            "breaches": breaches,
            "unreadable_lines": bad,
        }, sort_keys=True) + "\n")
    else:
        for status in found:
            sys.stdout.write("{}  {}\n".format(status.state, status.describe()))
        if bad:
            sys.stderr.write(
                "interlock obligations check: skipped {} unreadable line(s) in {}\n"
                .format(len(bad), args.log))
        sys.stdout.write(
            "interlock obligations check: {} opening(s) - {} discharged, {} "
            "pending, {} breached\n".format(
                len(found), counts[model.DISCHARGED], counts[model.PENDING],
                breaches))

    return EXIT_BREACH if breaches else EXIT_OK
