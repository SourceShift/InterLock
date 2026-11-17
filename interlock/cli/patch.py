"""Judge an agent-authored patch on evidence it cannot author.

  interlock patch gate                  # judge the working tree vs origin/main
  interlock patch gate --base HEAD~1    # judge against an explicit base
  interlock patch gate --head HEAD      # judge a commit, e.g. in CI
  interlock patch status                # is the current diff covered by a pass?

The gate asks three questions and refuses to guess:

1. does every test file the patch touches contain an assertion at all;
2. does the suite fail with the patch's own tests at the pre-patch revision
   (a test that passes before the change does not test the change);
3. does the same suite pass with the patch applied.

A pass is signed and stored under ``~/.interlock/patch-gates/``. With the hook
adapter's ``--patch-gate block`` (or ``INTERLOCK_PATCH_GATE=block``) a
``git commit``, ``git push`` or ``git merge`` is refused until a passing record
covers the exact diff being landed. Run the gate outside the agent: the agent
can edit a test, but it cannot edit the pre-patch revision it is replayed
against.

Exit codes: 0 the gate passed, 1 it failed, 64 bad arguments.
"""
from __future__ import annotations

import json
import sys

from . import EXIT_USAGE

from .. import patch_gate


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="patch_command", metavar="ACTION")

    gate = sub.add_parser(
        "gate", help="run the checks and sign a record",
        description="Judge a patch and write a signed record. Nothing is "
                    "committed or pushed by this command.")
    gate.add_argument("--repo", metavar="DIR", help="working tree (default: the current one)")
    gate.add_argument("--base", metavar="REF",
                      help="pre-patch revision (default: origin/main, else HEAD)")
    gate.add_argument("--head", metavar="REF",
                      help="judge this commit instead of the working tree")
    gate.add_argument("--test-cmd", metavar="CMD",
                      help="the suite to replay at both revisions (shell command). "
                           "Inferred only for Python test files, via pytest")
    gate.add_argument("--timeout", type=int, default=patch_gate.DEFAULT_TIMEOUT,
                      metavar="SEC", help="per-state timeout (default 600)")
    gate.add_argument("--rescan", metavar="CMD",
                      help="also run this (e.g. 'bandit -q -r .') and fail on a non-zero exit")
    gate.add_argument("--allow-untested", action="store_true",
                      help="a code patch with no test file passes the replay check "
                           "(it is recorded as a skip)")
    gate.add_argument("--keep", metavar="DIR",
                      help="keep the extracted base tree here for inspection")
    gate.add_argument("--gates-dir", metavar="DIR",
                      help="where records live (default ~/.interlock/patch-gates)")
    gate.add_argument("--key", metavar="FILE",
                      help="HMAC key for records (default ~/.interlock/patch-gates.key)")
    gate.add_argument("--json", action="store_true", help="machine-readable output")
    gate.add_argument("--no-record", action="store_true",
                      help="judge without writing (and without signing) a record")

    status = sub.add_parser(
        "status", help="compare the latest record against the current diff")
    status.add_argument("--repo", metavar="DIR")
    status.add_argument("--base", metavar="REF")
    status.add_argument("--head", metavar="REF")
    status.add_argument("--gates-dir", metavar="DIR")
    status.add_argument("--key", metavar="FILE")
    status.add_argument("--json", action="store_true")


def run(args) -> int:
    action = getattr(args, "patch_command", None)
    if action == "gate":
        return _gate(args)
    if action == "status":
        return _status(args)
    return EXIT_USAGE


def _mark(status: str) -> str:
    return {"pass": "ok  ", "fail": "FAIL", "skip": "skip"}.get(status, status)


def _base_label(report: patch_gate.Report) -> str:
    if report.base_ref and report.base_ref != report.base:
        return "{} ({})".format(report.base_ref, report.base[:8])
    return report.base or "-"


def _print_report(report: patch_gate.Report) -> None:
    print("patch gate: {}  base {}  diff {}".format(
        report.verdict.upper(), _base_label(report),
        (report.diff_sha256 or "-")[:12]))
    for check in report.checks:
        line = "  {}  {}".format(_mark(check.status), check.id)
        if check.detail:
            line += ": " + check.detail
        print(line)
    if report.test_cmd:
        print("  test command: {}".format(report.test_cmd))
    if report.tests:
        print("  tests touched: {}".format(", ".join(report.tests)))


def _gate(args) -> int:
    report = patch_gate.gate(
        repo=getattr(args, "repo", None),
        base=getattr(args, "base", None),
        head=getattr(args, "head", None),
        test_cmd=getattr(args, "test_cmd", None),
        timeout=getattr(args, "timeout", patch_gate.DEFAULT_TIMEOUT),
        allow_untested=getattr(args, "allow_untested", False),
        rescan=getattr(args, "rescan", None),
        keep=getattr(args, "keep", None),
    )
    path = None
    if not getattr(args, "no_record", False):
        try:
            path = patch_gate.write_record(
                report, getattr(args, "gates_dir", None), getattr(args, "key", None))
        except OSError as exc:
            print("patch gate: cannot write the signed record: {}".format(exc),
                  file=sys.stderr)
            return 1
    if getattr(args, "json", False):
        payload = report.as_dict()
        payload["record"] = path
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_report(report)
        print("  record: {}".format(path or "(not written)"))
    return 0 if report.verdict == patch_gate.PASS else 1


def _status(args) -> int:
    repo = patch_gate.repo_root(getattr(args, "repo", None))
    if repo is None:
        print("patch status: not inside a git working tree", file=sys.stderr)
        return 1
    record = patch_gate.read_record(
        repo, getattr(args, "gates_dir", None), getattr(args, "key", None))
    base = getattr(args, "base", None) or (
        str(record.get("base")) if record and record.get("base")
        else patch_gate.default_base(repo))
    head = getattr(args, "head", None)
    digest = patch_gate.diff_digest(repo, base, head) or ""
    covered = bool(record) and record.get("verdict") == patch_gate.PASS \
        and record.get("diff_sha256") == digest
    if getattr(args, "json", False):
        print(json.dumps({
            "repo": repo,
            "base": base,
            "head": head or "WORKTREE",
            "diff_sha256": digest,
            "record": record,
            "covered": covered,
        }, indent=2, sort_keys=True))
    else:
        if record is None:
            print("patch status: no signed record for this working tree")
        else:
            print("patch status: latest record {} at diff {} (base {})".format(
                record.get("verdict"), str(record.get("diff_sha256"))[:12],
                record.get("base")))
        print("              current diff {}: {}".format(
            digest[:12] or "-",
            "covered" if covered else "NOT covered"))
        if not covered:
            print("              run `interlock patch gate --base {}`".format(base))
    return 0 if covered else 1
