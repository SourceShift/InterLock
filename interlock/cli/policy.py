"""Check a declarative policy file before you rely on it.

  interlock policy check policy.json
  interlock policy check ~/.interlock/policy.json --overlay .interlock/policy.json
  interlock policy show builtin:coding-agent        # print a built-in pack

`check` loads the file the way the guard will: it lists the rules, the locked
ones, any rule quarantined as invalid (with why), and each overlay's status.

Exit codes: 0 valid, 1 loaded with quarantined rules, 2 does not load.
"""
from __future__ import annotations

import json
import sys


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="policy_command", metavar="ACTION")
    check = sub.add_parser("check", help="validate a policy file")
    check.add_argument("file")
    check.add_argument("--overlay", action="append", default=[], metavar="FILE",
                       help="also apply this overlay (if trusted)")
    check.add_argument("--json", action="store_true")
    show = sub.add_parser("show", help="print a built-in policy pack")
    show.add_argument("name", help="e.g. builtin:coding-agent")


def run(args) -> int:
    from ..policy.declarative import PolicyError, check_policy_file
    from ..policy.trust import TrustStore

    if args.policy_command == "show":
        from ..policy.packs import builtin_pack
        try:
            doc = builtin_pack(args.name.replace("builtin:", "", 1))
        except KeyError as exc:
            sys.stderr.write("interlock policy: {}\n".format(exc.args[0]))
            return 2
        sys.stdout.write(json.dumps(doc, indent=2) + "\n")
        return 0
    if args.policy_command != "check":
        sys.stderr.write("interlock policy: choose an action: check, show\n")
        return 64
    try:
        report = check_policy_file(args.file, overlays=args.overlay, trust=TrustStore())
    except PolicyError as exc:
        sys.stderr.write("interlock policy: {}\n".format(exc))
        return 2
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        print("{}: {} rule(s), epoch {}".format(report["path"], len(report["rules"]), report["epoch"]))
        if report["locked"]:
            print("  locked: {}".format(", ".join(report["locked"])))
        for item in report["quarantined"]:
            print("  QUARANTINED {}".format(item))
        for overlay in report["overlays"]:
            print("  overlay {}: {}".format(overlay["path"], overlay["status"]))
    return 1 if report["quarantined"] else 0
