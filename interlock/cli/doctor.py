"""Check that interlock protection is actually on.

Runs host-level checks and, when you point it at them, checks your policy,
your sidecar and your receipt log:

  interlock doctor
  interlock doctor --rules myapp.policy:RULES --receipts audit.jsonl --key-file audit.key
  interlock doctor --sidecar ~/.interlock/guard.sock --json

Inside your own process, call interlock.posture.attest() (or require()) instead:
it sees the installed engine, sink, guards and approver directly.

Exit codes: 0 enforced, 1 degraded (warnings), 2 unprotected (a check failed).
"""
from __future__ import annotations

import os
import platform
import sys
import time
from typing import List

from ..posture import FAIL, INFO, OK, WARN, Check, Posture, _sandbox_checks, probe_sidecar

EXIT_BY_LEVEL = {"enforced": 0, "degraded": 1, "unprotected": 2}

#: Extra check providers (``fn(args) -> List[Check]``) other modules register,
#: e.g. the coding-agent hook adapters checking their settings files.
EXTRA_CHECKS: List = []


def add_arguments(parser) -> None:
    parser.add_argument("--rules", metavar="MODULE:ATTR",
                        help="load this policy (same spec as interlock-sidecar --rules)")
    parser.add_argument("--policy", metavar="FILE",
                        help="load this declarative policy file (JSON, or YAML with PyYAML)")
    parser.add_argument("--sidecar", metavar="PATH",
                        help="probe the sidecar listening on this socket")
    parser.add_argument("--receipts", metavar="FILE", help="check this receipt log")
    parser.add_argument("--key-file", metavar="FILE",
                        help="the receipt MAC key, to verify the log's chain")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def run(args) -> int:
    checks: List[Check] = [Check("python", INFO, "Python {} on {} {}".format(
        platform.python_version(), platform.system(), platform.machine()))]
    policy = _policy_checks(args)
    if args.sidecar and policy and policy[0].status == WARN:
        policy = []  # the sidecar probe below checks the policy in force
    checks.extend(policy)
    checks.extend(_sidecar_checks(args))
    checks.extend(_sandbox_checks())
    checks.extend(_receipt_checks(args))
    checks.extend(_hook_checks())
    for provider in EXTRA_CHECKS:
        try:
            checks.extend(provider(args))
        except Exception as exc:  # a broken provider must not hide the rest
            checks.append(Check("doctor.provider", WARN, "a check failed to run: {}".format(
                type(exc).__name__)))
    posture = Posture(tuple(checks))
    if args.json:
        sys.stdout.write(posture.to_json() + "\n")
    else:
        from . import use_color
        sys.stdout.write(posture.render(color=use_color(flag=False if args.no_color else None)) + "\n")
    return EXIT_BY_LEVEL[posture.level]


def _policy_checks(args) -> List[Check]:
    if not args.rules and not getattr(args, "policy", None):
        # Never let "nothing was checked" read as "protected".
        return [Check("engine.installed", WARN,
                      "no policy checked: only the host was inspected",
                      "pass --rules MODULE:ATTR or --policy FILE (or --sidecar PATH)")]
    engine = None
    if args.rules:
        from ..sidecar.rules import RulesError, load_rules
        try:
            engine = load_rules(args.rules)
        except RulesError as exc:
            return [Check("engine.installed", FAIL, "policy {} did not load: {}".format(
                args.rules, exc), "fix the module, or run interlock-sidecar --check")]
        except Exception as exc:  # an import that raises is a broken policy
            return [Check("engine.installed", FAIL, "policy {} raised {}: {}".format(
                args.rules, type(exc).__name__, exc))]
        source = args.rules
    else:
        from ..policy.declarative import PolicyError, load_policy_file
        try:
            engine = load_policy_file(args.policy)
        except PolicyError as exc:
            return [Check("engine.installed", FAIL, "policy {} did not load: {}".format(
                args.policy, exc), "run: interlock policy check {}".format(args.policy))]
        source = args.policy
    checks = [Check("engine.installed", OK if len(engine) else FAIL,
                    "{}: {} rule(s)".format(source, len(engine)),
                    "" if len(engine) else "an empty policy allows every call")]
    checks.append(Check("engine.epoch", INFO, "policy epoch {}".format(engine.epoch)))
    quarantined = getattr(engine, "quarantined", None)
    if quarantined:
        checks.append(Check("policy.quarantine", WARN,
                            "{} rule(s) skipped as invalid: {}".format(
                                len(quarantined), ", ".join(quarantined[:5])),
                            "run: interlock policy check FILE"))
    return checks


def _sidecar_checks(args) -> List[Check]:
    path = args.sidecar
    if path is None:
        from ..sidecar.__main__ import default_socket_path
        default = default_socket_path()
        if not os.path.exists(default):
            return [Check("sidecar.reachable", INFO, "no sidecar socket at {}".format(default))]
        path = default
    return [probe_sidecar(path)]


def _receipt_checks(args) -> List[Check]:
    if not args.receipts:
        return [Check("audit.log", INFO, "no --receipts given")]
    from ..report import read_receipts, verification
    path = args.receipts
    if not os.path.exists(path):
        return [Check("audit.log", FAIL, "{} does not exist".format(path))]
    try:
        receipts, bad = read_receipts(path)
    except OSError as exc:
        return [Check("audit.log", FAIL, "{} is unreadable: {}".format(path, exc))]
    checks: List[Check] = []
    if bad:
        checks.append(Check("audit.log", FAIL, "{} line(s) are not receipts (first: line {})".format(
            len(bad), bad[0]), "a crash mid-write or a foreign file; move it aside"))
    else:
        checks.append(Check("audit.log", OK, "{}: {} receipt(s)".format(path, len(receipts))))
    key = None
    if args.key_file:
        from ..sidecar.__main__ import _read_key
        from ..sidecar.rules import RulesError
        try:
            key = _read_key(args.key_file)
        except RulesError as exc:
            checks.append(Check("audit.chain", FAIL, str(exc)))
            return checks
    result = verification(receipts, key=key)
    if result["status"] == "verified":
        checks.append(Check("audit.chain", OK, "chain verified"))
    elif result["status"] == "broken":
        checks.append(Check("audit.chain", FAIL, str(result["detail"]),
                            "the log was edited, truncated mid-chain, or written by two processes"))
    else:
        checks.append(Check("audit.chain", WARN, "chain not verified: no --key-file given",
                            "pass --key-file"))
    if receipts:
        age = time.time() - receipts[-1].ts
        checks.append(Check("audit.recent", INFO, "newest receipt {} ago".format(_ago(age))))
    dropped = sum(1 for r in receipts if r.action == "receipts.dropped")
    if dropped:
        checks.append(Check("audit.dropped", WARN,
                            "{} dropped-receipt notice(s): the log has gaps".format(dropped)))
    return checks


def _ago(seconds: float) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return "{}{}".format(int(seconds // size), unit)
    return "{}s".format(int(seconds))


def _hook_checks() -> List[Check]:
    """For each coding agent: is interlock's hook registered, and can it run?"""
    import shlex

    from ..adapters import ADAPTERS, get_adapter

    checks: List[Check] = []
    for name in sorted(ADAPTERS):
        adapter = get_adapter(name)
        path = adapter.settings_path()
        command = adapter.installed_command()
        if command is None:
            checks.append(Check("hook." + name, INFO, "not installed ({})".format(path)))
            continue
        try:
            program = shlex.split(command)[0]
        except ValueError:
            program = ""
        if program and os.path.isabs(program) and not os.path.exists(program):
            checks.append(Check("hook." + name, FAIL,
                                "hook in {} runs {}, which no longer exists".format(path, program),
                                "re-run: interlock install-hook --for {}".format(name)))
            continue
        mode = " (monitor mode: nothing is blocked)" if "--monitor" in command else ""
        checks.append(Check("hook." + name, WARN if mode else OK,
                            "installed in {}{}".format(path, mode),
                            "re-install without --monitor once trialled" if mode else ""))
    return checks
