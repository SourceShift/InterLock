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
    checks.extend(_mesh_checks())
    checks.extend(_hook_checks())
    checks.extend(_framework_checks())
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


def _mesh_checks() -> List[Check]:
    """What this node may report, always; and, when it subscribes to a
    commons, whether the subscription is fresh."""
    try:
        from ..mesh import reporting_killed
        from ..mesh.subscriber import Subscriber
        node = Subscriber()
        status = node.status()
    except Exception as exc:  # the mesh is optional; a broken state dir is a warning, not a crash
        return [Check("mesh.state", WARN, "mesh state unreadable: {}".format(type(exc).__name__))]
    from .mesh import report_summary
    consent = status.get("report") or {}
    summary = report_summary(consent)
    if reporting_killed():
        summary += "; INTERLOCK_MESH_NO_REPORT is set: every upload is refused"
    checks: List[Check] = [Check("mesh.report", INFO, summary, fix="" if consent.get("enabled_at") is None
                                 else "to stop: interlock mesh report enable --off")]
    if not status.get("configured"):
        return checks
    if status.get("cache_error"):
        checks.append(Check("mesh.cache", FAIL, "mesh cache does not verify: {}".format(status["cache_error"]),
                            fix="interlock mesh sync"))
    elif status.get("timestamp_expired"):
        checks.append(Check("mesh.fresh", WARN,
                            "mesh timestamp expired {}: the commons stopped signing or sync is failing; "
                            "the last good packs stay in force".format(status.get("timestamp_expires")),
                            fix="interlock mesh sync"))
    elif status.get("timestamp_expires"):
        checks.append(Check("mesh.fresh", OK, "mesh verified, timestamp valid until {}".format(
            status["timestamp_expires"])))
    checks.append(_mesh_root_check(node))
    if status.get("last_error"):
        checks.append(Check("mesh.sync", WARN, "last mesh sync failed: {}".format(status["last_error"]),
                            fix="interlock mesh sync"))
    if status.get("split_views"):
        latest = status["split_views"][-1]
        checks.append(Check("mesh.log", FAIL, "transparency log split view seen ({}): {}".format(
            latest.get("source"), latest.get("detail")),
            fix="stop trusting this commons until its maintainers explain; keep the evidence in the mesh state"))
    elif status.get("log"):
        checks.append(Check("mesh.log", OK, "transparency log verified: {} entries".format(status["log"].get("size"))))
    if status.get("capped"):
        from .mesh import capped_summary
        checks.append(Check("mesh.capped", INFO, capped_summary(status["capped"]),
                            fix="to let a pack's blocks block: interlock mesh grant block --pack PACK --status stable"))
    shadow = status.get("shadow") or {}
    if shadow.get("total"):
        checks.append(Check("mesh.shadow", INFO, "{} shadow finding(s) from rules in their monitor window "
                            "or capped with no approver".format(shadow["total"]), fix="interlock mesh status"))
    return checks


def _mesh_root_check(node) -> Check:
    """When the subscribed root expires: the pinned root plus the rotations the
    node has verified. It does not depend on the rest of the cache, because an
    expired root is exactly when every sync starts failing."""
    from ..mesh import metadata
    from ..mesh._util import iso, read_bounded

    try:
        trusted = metadata.TrustedMetadata(read_bounded(node.root_path, metadata.MAX_LENGTH["root"]))
        for _ in range(metadata.MAX_ROOT_ROTATIONS):
            path = os.path.join(node.dir, "metadata", "{}.root.json".format(trusted.root.version + 1))
            if not os.path.exists(path):
                break
            trusted.update_root(read_bounded(path, metadata.MAX_LENGTH["root"]))
    except Exception as exc:  # a broken root is reported, never a crash
        return Check("mesh.root", WARN, "mesh root unreadable: {}".format(exc), fix="interlock mesh sync")
    root = trusted.root
    left = root.expires - time.time()
    if left < 0:
        return Check("mesh.root", FAIL, "mesh root v{} expired {}: this node accepts nothing more from the commons "
                     "until it has a newer root".format(root.version, iso(root.expires)),
                     fix="interlock mesh sync, if the commons has published one; otherwise obtain its current "
                         "root out of band and run: interlock mesh init --root ROOT --mirror URL")
    if left <= metadata.ROOT_SIGNING_PERIOD:
        return Check("mesh.root", WARN, "mesh root v{} expires {}, in {}: inside its {}-day signing period, so "
                     "the commons' keyholders are due to sign a new one".format(
                         root.version, iso(root.expires), _ago(left), metadata.ROOT_SIGNING_PERIOD // 86400),
                     fix="interlock mesh sync picks up a new root once it is published; ask the commons if none is")
    return Check("mesh.root", OK, "mesh root v{} valid until {}".format(root.version, iso(root.expires)))


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


def _framework_checks() -> List[Check]:
    """Name each framework interlock ships an adapter for, covered or not.

    Doctor runs outside the user's process, so it cannot see which frameworks
    that process actually uses; it can only ask the import system. A framework
    present here gets an OK row naming its guarded surface. One that is absent
    is reported ``uncovered``: interlock cannot attest that its tool surface is
    guarded in this environment, and silence would read as "covered" - the
    failure this check exists to prevent. WARN keeps it "degraded" (exit 1), not
    "unprotected".
    """
    from ..interceptors import FRAMEWORK_ADAPTERS

    checks: List[Check] = []
    for adapter in FRAMEWORK_ADAPTERS:
        module = adapter.MODULE
        short = adapter.__name__.rsplit(".", 1)[-1]
        if adapter.framework_available():
            checks.append(Check("framework." + adapter.FRAMEWORK, OK,
                                "detected: {}".format(adapter.SURFACE)))
        else:
            checks.append(Check("framework." + adapter.FRAMEWORK, WARN,
                                "uncovered: {} is not importable here, so its tool "
                                "surface is not guarded".format(module),
                                "install {} and wrap its tool runner with "
                                "interlock.interceptors.{}.guard_tool_loop".format(
                                    module, short)))
    return checks


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
