"""Check a declarative policy file before you rely on it.

  interlock policy check policy.json
  interlock policy check ~/.interlock/policy.json --overlay .interlock/policy.json
  interlock policy show builtin:coding-agent        # print a built-in pack
  interlock policy verify --artifact policy.json    # a distributed artifact
  interlock policy doctor                           # the native evaluator

`check` loads the file the way the guard will: it lists the rules, the locked
ones, any rule quarantined as invalid (with why), and each overlay's status.
`verify` loads an artifact the way a host will and reports its epoch, sha256
and which backend decides which part. `doctor` reports whether the optional
native accelerator is importable and which ABI it implements.

Exit codes: 0 valid / available, 1 an invalid artifact or a file with
quarantined rules, 2 does not load / unavailable, 64 bad action.
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
    verify = sub.add_parser("verify", help="validate a distributed policy artifact")
    verify.add_argument("--artifact", required=True, metavar="PATH",
                        help="artifact file, or a directory containing active.json")
    verify.add_argument("--json", action="store_true")
    doctor = sub.add_parser(
        "doctor", help="report the native evaluator's availability and ABI")
    doctor.add_argument("--json", action="store_true")


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
    if args.policy_command == "verify":
        return _verify(args)
    if args.policy_command == "doctor":
        return _doctor(args)
    if args.policy_command != "check":
        sys.stderr.write(
            "interlock policy: choose an action: check, show, verify, doctor\n")
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


#: Artifact refusals that mean "this host cannot materialise the artifact"
#: rather than "the artifact is invalid". Both are failures, but only the
#: former is an unavailable environment (2); everything else is a bad
#: artifact (1).
_UNAVAILABLE_CODES = frozenset({
    "missing_artifact", "rules_module", "missing_template",
})


def _verify(args) -> int:
    """Load an artifact the way a host does, or report why it cannot."""
    from ..policy.artifact import ArtifactError, load_artifact
    from ..policy.killswitch import read_kill

    try:
        compiled = load_artifact(args.artifact)
    except ArtifactError as exc:
        sys.stderr.write(
            "interlock policy: artifact {}: {}: {}\n".format(
                args.artifact, exc.code, exc)
        )
        return 2 if exc.code in _UNAVAILABLE_CODES else 1
    except Exception as exc:  # noqa: BLE001 - unreadable rules module, etc.
        sys.stderr.write(
            "interlock policy: artifact {}: {}: {}\n".format(
                args.artifact, type(exc).__name__, exc)
        )
        return 2
    status = compiled.status()
    report = {
        "path": str(args.artifact),
        "format": compiled.artifact.get("format"),
        "sha256": compiled.sha256,
        "epoch": compiled.epoch,
        "scope_epochs": compiled.scope_epochs(),
        "rule_count": compiled.rule_count(),
        # The artifact carries the detector catalog's id, which is the
        # published detector set's identity. A host with no catalog stamped
        # reports an empty list rather than pretending coverage.
        "detector_ids": [compiled.catalog] if compiled.catalog else [],
        "catalog": compiled.catalog,
        "failure_policy": dict(compiled.failure_policy),
        "rules_module": compiled.rules_module,
        "template_ids": list(compiled.template_ids),
        "native": status,
        "kill": read_kill(args.artifact),
    }
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
        return 0
    print("{}: format {}, epoch {}, sha256 {}".format(
        args.artifact, report["format"], compiled.epoch, compiled.sha256))
    print("  rules: {} ({} template(s))".format(
        report["rule_count"], len(compiled.template_ids)))
    if report["scope_epochs"]:
        print("  scope epochs: {}".format(", ".join(
            "{}={}".format(key, value or "unresolved")
            for key, value in report["scope_epochs"].items())))
    print("  detector ids: {}".format(
        ", ".join(report["detector_ids"]) or "none (no catalog stamped)"))
    print("  failure policy: {}".format(", ".join(
        "{}={}".format(key, value)
        for key, value in report["failure_policy"].items())))
    print("  rules module: {}".format(compiled.rules_module or "none"))
    if compiled.template_ids:
        print("  templates: {}".format(", ".join(compiled.template_ids)))
    print("  native base: {}".format(
        "yes" if status["native_base"] else "no ({})".format(
            status["native_unavailable_reason"] or "not planned")))
    print("  native scopes: {}; python scopes: {}".format(
        len(status["native_scopes"]), len(status["python_scopes"])))
    if status["native_fallbacks"]:
        print("  native fallbacks: {}".format(status["native_fallbacks"]))
    kill = report["kill"]
    if kill:
        print("  KILLED: {} ({})".format(
            kill.get("id") or "unknown", kill.get("reason") or "no reason"))
    return 0


def _active_artifact() -> dict:
    """The connector's active artifact pointer, or ``None`` when unpublished.

    The pointer lives beside the artifacts at ``<home>/artifacts/active.json``
    (see ``interlock/cloud/connector/policy.py``); ``doctor`` only reads it, so a
    host that has never enrolled simply reports that no artifact is active.
    """
    import os
    from pathlib import Path

    home = Path(os.environ.get("IL_CLOUD_HOME") or "~/.interlock").expanduser()
    path = home / "artifacts" / "active.json"
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    return {
        "path": str(path),
        "sha256": body.get("sha256"),
        "epoch": body.get("epoch"),
        "version": body.get("version"),
        "mode": body.get("mode"),
    }


def _parity(available: bool) -> dict:
    """The embedded-corpus parity report, or why it could not run."""
    from ..policy import native

    if not available:
        return {"ran": False, "ok": False, "cases": 0, "mismatches": 0,
                "detail": "the native evaluator is unavailable"}
    try:
        return native.parity_report()
    except Exception as exc:  # noqa: BLE001 - a diagnostic, never fatal
        return {"ran": False, "ok": False, "cases": 0, "mismatches": 0,
                "detail": "{}: {}".format(type(exc).__name__, exc)}


def _doctor(args) -> int:
    """Report whether the native evaluator is usable in this process."""
    from ..policy import native

    available = native.available()
    abi = native.abi_version()
    module_path = None
    module_version = None
    try:
        import interlock_scopes  # type: ignore[import-not-found]
        module_path = getattr(interlock_scopes, "__file__", None)
        module_version = getattr(interlock_scopes, "__version__", None)
    except Exception:  # pragma: no cover - the accelerator is optional
        pass
    try:
        from ..policy import SCOPE_BACKEND
    except Exception:  # pragma: no cover - defensive
        SCOPE_BACKEND = "unknown"
    parity = _parity(available)
    report = {
        "python": sys.executable,
        "native": available,
        "engine_abi": abi,
        "module": module_path,
        "module_version": module_version,
        "scope_backend": SCOPE_BACKEND,
        # ``NativePlan`` is the loadable handle the PyO3 layer exposes; the
        # parity run builds one, so ``ran`` is exactly "the plan loaded and
        # evaluated the embedded corpus".
        "native_plan": bool(parity.get("ran")),
        "parity": parity,
        "active_artifact": _active_artifact(),
    }
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
        return 0 if available else 2
    if available:
        print("native evaluator: available (ENGINE_ABI {})".format(abi))
        print("  python: {}".format(report["python"]))
        print("  module: {}{}".format(
            module_path,
            " (version {})".format(module_version) if module_version else ""))
        print("  scope backend: {}".format(SCOPE_BACKEND))
        print("  NativePlan: {}".format(
            "loaded" if report["native_plan"] else "NOT loaded"))
        if parity.get("ran"):
            print("  parity: {}/{} embedded case(s) agree{}".format(
                parity.get("cases", 0) - parity.get("mismatches", 0),
                parity.get("cases", 0),
                "" if parity.get("ok") else " - MISMATCH"))
        else:
            print("  parity: not run ({})".format(parity.get("detail")))
    else:
        print("native evaluator: unavailable (the optional interlock_scopes "
              "accelerator is not installed; the Python engine is in use)")
        print("  python: {}".format(report["python"]))
    active = report["active_artifact"]
    if available:
        if active:
            print("  active artifact: {} epoch {} (version {}, mode {})".format(
                active.get("sha256") or "unknown",
                active.get("epoch") or "unrecorded",
                active.get("version", "?"), active.get("mode") or "?"))
        else:
            print("  active artifact: none")
    return 0 if available else 2
