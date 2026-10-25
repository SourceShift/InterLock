"""Check that the import seams interlock attaches to still exist.

  interlock attach --check
  interlock attach --check --json

``attach()`` monkey-patches another library's class, which is the most fragile
thing in interlock: a client update that renames the class or moves the method
turns a guard into a no-op. This command runs the same structural contract
check on the installed packages without installing any hook, so a dependency
upgrade can be verified in CI before it reaches an agent.

Only attachable surfaces are imported (MCP today); the model SDKs are listed as
adapter-guarded and not imported. Exit codes: 0 every installed attachable
surface is compatible, 1 at least one is not (or failed to import), 64 the
command line was wrong.
"""
from __future__ import annotations

import json
import sys


def add_arguments(parser) -> None:
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero when an installed attachable surface is incompatible")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _line(entry) -> str:
    state = "installed" if entry.get("installed") else "not installed"
    extra = []
    if entry.get("version"):
        extra.append("v" + str(entry["version"]))
    if entry.get("import_error"):
        extra.append("import failed: " + entry["import_error"])
    elif entry.get("compatible") is False:
        extra.append("INCOMPATIBLE: " + "; ".join(entry.get("problems") or []))
    elif entry.get("compatible") is True:
        extra.append("compatible")
    if entry.get("guarded"):
        extra.append("guarded in this process")
    if entry.get("drifts"):
        extra.append("{} drift(s)".format(len(entry["drifts"])))
    detail = (", ".join(extra) + " - ") if extra else ""
    return "  {:<14} {:<22} {}{}{}".format(
        entry["site"], entry["module"], state, ", " if detail else "", detail)


def run(args) -> int:
    from ..attach import inspect_surfaces

    entries = inspect_surfaces()
    broken = [entry for entry in entries
              if entry.get("attachable") and entry.get("installed")
              and (entry.get("compatible") is False or entry.get("import_error")
                   or entry.get("drifts"))]
    if args.json:
        sys.stdout.write(json.dumps({"surfaces": entries, "ok": not broken},
                                    indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write("import seams:\n")
        for entry in entries:
            sys.stdout.write(_line(entry) + "\n")
        if broken:
            sys.stdout.write("\n{} attachable surface(s) need attention\n".format(len(broken)))
        else:
            sys.stdout.write("\nevery installed attachable surface is compatible\n")
    return 1 if (args.check and broken) else 0
