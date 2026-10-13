"""Put interlock in front of a coding agent's tool calls.

  interlock install-hook --for claude-code
  interlock install-hook --for all --dry-run       # show the change, write nothing
  interlock install-hook --for codex --uninstall

Registers `interlock hook --agent <name>` in the agent's hook settings
(~/.claude/settings.json, ~/.codex/hooks.json, ~/.cursor/hooks.json), keeping
every other entry, backing the file up first (<file>.interlock-bak) and
replacing any earlier interlock entry. It also creates ~/.interlock with a
default policy that extends the built-in coding-agent pack and a key for the
receipt log. Restart running agent sessions afterwards.

Run this yourself, outside the agent: the coding-agent pack refuses it from
inside one.

Exit codes: 0 done, 1 an agent could not be configured, 64 bad arguments.
"""
from __future__ import annotations

import os
import shlex
import shutil
import sys
import tempfile


def add_arguments(parser) -> None:
    from ..adapters import ADAPTERS
    parser.add_argument("--for", dest="agents", required=True,
                        choices=sorted(ADAPTERS) + ["all"])
    parser.add_argument("--settings", metavar="FILE",
                        help="the agent's settings file (default: its usual path)")
    parser.add_argument("--policy", metavar="FILE", help="pin this policy file in the hook")
    parser.add_argument("--sidecar", metavar="PATH", help="decide through this sidecar")
    parser.add_argument("--receipts", metavar="FILE", help="receipt log path")
    parser.add_argument("--key-file", metavar="FILE", help="receipt key path")
    parser.add_argument("--monitor", action="store_true", help="install in monitor mode")
    parser.add_argument("--dry-run", action="store_true", help="print the change only")
    parser.add_argument("--uninstall", action="store_true", help="remove interlock's hooks")


def hook_command(agent: str, args) -> str:
    parts = [shlex.quote(sys.executable), "-m", "interlock", "hook", "--agent", agent]
    for flag, value in (("--policy", args.policy), ("--sidecar", args.sidecar),
                        ("--receipts", args.receipts), ("--key-file", args.key_file)):
        if value:
            parts += [flag, shlex.quote(os.path.abspath(value) if flag != "--sidecar" else value)]
    if args.monitor:
        parts.append("--monitor")
    return " ".join(parts)


def run(args) -> int:
    from ..adapters import ADAPTERS, get_adapter
    from ..adapters.config import ensure_home

    names = sorted(ADAPTERS) if args.agents == "all" else [args.agents]
    if args.settings and len(names) > 1:
        sys.stderr.write("interlock install-hook: --settings needs a single --for agent\n")
        return 64
    if not args.uninstall and not args.dry_run:
        ensure_home()
    failed = 0
    for name in names:
        adapter = get_adapter(name)
        path = args.settings or adapter.settings_path()
        try:
            if args.uninstall:
                if args.dry_run:
                    print("{}: would remove interlock's hooks from {}".format(name, path))
                    continue
                path, text = adapter.uninstall(args.settings)
                print("{}: {}".format(name, "removed interlock's hooks from " + path
                                      if text is not None else "nothing to remove at " + path))
                continue
            command = hook_command(name, args)
            if args.dry_run:
                text = _preview(adapter, command, path)
                print("{}: would write {}:\n{}".format(name, path, text))
                continue
            _backup(path)
            path, _ = adapter.install(command, args.settings)
            print("{}: hooks installed in {}".format(name, path))
            print("  command: {}".format(command))
            if name == "codex":
                flag = adapter.ensure_feature_flag(args.settings)  # type: ignore[attr-defined]
                if flag == "set":
                    print("  enabled [features] hooks = true in {}".format(
                        adapter.config_path(args.settings)))  # type: ignore[attr-defined]
                elif flag != "already":
                    print("  ! {}".format(flag))
                print("  ! Codex asks you to trust new hooks: open Codex, run /hooks, press t")
            if name == "claude-code":
                print("  check it: start a new session and ask Claude to run "
                      "`git push --force origin main` - interlock should ask you first")
        except (OSError, ValueError) as exc:
            failed += 1
            sys.stderr.write("{}: could not configure {}: {}\n".format(name, path, exc))
    if not args.uninstall and not args.dry_run and not failed:
        print("Restart running agent sessions so they load the hooks. "
              "Then: interlock doctor")
    return 1 if failed else 0


def _backup(path: str) -> None:
    backup = path + ".interlock-bak"
    if os.path.exists(path) and not os.path.exists(backup):
        shutil.copy2(path, backup)


def _preview(adapter, command: str, path: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, os.path.basename(path))
        if os.path.exists(path):
            shutil.copy2(path, copy)
        _, text = adapter.install(command, copy)
        return text
