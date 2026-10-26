"""Put interlock in front of a coding agent's tool calls.

  interlock install-hook --for claude-code
  interlock install-hook --for all --dry-run       # show the change, write nothing
  interlock install-hook --for codex --uninstall

Registers `interlock hook --agent <name>` in the agent's hook settings
(~/.claude/settings.json, ~/.codex/hooks.json, ~/.cursor/hooks.json), keeping
every other entry, backing the file up first (<file>.interlock-bak) and
replacing any earlier interlock entry. The hook runs this Python and this
interlock package, whatever directory the agent runs it from, and denies the
call if it cannot start. It also creates ~/.interlock with a default policy
that extends the built-in coding-agent pack and a key for the receipt log.
Restart running agent sessions afterwards; re-run this if interlock moves.

Run this yourself, outside the agent: the coding-agent pack refuses it from
inside one.

Exit codes: 0 done, 1 an agent could not be configured, 64 bad arguments.
"""
from __future__ import annotations

import json
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
    parser.add_argument("--artifact", metavar="PATH",
                        help="pin a distributed policy artifact (or its directory) in "
                             "the hook; mutually exclusive with --policy")
    parser.add_argument("--sidecar", metavar="PATH", help="decide through this sidecar")
    parser.add_argument("--receipts", metavar="FILE", help="receipt log path")
    parser.add_argument("--key-file", metavar="FILE", help="receipt key path")
    parser.add_argument("--reviews", choices=("fallback", "always", "off"), default=None,
                        help="settle escalations through the review queue: when the agent "
                             "can't ask (default), always - Claude Code too - or never")
    parser.add_argument("--review-db", metavar="FILE", help="review queue path")
    parser.add_argument("--monitor", action="store_true", help="install in monitor mode")
    parser.add_argument("--dry-run", action="store_true", help="print the change only")
    parser.add_argument("--uninstall", action="store_true", help="remove interlock's hooks")


#: The program the hook command runs (``python -I -c``), before interlock is
#: imported: it loads the package from the root recorded at install time, and if
#: anything stops ``interlock hook`` from starting it answers in the agent's own
#: blocking shape instead of exiting with a traceback, which agents read as "no
#: objection". The shapes mirror ``render_error`` in adapters/claude_code.py,
#: adapters/codex.py and adapters/cursor.py: change them together.
_BOOTSTRAP = r"""
import sys
argv = sys.argv[2:]
opts = {"--agent": None, "--on-error": "deny"}
for i, arg in enumerate(argv):
    for flag in opts:
        if arg == flag and i + 1 < len(argv):
            opts[flag] = argv[i + 1]
        elif arg.startswith(flag + "="):
            opts[flag] = arg[len(flag) + 1:]
agent, allow = opts["--agent"], opts["--on-error"] == "allow"


def refuse(why):
    import json
    try:
        event = str(json.loads(sys.stdin.buffer.read(1 << 24)).get("hook_event_name", ""))
    except Exception:
        event = None
    deny = ("interlock could not start ({}); denied fail-closed. "
            "Run `interlock doctor` outside the agent.").format(why)
    warn = "⚠ interlock is NOT enforcing: could not start: {} (run: interlock doctor)".format(why)
    out, err, code = None, "", 0
    if agent == "cursor":
        out = ({"permission": "allow", "user_message": warn} if allow else
               {"permission": "deny", "user_message": deny, "agent_message": deny})
    elif agent == "codex" and not allow and event in (None, "PreToolUse", "PermissionRequest"):
        err, code = deny + "\n", 2
    elif allow or agent == "codex":
        out = {"systemMessage": warn}
    elif event == "PostToolUse":
        out = {"decision": "block", "reason": "interlock could not start ({}); withheld".format(why),
               "hookSpecificOutput": {"hookEventName": "PostToolUse",
                                      "updatedToolOutput": "[interlock withheld this tool output]"}}
    else:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": deny}}
    if out is not None:
        sys.stdout.write(json.dumps(out) + "\n")
    sys.stderr.write(err)
    sys.stdout.flush()
    return code


try:
    if agent not in ("claude-code", "codex", "cursor"):
        raise ValueError("unknown agent {!r}".format(agent))
    import io
    import os
    root = @ROOT@
    if root not in sys.path:
        sys.path.insert(0, root)
    import interlock
    found = os.path.dirname(os.path.dirname(os.path.abspath(interlock.__file__)))
    if found != root:
        raise ImportError("interlock is no longer installed in {} (found it in {}); "
                          "re-run interlock install-hook".format(root, found))
    from interlock.cli import build_parser
    real, sys.stderr = sys.stderr, io.StringIO()
    try:
        args = build_parser().parse_args(argv)
    except SystemExit:
        raise ValueError(sys.stderr.getvalue().strip().rpartition("\n")[2] or "bad arguments")
    finally:
        sys.stderr = real
    code = int(args._run(args) or 0)
except BaseException as exc:
    code = refuse("{}: {}".format(type(exc).__name__, exc)[:300])
sys.exit(code)
"""


def hook_command(agent: str, args) -> str:
    """The agent's hook command: one shell line, independent of the agent's cwd.

    It runs this Python isolated (``-I``: neither the working directory nor
    PYTHONPATH reaches ``sys.path``) through :data:`_BOOTSTRAP`. The trailing
    ``interlock hook --agent <name>`` stays literal: it is the bootstrap's argv
    and the marker install, uninstall and doctor find the entry by.
    """
    source = _BOOTSTRAP.replace("@ROOT@", json.dumps(_package_root()))
    parts = [shlex.quote(sys.executable), "-I", "-c",
             shlex.quote("exec({})".format(json.dumps(source))),
             "interlock", "hook", "--agent", shlex.quote(agent)]
    for flag, value in (("--policy", args.policy),
                        ("--artifact", getattr(args, "artifact", None)),
                        ("--sidecar", args.sidecar),
                        ("--receipts", args.receipts), ("--key-file", args.key_file),
                        ("--review-db", getattr(args, "review_db", None))):
        if value:
            parts += [flag, shlex.quote(os.path.abspath(value) if flag != "--sidecar" else value)]
    reviews = getattr(args, "reviews", None)
    if reviews:
        parts += ["--reviews", shlex.quote(reviews)]
    if args.monitor:
        parts.append("--monitor")
    return " ".join(parts)


def _package_root() -> str:
    """The directory the hook imports interlock from: where this copy lives."""
    import interlock
    return os.path.dirname(os.path.dirname(os.path.abspath(interlock.__file__)))


def run(args) -> int:
    from ..adapters import ADAPTERS, get_adapter
    from ..adapters.config import ensure_home

    names = sorted(ADAPTERS) if args.agents == "all" else [args.agents]
    if getattr(args, "artifact", None) and getattr(args, "policy", None):
        sys.stderr.write(
            "interlock install-hook: --artifact cannot be combined with --policy\n")
        return 64
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
                # With --reviews always the escalation never reaches Claude Code's
                # own prompt: the hook refuses the call and files a review a human
                # approves instead. Say which one this install will do.
                print("  check it: start a new session and ask Claude to run "
                      "`git push --force origin main` - interlock should {}".format(
                          "refuse it and file a review you approve on #/reviews"
                          if getattr(args, "reviews", None) == "always"
                          else "ask you first"))
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
