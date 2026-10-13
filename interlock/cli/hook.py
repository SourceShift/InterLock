"""Decide one coding-agent tool call (run by the agent, not by you).

The agent passes its hook payload on stdin; the verdict goes back on stdout and
the exit code, in that agent's own protocol. `interlock install-hook` writes
the command line; you do not normally run this by hand, except to test:

  echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",
         "tool_input":{"command":"git push --force origin main"},
         "session_id":"s","cwd":"/tmp"}' | interlock hook --agent claude-code

Any error - unreadable input, a policy that will not load, a crash - denies the
call (fail closed) unless --on-error allow, which lets the call through and
says so loudly.
"""
from __future__ import annotations

import json
import os
import sys


def add_arguments(parser) -> None:
    from ..adapters import ADAPTERS
    parser.add_argument("--agent", required=True, choices=sorted(ADAPTERS))
    parser.add_argument("--policy", metavar="FILE",
                        help="policy file (default ~/.interlock/policy.json, else the "
                             "built-in coding-agent pack)")
    parser.add_argument("--rules", metavar="MODULE:ATTR", help="a Python policy module instead")
    parser.add_argument("--sidecar", metavar="PATH", help="ask this sidecar instead")
    parser.add_argument("--receipts", metavar="FILE",
                        help="receipt log (default ~/.interlock/receipts.jsonl when its key exists)")
    parser.add_argument("--key-file", metavar="FILE", help="receipt MAC key")
    parser.add_argument("--no-receipts", action="store_true", help="write no receipts")
    parser.add_argument("--no-overlay", action="store_true", help="ignore project overlays")
    parser.add_argument("--monitor", action="store_true",
                        help="record what would happen, never block")
    parser.add_argument("--on-error", choices=("deny", "allow"), default="deny",
                        help="what an internal error does (default deny)")


def run(args) -> int:
    from ..adapters import get_adapter
    from ..adapters.base import MAX_PAYLOAD, run_hook

    adapter = get_adapter(args.agent)
    fail_open = args.on_error == "allow"
    call = None
    try:
        raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("hook input larger than {} bytes".format(MAX_PAYLOAD))
        payload = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        call = adapter.parse(payload)
        cwd = call.cwd if isinstance(call.cwd, str) else None
        engine = _engine(args, cwd)
        _install_sink(args)
        stdout, stderr, code = run_hook(adapter, payload, engine,
                                        enforcement="monitor" if args.monitor else "blocking")
    except Exception as exc:  # fail closed (or loudly open), never crash the agent
        stdout, stderr, code = adapter.render_error(
            call, "{}: {}".format(type(exc).__name__, exc)[:300], fail_open=fail_open)
    if stdout:
        sys.stdout.write(stdout + "\n")
    if stderr:
        sys.stderr.write(stderr)
    sys.stdout.flush()
    return code


def _engine(args, cwd):
    from ..adapters.config import load_engine
    return load_engine(policy=args.policy, rules=args.rules, sidecar=args.sidecar,
                       cwd=cwd, overlay=not args.no_overlay)


def _install_sink(args) -> None:
    from ..adapters.config import receipts_paths
    from ..receipt import set_sink
    from ..sink import FileSink

    if args.no_receipts:
        set_sink(None)
        return
    default_log, default_key = receipts_paths()
    log = args.receipts or default_log
    key_file = args.key_file or default_key
    if not os.path.exists(key_file):
        if args.receipts:
            raise ValueError("--receipts needs a --key-file that exists")
        set_sink(None)  # not installed yet: no key, no receipts
        return
    from ..sidecar.__main__ import _read_key
    set_sink(FileSink(log, key=_read_key(key_file), shared=True))
