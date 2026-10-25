"""The ``interlock`` command line (``python -m interlock``).

Each subcommand lives in its own module and registers itself through
:data:`COMMANDS`: ``doctor`` (is protection on?), ``report`` (what did the
guard do?), ``hook`` and ``install-hook`` (coding-agent adapters), ``mcp``
(MCP inventory), ``policy`` (declarative policy files), ``trust``
(project-overlay trust), ``drift`` (diff a live surface against a corpus)
and ``learn`` (draft a policy from observed receipts).

Exit codes are per command and documented in each one's ``--help``; 64 means
the command line itself was wrong.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, List, Optional, Tuple

EXIT_USAGE = 64

# (name, help, module) - the module exposes add_arguments(parser) and run(args).
COMMANDS: List[Tuple[str, str, str]] = [
    ("doctor", "check that protection is actually on", "doctor"),
    ("report", "summarize a receipt log: blocks, monitor findings, latency", "report"),
    ("hook", "decide one coding-agent tool call (run by the agent)", "hook"),
    ("install-hook", "put interlock in front of Claude Code, Codex or Cursor", "install_hook"),
    ("attach", "check the import seams attach() patches (compatibility contract)", "attach"),
    ("policy", "check a declarative policy file, or show a built-in pack", "policy"),
    ("learn", "draft a reviewable policy from observed receipts", "learn"),
    ("trust", "trust a project's policy overlay", "trust"),
    ("mcp", "inventory the MCP servers configured on this machine", "mcp"),
    ("reviews", "decide pending reviews; serve their status to agents", "reviews"),
    ("drift", "diff a live surface's tool listing against a recorded corpus", "drift"),
    ("mesh", "subscribe to community policy packs, or publish a commons", "mesh"),
]


def use_color(stream=None, flag: Optional[bool] = None) -> bool:
    """Color only for a terminal, and never when NO_COLOR is set."""
    if flag is not None:
        return flag
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def build_parser() -> argparse.ArgumentParser:
    import importlib

    parser = argparse.ArgumentParser(
        prog="interlock",
        description="interlock: guard what AI agents do.",
    )
    parser.add_argument("--no-color", action="store_true", help="disable color output")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, help_text, module_name in COMMANDS:
        module = importlib.import_module("interlock.cli." + module_name)
        command = sub.add_parser(name, help=help_text, description=module.__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
        module.add_arguments(command)
        command.set_defaults(_run=module.run)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    run: Optional[Callable] = getattr(args, "_run", None)
    if run is None:
        parser.print_help()
        return EXIT_USAGE
    return int(run(args) or 0)
