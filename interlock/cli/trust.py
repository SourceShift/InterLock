"""Trust (or stop trusting) a project's policy overlay.

  interlock trust add                 # the overlay found from this directory
  interlock trust add path/to/.interlock/policy.json
  interlock trust list                # ok / CHANGED / MISSING
  interlock trust remove [PATH]

An overlay (.interlock/policy.json in a repository) is ignored until trusted,
and trust is tied to the file's exact content: edit it and it is ignored again
until you re-trust it. `add` shows what the overlay adds before recording it.
Run this yourself, outside the agent - the coding-agent pack refuses it from
inside one.
"""
from __future__ import annotations

import json
import os
import sys


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="trust_command", metavar="ACTION")
    add = sub.add_parser("add", help="trust an overlay's current content")
    add.add_argument("path", nargs="?", help="overlay file (default: found from here)")
    add.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    sub.add_parser("list", help="list trusted overlays")
    remove = sub.add_parser("remove", help="stop trusting an overlay")
    remove.add_argument("path", nargs="?")
    parser.add_argument("--store", metavar="FILE", help="trust file (default ~/.interlock/trusted.json)")


def run(args) -> int:
    from ..policy.declarative import PolicyError, read_policy_file
    from ..policy.trust import TrustStore, find_overlay

    store = TrustStore(args.store)
    if args.trust_command == "list":
        entries = store.entries()
        if not entries:
            print("no trusted overlays")
        for path, status in entries:
            print("{:<8} {}".format(status.upper() if status != "ok" else "ok", path))
        return 0
    if args.trust_command not in ("add", "remove"):
        sys.stderr.write("interlock trust: choose an action: add, list, remove\n")
        return 64
    path = args.path or find_overlay(os.getcwd())
    if not path:
        sys.stderr.write("interlock trust: no .interlock/policy.json found from here\n")
        return 1
    if args.trust_command == "remove":
        print(("removed " if store.remove(path) else "was not trusted: ") + os.path.abspath(path))
        return 0
    try:
        doc, _ = read_policy_file(path)
    except PolicyError as exc:
        sys.stderr.write("interlock trust: {}\n".format(exc))
        return 1
    print("Overlay {} adds:".format(os.path.abspath(path)))
    for rule in doc.get("rules", []) or []:
        if isinstance(rule, dict):
            print("  rule {} ({})".format(rule.get("id"), rule.get("verdict") or rule.get("detector")))
    for rule_id, params in (doc.get("widen") or {}).items():
        print("  widens {}: {}".format(rule_id, json.dumps(params)))
    if not args.yes:
        if not sys.stdin.isatty():
            sys.stderr.write("interlock trust: confirm on a terminal, or pass --yes\n")
            return 1
        if input("Trust this exact content? [y/N] ").strip().lower() not in ("y", "yes"):
            print("not trusted")
            return 1
    digest = store.add(path)
    print("trusted {} (sha256 {}...)".format(os.path.abspath(path), digest[:12]))
    return 0
