"""Inventory the MCP servers configured on this machine.

  interlock mcp scan                       # every server, with risk notes
  interlock mcp scan --json
  interlock mcp scan --emit-policy mcp.json  # a rule blocking unlisted servers
  interlock mcp where github               # every config that defines it

Reads Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI and
Codex configs (user scope, plus the project around --cwd). Never starts a server
and never touches the network. Environment and header values are not read into
the report - only their names.

Exit codes: 0 no risks found, 1 at least one risk note, 2 nothing matched (where).
"""
from __future__ import annotations

import json
import os
import sys


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="mcp_command", metavar="ACTION")
    scan = sub.add_parser("scan", help="list configured MCP servers")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--cwd", default=os.getcwd(), help="project directory (default: here)")
    scan.add_argument("--emit-policy", metavar="FILE",
                      help="write a policy blocking MCP tools from unlisted servers")
    where = sub.add_parser("where", help="which configs define a server")
    where.add_argument("name")
    where.add_argument("--cwd", default=os.getcwd())


def run(args) -> int:
    from ..mcp_inventory import scan, starter_policy, where

    if args.mcp_command not in ("scan", "where"):
        sys.stderr.write("interlock mcp: choose an action: scan, where\n")
        return 64
    servers, problems = scan(args.cwd)
    for problem in problems:
        sys.stderr.write("interlock mcp: could not read {}\n".format(problem))
    if args.mcp_command == "where":
        found = where(servers, args.name)
        for s in found:
            print("{:<14} {:<8} {}{}".format(s.client, s.scope, s.config,
                                              " (project {})".format(s.project) if s.project else ""))
        return 0 if found else 2
    if args.emit_policy:
        with open(args.emit_policy, "w", encoding="utf-8") as fh:
            json.dump(starter_policy(servers), fh, indent=2)
            fh.write("\n")
    if args.json:
        sys.stdout.write(json.dumps({"servers": [s.to_dict() for s in servers],
                                     "unreadable": problems}, indent=2) + "\n")
    else:
        if not servers:
            print("no MCP servers configured")
        for s in servers:
            target = s.url or " ".join([s.command or "?"] + s.args)
            print("{:<24} {:<14} {:<7} {:<6} {}".format(s.name, s.client, s.scope, s.transport,
                                                         target[:70]))
            for risk in s.risks:
                print("{:<24} ! {}".format("", risk))
        if args.emit_policy:
            print("wrote {} - review it, then extend your policy with it".format(args.emit_policy))
    return 1 if any(s.risks for s in servers) else 0
